// Package aggregator owns metric updates and the join buffer.
// It is the single point of mutation; tailers fan in via OnRaw* methods.
package aggregator

import (
	"net"
	"sync"
	"time"

	"github.com/fretscha/modsec-exporter/internal/geoip"
	"github.com/fretscha/modsec-exporter/internal/join"
	"github.com/fretscha/modsec-exporter/internal/metrics"
	"github.com/fretscha/modsec-exporter/internal/parser"
)

// Config holds runtime knobs.
type Config struct {
	BufferSize int
	BufferTTL  time.Duration
	TopN       int
	Now        func() time.Time
}

// Aggregator is the central event sink. Methods are safe for concurrent use.
type Aggregator struct {
	m    *metrics.Metrics
	gip  geoip.Lookup
	buf  *join.Buffer
	topN *metrics.TopN

	mu          sync.Mutex
	lastEvicted uint64
}

// New constructs an Aggregator and, if cfg.TopN > 0, registers the Top-N collector.
func New(m *metrics.Metrics, gip geoip.Lookup, cfg Config) *Aggregator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	tn := metrics.NewTopN(cfg.TopN)
	if cfg.TopN > 0 {
		m.Registry.MustRegister(tn)
	}
	return &Aggregator{
		m:    m,
		gip:  gip,
		buf:  join.NewBuffer(cfg.BufferSize, cfg.BufferTTL, cfg.Now),
		topN: tn,
	}
}

// OnRawAccess parses then forwards. Drops malformed lines with a counter increment.
func (a *Aggregator) OnRawAccess(line string) {
	ev, err := parser.ParseAccess(line)
	if err != nil {
		a.m.LinesParsed.WithLabelValues("access", "parse_error").Inc()
		return
	}
	a.m.LinesParsed.WithLabelValues("access", "ok").Inc()
	a.OnAccess(ev)
}

// OnRawError parses then forwards.
func (a *Aggregator) OnRawError(line string) {
	ev, err := parser.ParseError(line)
	if err != nil {
		a.m.LinesParsed.WithLabelValues("error", "parse_error").Inc()
		return
	}
	a.m.LinesParsed.WithLabelValues("error", "ok").Inc()
	a.OnError(ev)
}

// OnAccess updates RED metrics and drains pending error events for this
// unique_id. If no errors are buffered yet, remembers the access summary so a
// late-arriving error event (in replay or out-of-order log shipping) can still
// emit the joined outcome metric.
func (a *Aggregator) OnAccess(ev parser.AccessEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc := metrics.StatusClass(ev.Status)
	a.m.HTTPRequests.WithLabelValues(ev.Hostname, ev.Method, sc).Inc()
	a.m.HTTPRequestDuration.WithLabelValues(ev.Hostname, ev.Method, sc).Observe(float64(ev.DurationUsec) / 1e6)
	a.m.HTTPResponseSize.WithLabelValues(ev.Hostname, sc).Observe(float64(ev.ResponseBytes))

	country := ev.Country
	if country == "" {
		r := a.gip.Lookup(net.ParseIP(ev.ClientIP))
		if r.Country != "" {
			country = r.Country
			a.m.GeoIPLookups.WithLabelValues("hit").Inc()
		} else {
			a.m.GeoIPLookups.WithLabelValues("miss").Inc()
		}
	}
	if country == "" {
		country = "unknown"
	}
	a.m.HTTPRequestsCountry.WithLabelValues(ev.Hostname, country, sc).Inc()

	a.m.ModsecAnomalyScore.WithLabelValues(ev.Hostname, "incoming").Observe(float64(ev.AnomalyScoreIn))
	a.m.ModsecAnomalyScore.WithLabelValues(ev.Hostname, "outgoing").Observe(float64(ev.AnomalyScoreOut))

	pending := a.buf.Drain(ev.UniqueID)
	for _, p := range pending {
		host := p.Hostname
		if host == "" {
			host = ev.Hostname
		}
		a.m.ModsecOutcome.WithLabelValues(host, p.RuleID, p.Severity, sc).Inc()
	}
	// If CRS scored this request, remember the access summary so any *late*
	// error events (mixed ordering, log-flush quirks, replay races) can still
	// join. Always remembered when score > 0, regardless of whether we just
	// drained pending events — the same uid can have more errors arrive after.
	// Benign requests (score=0) are skipped to keep the buffer focused.
	if ev.AnomalyScoreIn > 0 {
		a.buf.RememberAccess(ev.UniqueID, join.AccessSummary{
			StatusClass: sc,
			Hostname:    ev.Hostname,
		})
	}
	a.m.JoinBufferSize.Set(float64(a.buf.Size()))
}

// OnError updates rule metrics and stores the event in the join buffer.
func (a *Aggregator) OnError(ev parser.ErrorEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pl := ev.ParanoiaLevel
	if pl == "" {
		pl = "unknown"
	}
	a.m.ModsecRuleTriggered.WithLabelValues(ev.Hostname, ev.RuleID, ev.Severity, pl).Inc()
	for _, c := range ev.Categories {
		a.m.ModsecAttackCat.WithLabelValues(ev.Hostname, c).Inc()
	}

	// If the access entry already arrived (race / out-of-order / mixed
	// ordering across multiple errors for the same uid), we can join now.
	// Peek leaves the summary in place so subsequent errors for the same
	// uid still match; TTL eviction is the eventual reaper.
	if as := a.buf.PeekAccess(ev.UniqueID); as != nil {
		host := ev.Hostname
		if host == "" {
			host = as.Hostname
		}
		a.m.ModsecOutcome.WithLabelValues(host, ev.RuleID, ev.Severity, as.StatusClass).Inc()
	} else {
		a.buf.Append(ev.UniqueID, join.Pending{
			RuleID:   ev.RuleID,
			Severity: ev.Severity,
			Hostname: ev.Hostname,
		})
	}
	a.m.JoinBufferSize.Set(float64(a.buf.Size()))

	// Top-N: enrich country/ASN if a Lookup is available.
	if a.topN != nil && ev.ClientIP != "" {
		var country, asn string
		r := a.gip.Lookup(net.ParseIP(ev.ClientIP))
		country, asn = r.Country, r.ASN
		// Severity-derived weight; we don't have the request's anomaly score on this side.
		a.topN.Observe(ev.ClientIP, country, asn, severityWeight(ev.Severity), 1)
	}

	// Track buffer overflow as orphans counter (delta against lifetime total).
	if e := a.buf.OrphansEvicted(); e > a.lastEvicted {
		a.m.JoinBufferOrphans.Add(float64(e - a.lastEvicted))
		a.lastEvicted = e
	}
}

// SweepOrphans drops TTL-expired pending events and emits them as status_class=unknown.
// Called periodically from the main loop.
func (a *Aggregator) SweepOrphans() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, o := range a.buf.SweepExpired() {
		for _, p := range o.Pending {
			host := p.Hostname
			if host == "" {
				host = "unknown"
			}
			a.m.ModsecOutcome.WithLabelValues(host, p.RuleID, p.Severity, "unknown").Inc()
		}
	}
	a.m.JoinBufferSize.Set(float64(a.buf.Size()))
}

// severityWeight maps CRS severity strings to a small positive integer used for Top-N scoring.
func severityWeight(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "ERROR":
		return 4
	case "WARNING":
		return 3
	case "NOTICE":
		return 1
	}
	return 1
}
