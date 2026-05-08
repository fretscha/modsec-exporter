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

// Aggregator is the central event sink for one site. Methods are safe for concurrent use.
type Aggregator struct {
	m    *metrics.Metrics
	gip  geoip.Lookup
	buf  *join.Buffer
	topN *metrics.TopN
	site string

	mu          sync.Mutex
	lastEvicted uint64
}

// New constructs an Aggregator for the named site and, if cfg.TopN > 0,
// registers a bounded Top-N attacker collector in the shared registry.
func New(m *metrics.Metrics, gip geoip.Lookup, cfg Config, site string) *Aggregator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	tn := metrics.NewTopN(cfg.TopN, site)
	if cfg.TopN > 0 {
		m.Registry.MustRegister(tn)
	}
	return &Aggregator{
		m:    m,
		gip:  gip,
		buf:  join.NewBuffer(cfg.BufferSize, cfg.BufferTTL, cfg.Now),
		topN: tn,
		site: site,
	}
}

// OnRawAccess parses then forwards. Drops malformed lines with a counter increment.
func (a *Aggregator) OnRawAccess(line string) {
	ev, err := parser.ParseAccess(line)
	if err != nil {
		a.m.LinesParsed.WithLabelValues(a.site, "access", "parse_error").Inc()
		return
	}
	a.m.LinesParsed.WithLabelValues(a.site, "access", "ok").Inc()
	a.OnAccess(ev)
}

// OnRawError parses then forwards.
func (a *Aggregator) OnRawError(line string) {
	ev, err := parser.ParseError(line)
	if err != nil {
		a.m.LinesParsed.WithLabelValues(a.site, "error", "parse_error").Inc()
		return
	}
	a.m.LinesParsed.WithLabelValues(a.site, "error", "ok").Inc()
	a.OnError(ev)
}

// OnAccess updates RED metrics and drains pending error events for this
// unique_id. If no errors are buffered yet, remembers the access summary so a
// late-arriving error event can still emit the joined outcome metric.
func (a *Aggregator) OnAccess(ev parser.AccessEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc := metrics.StatusClass(ev.Status)
	a.m.HTTPRequests.WithLabelValues(a.site, ev.Method, sc).Inc()
	a.m.HTTPRequestDuration.WithLabelValues(a.site, ev.Method, sc).Observe(float64(ev.DurationUsec) / 1e6)
	a.m.HTTPResponseSize.WithLabelValues(a.site, sc).Observe(float64(ev.ResponseBytes))

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
	a.m.HTTPRequestsCountry.WithLabelValues(a.site, country, sc).Inc()

	a.m.ModsecAnomalyScore.WithLabelValues(a.site, "incoming").Observe(float64(ev.AnomalyScoreIn))
	a.m.ModsecAnomalyScore.WithLabelValues(a.site, "outgoing").Observe(float64(ev.AnomalyScoreOut))

	pending := a.buf.Drain(ev.UniqueID)
	for _, p := range pending {
		a.m.ModsecOutcome.WithLabelValues(a.site, p.RuleID, p.Severity, sc).Inc()
	}
	if ev.AnomalyScoreIn > 0 {
		a.buf.RememberAccess(ev.UniqueID, join.AccessSummary{
			StatusClass: sc,
		})
	}
	a.m.JoinBufferSize.WithLabelValues(a.site).Set(float64(a.buf.Size()))
}

// OnError updates rule metrics and stores the event in the join buffer.
func (a *Aggregator) OnError(ev parser.ErrorEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pl := ev.ParanoiaLevel
	if pl == "" {
		pl = "unknown"
	}
	a.m.ModsecRuleTriggered.WithLabelValues(a.site, ev.RuleID, ev.Severity, pl).Inc()
	for _, c := range ev.Categories {
		a.m.ModsecAttackCat.WithLabelValues(a.site, c).Inc()
	}

	if as := a.buf.PeekAccess(ev.UniqueID); as != nil {
		a.m.ModsecOutcome.WithLabelValues(a.site, ev.RuleID, ev.Severity, as.StatusClass).Inc()
	} else {
		a.buf.Append(ev.UniqueID, join.Pending{
			RuleID:   ev.RuleID,
			Severity: ev.Severity,
		})
	}
	a.m.JoinBufferSize.WithLabelValues(a.site).Set(float64(a.buf.Size()))

	if a.topN != nil && ev.ClientIP != "" {
		r := a.gip.Lookup(net.ParseIP(ev.ClientIP))
		a.topN.Observe(ev.ClientIP, r.Country, r.ASN, severityWeight(ev.Severity), 1)
	}

	if e := a.buf.OrphansEvicted(); e > a.lastEvicted {
		a.m.JoinBufferOrphans.WithLabelValues(a.site).Add(float64(e - a.lastEvicted))
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
			a.m.ModsecOutcome.WithLabelValues(a.site, p.RuleID, p.Severity, "unknown").Inc()
		}
	}
	a.m.JoinBufferSize.WithLabelValues(a.site).Set(float64(a.buf.Size()))
}

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
