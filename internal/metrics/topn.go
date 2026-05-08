package metrics

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// TopN tracks the top-N attacker IPs by anomaly score and rule-trigger count.
// Implements prometheus.Collector — emits two gauge series per tracked IP at
// scrape time, drawn from the current top-N. State is not reset between scrapes;
// to clear it, call Reset().
type TopN struct {
	cap int

	mu        sync.Mutex
	stats     map[string]*ipStat
	descScore *prometheus.Desc
	descRules *prometheus.Desc
}

type ipStat struct {
	ip           string
	country      string
	asn          string
	anomalyScore int
	ruleCount    int
}

// NewTopN creates a tracker capped at the given size with site as a const label.
// cap=0 makes the tracker a no-op.
func NewTopN(cap int, site string) *TopN {
	return &TopN{
		cap:   cap,
		stats: make(map[string]*ipStat),
		descScore: prometheus.NewDesc(
			"modsec_top_attacker_anomaly_score",
			"Top-N attacking IPs by accumulated anomaly score.",
			[]string{"client_ip", "country", "asn"},
			prometheus.Labels{"site": site}),
		descRules: prometheus.NewDesc(
			"modsec_top_attacker_rules_triggered",
			"Top-N attacking IPs by rules-triggered count.",
			[]string{"client_ip", "country", "asn"},
			prometheus.Labels{"site": site}),
	}
}

// Observe records one rule-trigger event for ip with its enriched location.
func (t *TopN) Observe(ip, country, asn string, anomalyAdd int, ruleAdd int) {
	if t.cap == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.stats[ip]
	if !ok {
		s = &ipStat{ip: ip, country: country, asn: asn}
		t.stats[ip] = s
	}
	if country != "" && s.country == "" {
		s.country = country
	}
	if asn != "" && s.asn == "" {
		s.asn = asn
	}
	s.anomalyScore += anomalyAdd
	s.ruleCount += ruleAdd

	if len(t.stats) > t.cap*2 {
		t.shrinkLocked()
	}
}

// Reset drops all tracked state.
func (t *TopN) Reset() {
	t.mu.Lock()
	t.stats = make(map[string]*ipStat)
	t.mu.Unlock()
}

func (t *TopN) shrinkLocked() {
	if len(t.stats) <= t.cap {
		return
	}
	all := make([]*ipStat, 0, len(t.stats))
	for _, s := range t.stats {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].anomalyScore > all[j].anomalyScore })
	keep := make(map[string]*ipStat, t.cap)
	for i := 0; i < t.cap && i < len(all); i++ {
		keep[all[i].ip] = all[i]
	}
	t.stats = keep
}

// Describe implements prometheus.Collector.
func (t *TopN) Describe(ch chan<- *prometheus.Desc) {
	ch <- t.descScore
	ch <- t.descRules
}

// Collect implements prometheus.Collector. Emits the current top-N as gauges.
func (t *TopN) Collect(ch chan<- prometheus.Metric) {
	t.mu.Lock()
	t.shrinkLocked()
	snap := make([]ipStat, 0, len(t.stats))
	for _, s := range t.stats {
		snap = append(snap, *s)
	}
	t.mu.Unlock()

	sort.Slice(snap, func(i, j int) bool { return snap[i].anomalyScore > snap[j].anomalyScore })
	for _, s := range snap {
		country := s.country
		if country == "" {
			country = "unknown"
		}
		asn := s.asn
		if asn == "" {
			asn = "unknown"
		}
		ch <- prometheus.MustNewConstMetric(t.descScore, prometheus.GaugeValue, float64(s.anomalyScore), s.ip, country, asn)
		ch <- prometheus.MustNewConstMetric(t.descRules, prometheus.GaugeValue, float64(s.ruleCount), s.ip, country, asn)
	}
}
