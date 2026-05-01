// Package metrics defines all Prometheus metrics for modsec-exporter.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics groups every registered metric. The aggregator owns one instance.
type Metrics struct {
	Registry *prometheus.Registry

	// (a) Access stream — golden signals
	HTTPRequests        *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPResponseSize    *prometheus.HistogramVec
	HTTPRequestsCountry *prometheus.CounterVec

	// (b) ModSec rule stream
	ModsecRuleTriggered *prometheus.CounterVec
	ModsecAnomalyScore  *prometheus.HistogramVec
	ModsecAttackCat     *prometheus.CounterVec

	// (c) Joined metric
	ModsecOutcome *prometheus.CounterVec

	// (e) Operational
	LinesParsed       *prometheus.CounterVec
	JoinBufferSize    prometheus.Gauge
	JoinBufferOrphans prometheus.Counter
	GeoIPLookups      *prometheus.CounterVec
	TailErrors        *prometheus.CounterVec
	BuildInfo         *prometheus.GaugeVec
}

// New constructs Metrics, registers them in a fresh registry, and adds
// the standard Go + process collectors.
func New() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector())
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{Registry: r}

	m.HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "HTTP requests observed in the access log.",
	}, []string{"hostname", "method", "status_class"})

	m.HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request duration as logged by Apache (%D, in seconds).",
		Buckets: prometheus.DefBuckets,
	}, []string{"hostname", "method", "status_class"})

	m.HTTPResponseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_size_bytes",
		Help:    "HTTP response body size in bytes.",
		Buckets: []float64{1024, 8192, 65536, 524288, 4194304, 33554432},
	}, []string{"hostname", "status_class"})

	m.HTTPRequestsCountry = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_by_country_total",
		Help: "HTTP requests by source country (ISO-2; 'unknown' if not resolvable).",
	}, []string{"hostname", "country", "status_class"})

	m.ModsecRuleTriggered = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modsec_rule_triggered_total",
		Help: "Count of ModSecurity rule triggers from the error log.",
	}, []string{"hostname", "rule_id", "severity", "paranoia_level"})

	m.ModsecAnomalyScore = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "modsec_anomaly_score",
		Help:    "Distribution of CRS anomaly scores per request (incoming/outgoing).",
		Buckets: []float64{0, 1, 2, 3, 5, 7, 10, 15, 20, 30, 50, 100},
	}, []string{"hostname", "direction"})

	m.ModsecAttackCat = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modsec_attack_category_total",
		Help: "ModSecurity rule triggers by CRS attack-* tag.",
	}, []string{"hostname", "category"})

	m.ModsecOutcome = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modsec_request_outcome_total",
		Help: "Joined: triggered rules grouped by access-log status_class. status_class=\"unknown\" denotes orphaned error events.",
	}, []string{"hostname", "rule_id", "severity", "status_class"})

	m.LinesParsed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modsec_exporter_log_lines_parsed_total",
		Help: "Lines read from each log stream, by parse result.",
	}, []string{"stream", "result"})

	m.JoinBufferSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "modsec_exporter_join_buffer_size",
		Help: "Number of pending unique_ids in the correlation buffer.",
	})

	m.JoinBufferOrphans = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "modsec_exporter_join_buffer_orphans_total",
		Help: "Lifetime count of buffer entries evicted due to size overflow (not TTL).",
	})

	m.GeoIPLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modsec_exporter_geoip_lookups_total",
		Help: "GeoIP fallback lookups, by result.",
	}, []string{"result"})

	m.TailErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "modsec_exporter_tail_errors_total",
		Help: "File-tail errors (rotation, permissions, etc.).",
	}, []string{"stream"})

	m.BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "modsec_exporter_build_info",
		Help: "Build metadata; value is always 1.",
	}, []string{"version", "go_version"})

	r.MustRegister(
		m.HTTPRequests, m.HTTPRequestDuration, m.HTTPResponseSize, m.HTTPRequestsCountry,
		m.ModsecRuleTriggered, m.ModsecAnomalyScore, m.ModsecAttackCat,
		m.ModsecOutcome,
		m.LinesParsed, m.JoinBufferSize, m.JoinBufferOrphans, m.GeoIPLookups, m.TailErrors, m.BuildInfo,
	)

	return m
}

// StatusClass groups raw HTTP status into 2xx/3xx/4xx/5xx/unknown.
func StatusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	}
	return "unknown"
}
