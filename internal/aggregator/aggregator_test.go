package aggregator

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/fretscha/modsec-exporter/internal/geoip"
	"github.com/fretscha/modsec-exporter/internal/metrics"
	"github.com/fretscha/modsec-exporter/internal/parser"
)

func newAgg(t *testing.T) (*Aggregator, *metrics.Metrics) {
	t.Helper()
	m := metrics.New()
	a := New(m, geoip.Disabled{}, Config{
		BufferSize: 100,
		BufferTTL:  60 * time.Second,
		TopN:       50,
		Now:        time.Now,
	})
	return a, m
}

func TestJoin_AttachesStatusToRules(t *testing.T) {
	a, m := newAgg(t)
	a.OnError(parser.ErrorEvent{UniqueID: "abc", RuleID: "942100", Severity: "CRITICAL", Hostname: "www.example.com", ParanoiaLevel: "1", Categories: []string{"attack-sqli"}, ClientIP: "1.2.3.4"})
	a.OnError(parser.ErrorEvent{UniqueID: "abc", RuleID: "920350", Severity: "WARNING", Hostname: "www.example.com", ParanoiaLevel: "1", ClientIP: "1.2.3.4"})
	a.OnAccess(parser.AccessEvent{UniqueID: "abc", Status: 403, Hostname: "www.example.com", Method: "GET"})

	if got := testutil.ToFloat64(m.ModsecOutcome.WithLabelValues("www.example.com", "942100", "CRITICAL", "4xx")); got != 1 {
		t.Fatalf("942100/4xx outcome = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ModsecOutcome.WithLabelValues("www.example.com", "920350", "WARNING", "4xx")); got != 1 {
		t.Fatalf("920350/4xx outcome = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.JoinBufferSize); got != 0 {
		t.Fatalf("buffer size = %v, want 0 (drained)", got)
	}
	if got := testutil.ToFloat64(m.HTTPRequests.WithLabelValues("www.example.com", "GET", "4xx")); got != 1 {
		t.Fatalf("http_requests = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ModsecRuleTriggered.WithLabelValues("www.example.com", "942100", "CRITICAL", "1")); got != 1 {
		t.Fatalf("rule_triggered = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ModsecAttackCat.WithLabelValues("www.example.com", "attack-sqli")); got != 1 {
		t.Fatalf("attack_category = %v, want 1", got)
	}
}

func TestJoin_OrphanEmittedAsUnknownAfterTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := metrics.New()
	a := New(m, geoip.Disabled{}, Config{
		BufferSize: 100,
		BufferTTL:  30 * time.Second,
		TopN:       0,
		Now:        func() time.Time { return now },
	})

	a.OnError(parser.ErrorEvent{UniqueID: "orphan", RuleID: "100", Severity: "WARNING", Hostname: "h"})
	now = now.Add(31 * time.Second)
	a.SweepOrphans()

	if got := testutil.ToFloat64(m.ModsecOutcome.WithLabelValues("h", "100", "WARNING", "unknown")); got != 1 {
		t.Fatalf("orphan outcome = %v, want 1", got)
	}
}

func TestParseError_CountsAsParseError(t *testing.T) {
	a, m := newAgg(t)
	a.OnRawAccess("garbage")
	a.OnRawError("garbage")
	if got := testutil.ToFloat64(m.LinesParsed.WithLabelValues("access", "parse_error")); got != 1 {
		t.Fatalf("access parse_error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.LinesParsed.WithLabelValues("error", "parse_error")); got != 1 {
		t.Fatalf("error parse_error = %v, want 1", got)
	}
}

func TestJoin_AccessFirstThenError(t *testing.T) {
	a, m := newAgg(t)
	// Access arrives BEFORE the error event (racy / out-of-order / mixed).
	// Non-zero AnomalyScoreIn signals "CRS scored this request" — required for
	// the access summary to be remembered (benign requests are skipped).
	a.OnAccess(parser.AccessEvent{UniqueID: "xyz", Status: 403, Hostname: "h", Method: "GET", AnomalyScoreIn: 5})
	a.OnError(parser.ErrorEvent{UniqueID: "xyz", RuleID: "942100", Severity: "CRITICAL", Hostname: "h"})
	// A SECOND late error for the same uid must also join — multiple errors per request.
	a.OnError(parser.ErrorEvent{UniqueID: "xyz", RuleID: "920350", Severity: "WARNING", Hostname: "h"})

	if got := testutil.ToFloat64(m.ModsecOutcome.WithLabelValues("h", "942100", "CRITICAL", "4xx")); got != 1 {
		t.Fatalf("first late-error outcome = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ModsecOutcome.WithLabelValues("h", "920350", "WARNING", "4xx")); got != 1 {
		t.Fatalf("second late-error outcome = %v, want 1 (buffer must keep the access summary for subsequent errors)", got)
	}
	// Buffer size = 1 is correct: the AccessSummary stays remembered until TTL eviction.
}

func TestJoin_BenignAccessNotRemembered(t *testing.T) {
	a, m := newAgg(t)
	// Benign request (AnomalyScoreIn=0): should NOT be remembered.
	a.OnAccess(parser.AccessEvent{UniqueID: "benign", Status: 200, Hostname: "h", Method: "GET", AnomalyScoreIn: 0})
	if got := testutil.ToFloat64(m.JoinBufferSize); got != 0 {
		t.Fatalf("buffer size = %v, want 0 (benign access not remembered)", got)
	}
}

func TestBufferOverflow_IncrementsOrphansCounter(t *testing.T) {
	m := metrics.New()
	a := New(m, geoip.Disabled{}, Config{
		BufferSize: 2,
		BufferTTL:  10 * time.Minute,
		TopN:       0,
		Now:        time.Now,
	})
	a.OnError(parser.ErrorEvent{UniqueID: "a", RuleID: "1", Severity: "WARNING", Hostname: "h", ClientIP: "1.1.1.1"})
	a.OnError(parser.ErrorEvent{UniqueID: "b", RuleID: "2", Severity: "WARNING", Hostname: "h", ClientIP: "1.1.1.1"})
	a.OnError(parser.ErrorEvent{UniqueID: "c", RuleID: "3", Severity: "WARNING", Hostname: "h", ClientIP: "1.1.1.1"})

	if got := testutil.ToFloat64(m.JoinBufferOrphans); got != 1 {
		t.Fatalf("orphans counter = %v, want 1", got)
	}
}
