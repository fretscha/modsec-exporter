// Package parser converts raw Apache access-log and ModSecurity error-log
// lines into structured events. All exported functions are pure.
package parser

import "time"

// AccessEvent is an Apache CRS-extended access-log line, parsed.
// Fields the exporter doesn't currently use are still parsed (cheap) so
// the metric model can grow without re-touching the parser.
type AccessEvent struct {
	Timestamp       time.Time
	ClientIP        string
	Country         string // ISO-2; "" when access log shows -;-;-
	ASN             string // numeric or ""
	Method          string
	URI             string // not exposed as a label, used by drilldown tools
	Protocol        string // "HTTP/1.1" etc.
	Status          int
	ResponseBytes   int64
	Hostname        string // vhost
	UniqueID        string // Apache mod_unique_id; correlation key
	DurationUsec    int64  // %D — total request time in microseconds
	AnomalyScoreIn  int    // ModSecAnomalyScoreIn (incoming)
	AnomalyScoreOut int    // ModSecAnomalyScoreOut (outgoing)
}

// ErrorEvent is one ModSecurity warning line.
type ErrorEvent struct {
	Timestamp     time.Time
	ClientIP      string
	UniqueID      string
	RuleID        string // numeric string
	Severity      string // NOTICE | WARNING | ERROR | CRITICAL | ALERT (uppercase)
	Hostname      string
	URI           string
	ParanoiaLevel string   // "1".."4" or "" when not tagged
	Categories    []string // attack-* tags, e.g. ["attack-sqli"]
}
