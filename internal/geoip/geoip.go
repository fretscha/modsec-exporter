// Package geoip provides best-effort country/ASN lookup for client IPs
// when the access log doesn't carry pre-baked GeoIP fields.
package geoip

import "net"

// Result holds the enriched values; empty strings mean unknown.
type Result struct {
	Country string // ISO-2
	ASN     string
}

// Lookup is the small interface the aggregator depends on.
// Implementations must be safe for concurrent use.
type Lookup interface {
	Lookup(ip net.IP) Result
}

// Disabled is the no-op Lookup used when no MMDB is configured.
type Disabled struct{}

// Lookup always returns an empty Result.
func (Disabled) Lookup(net.IP) Result { return Result{} }
