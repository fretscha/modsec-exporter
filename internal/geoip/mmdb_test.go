package geoip

import (
	"net"
	"testing"
)

func TestDisabled(t *testing.T) {
	got := Disabled{}.Lookup(net.ParseIP("8.8.8.8"))
	if got.Country != "" || got.ASN != "" {
		t.Fatalf("expected empty Result, got %+v", got)
	}
}

func TestMMDB_DisabledOnMissingFile(t *testing.T) {
	if _, err := NewMMDB("/no/such/file.mmdb", 100); err == nil {
		t.Fatal("expected error for missing file")
	}
}
