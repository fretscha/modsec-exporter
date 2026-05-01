package parser

import (
	"reflect"
	"testing"
	"time"
)

// All sample lines below use RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
// 203.0.113.0/24) IPs and example.com hostnames so the test fixtures
// carry no real-world attribution.
func TestParseAccess(t *testing.T) {
	cases := []struct {
		name string
		line string
		want AccessEvent
		err  bool
	}{
		{
			name: "no-geoip",
			line: `192.0.2.10 -;-;- - [2026-01-15 12:00:00.123456] "GET / HTTP/1.0" 403 199 "-" "-" "-" 33278 example.com 192.168.1.10 443 - - - "ReqID--" Aaaaaaaaaaaaaaaaaaaaaaaaaa - - 5 561 -% 14395 7391 0 0 3-0-0-0 0-0-0-0 3 0`,
			want: AccessEvent{
				Timestamp:       time.Date(2026, 1, 15, 12, 0, 0, 123456000, time.UTC),
				ClientIP:        "192.0.2.10",
				Country:         "",
				ASN:             "",
				Method:          "GET",
				URI:             "/",
				Protocol:        "HTTP/1.0",
				Status:          403,
				ResponseBytes:   199,
				Hostname:        "example.com",
				UniqueID:        "Aaaaaaaaaaaaaaaaaaaaaaaaaa",
				AnomalyScoreIn:  3,
				AnomalyScoreOut: 0,
			},
		},
		{
			name: "with-geoip-and-tls",
			line: `198.51.100.42 XX;65001;Documentation_Range_Only - [2026-01-15 13:00:00.000000] "GET /test HTTP/1.1" 403 199 "-" "Mozilla/5.0 (synthetic-test-agent)" "-" 52165 example.com 192.168.1.10 443 - - - "ReqID--" Bbbbbbbbbbbbbbbbbbbbbbbbbb TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 835 5829 -% 9397 4432 0 0 5-0-0-0 0-0-0-0 5 0`,
			want: AccessEvent{
				Timestamp:       time.Date(2026, 1, 15, 13, 0, 0, 0, time.UTC),
				ClientIP:        "198.51.100.42",
				Country:         "XX",
				ASN:             "65001",
				Method:          "GET",
				URI:             "/test",
				Protocol:        "HTTP/1.1",
				Status:          403,
				ResponseBytes:   199,
				Hostname:        "example.com",
				UniqueID:        "Bbbbbbbbbbbbbbbbbbbbbbbbbb",
				AnomalyScoreIn:  5,
				AnomalyScoreOut: 0,
			},
		},
		{name: "empty", line: ``, err: true},
		{name: "garbage", line: `not a real access log line`, err: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAccess(tc.line)
			if (err != nil) != tc.err {
				t.Fatalf("err=%v, want err=%v", err, tc.err)
			}
			if tc.err {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("\ngot:  %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}
