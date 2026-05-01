package parser

import (
	"reflect"
	"testing"
	"time"
)

// All sample lines below use RFC 5737 IPs and example.com hostnames.
// CRS rule IDs (e.g. 942100, 920350) are public OWASP CRS canonical IDs,
// not user-derived data.
func TestParseError(t *testing.T) {
	cases := []struct {
		name string
		line string
		want ErrorEvent
		err  bool
	}{
		{
			name: "crs-sqli-critical",
			line: `[2026-01-15 12:00:00.123456] [-:error] 203.0.113.5:55531 Cccccccccccccccccccccccccc [client 203.0.113.5] ModSecurity: Warning. Pattern match at REQUEST. [file "/etc/apache2/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "100"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "synthetic test data"] [severity "CRITICAL"] [ver "OWASP_CRS/4.0.0-rc1"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "OWASP_CRS"] [hostname "example.com"] [uri "/login"] [unique_id "Cccccccccccccccccccccccccc"]`,
			want: ErrorEvent{
				Timestamp:  time.Date(2026, 1, 15, 12, 0, 0, 123456000, time.UTC),
				ClientIP:   "203.0.113.5",
				UniqueID:   "Cccccccccccccccccccccccccc",
				RuleID:     "942100",
				Severity:   "CRITICAL",
				Hostname:   "example.com",
				URI:        "/login",
				Categories: []string{"attack-sqli"},
			},
		},
		{
			name: "crs-host-ip-with-paranoia-level",
			line: `[2026-01-15 13:00:00.000000] [-:error] 198.51.100.7:47273 Dddddddddddddddddddddddddd [client 198.51.100.7] ModSecurity: Warning. Pattern match at REQUEST_HEADERS:Host. [file "/etc/apache2/crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "761"] [id "920350"] [msg "Host header is a numeric IP address"] [data "1.2.3.4"] [severity "WARNING"] [ver "OWASP_CRS/4.0.0-rc1"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [hostname "example.com"] [uri "/"] [unique_id "Dddddddddddddddddddddddddd"]`,
			want: ErrorEvent{
				Timestamp:     time.Date(2026, 1, 15, 13, 0, 0, 0, time.UTC),
				ClientIP:      "198.51.100.7",
				UniqueID:      "Dddddddddddddddddddddddddd",
				RuleID:        "920350",
				Severity:      "WARNING",
				Hostname:      "example.com",
				URI:           "/",
				ParanoiaLevel: "1",
				Categories:    []string{"attack-protocol"},
			},
		},
		{
			name: "non-modsec-line-ignored",
			line: `[Sun Nov 20 04:00:01.123456 2026] [mpm_event:notice] [pid 12345:tid 7890] AH00489: Apache/2.4.54 configured -- resuming normal operations`,
			err:  true,
		},
		{
			name: "empty",
			line: ``,
			err:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseError(tc.line)
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
