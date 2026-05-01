package parser

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	errModSecOnly = errors.New("not a modsecurity warning")
	errMalformed  = errors.New("malformed modsecurity line")
)

var (
	reHeader = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\] \[[^\]]*:error\] (\d+\.\d+\.\d+\.\d+):\d+ (\S+) \[client `)

	reBracketed = regexp.MustCompile(`\[(\w+)\s+"([^"]*)"\]`)
)

const tsFormat = "2006-01-02 15:04:05.000000"

// ParseError parses a single ModSecurity error-log line.
// Returns errModSecOnly for non-ModSec lines; the caller should drop those.
func ParseError(line string) (ErrorEvent, error) {
	if !strings.Contains(line, "ModSecurity:") {
		return ErrorEvent{}, errModSecOnly
	}

	m := reHeader.FindStringSubmatch(line)
	if m == nil {
		return ErrorEvent{}, errMalformed
	}

	ts, err := time.Parse(tsFormat, m[1])
	if err != nil {
		return ErrorEvent{}, fmt.Errorf("timestamp parse: %w", err)
	}

	ev := ErrorEvent{
		Timestamp: ts.UTC(),
		ClientIP:  m[2],
		UniqueID:  m[3],
	}

	for _, b := range reBracketed.FindAllStringSubmatch(line, -1) {
		key, val := b[1], b[2]
		switch key {
		case "id":
			ev.RuleID = val
		case "severity":
			ev.Severity = strings.ToUpper(val)
		case "hostname":
			ev.Hostname = val
		case "uri":
			ev.URI = val
		case "unique_id":
			if ev.UniqueID == "" {
				ev.UniqueID = val
			}
		case "tag":
			switch {
			case strings.HasPrefix(val, "paranoia-level/"):
				ev.ParanoiaLevel = strings.TrimPrefix(val, "paranoia-level/")
			case strings.HasPrefix(val, "attack-"):
				ev.Categories = append(ev.Categories, val)
			}
		}
	}

	if ev.RuleID == "" {
		return ErrorEvent{}, errMalformed
	}
	return ev, nil
}
