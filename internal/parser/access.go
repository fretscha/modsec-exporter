package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var errAccessMalformed = errors.New("malformed access-log line")

// ParseAccess parses one Apache CRS-extended access-log line.
// Format reference: https://www.netnea.com/cms/apache-tutorial-5_extending-access-log/
//
// Tokenization: split on whitespace, but treat "..." and [...] as single tokens.
func ParseAccess(line string) (AccessEvent, error) {
	if line == "" {
		return AccessEvent{}, errAccessMalformed
	}

	tokens, err := tokenize(line)
	if err != nil {
		return AccessEvent{}, err
	}
	if len(tokens) < 24 {
		return AccessEvent{}, fmt.Errorf("%w: only %d tokens", errAccessMalformed, len(tokens))
	}

	ev := AccessEvent{ClientIP: tokens[0]}

	// GeoIP triple: "CC;ASN;Org" or "-;-;-"
	if g := tokens[1]; g != "-;-;-" && g != "-" {
		parts := strings.SplitN(g, ";", 3)
		if len(parts) >= 2 {
			if parts[0] != "-" {
				ev.Country = parts[0]
			}
			if parts[1] != "-" {
				ev.ASN = parts[1]
			}
		}
	}

	// tokens[2] = auth-user (-)
	// tokens[3] = "[YYYY-MM-DD HH:MM:SS.uuuuuu]"
	tsStr := strings.Trim(tokens[3], "[]")
	ts, err := time.Parse(tsFormat, tsStr)
	if err != nil {
		return AccessEvent{}, fmt.Errorf("timestamp: %w", err)
	}
	ev.Timestamp = ts.UTC()

	// tokens[4] = `"METHOD URI PROTOCOL"`
	reqLine := strings.Trim(tokens[4], `"`)
	rp := strings.SplitN(reqLine, " ", 3)
	if len(rp) == 3 {
		ev.Method, ev.URI, ev.Protocol = rp[0], rp[1], rp[2]
	}

	// tokens[5] = status, tokens[6] = response bytes
	if v, err := strconv.Atoi(tokens[5]); err == nil {
		ev.Status = v
	}
	if v, err := strconv.ParseInt(tokens[6], 10, 64); err == nil {
		ev.ResponseBytes = v
	}

	// tokens[7..9] = referer, ua, content-type (quoted)
	// tokens[10] = pid, tokens[11] = vhost
	ev.Hostname = tokens[11]

	// Locate UNIQUE_ID. Format ordering after vhost:
	//   server_ip server_port %D %X "%{ModSecTimer}o" %{UNIQUE_ID}e ...
	// Strategy: find first token after position 14 that looks like a unique_id.
	uidIdx := -1
	for i := 15; i < len(tokens); i++ {
		if isUniqueID(tokens[i]) {
			uidIdx = i
			break
		}
	}
	if uidIdx == -1 {
		return AccessEvent{}, fmt.Errorf("%w: unique_id not found", errAccessMalformed)
	}
	ev.UniqueID = tokens[uidIdx]

	// Trailing positional fields after unique_id:
	//   SSL_PROTOCOL SSL_CIPHER bytes_in bytes_out ratio% modsec_in_us app_us modsec_out_us
	//   anomaly_in out_pl1-pl2-pl3-pl4 in_pl1-pl2-pl3-pl4 anomaly_in_total anomaly_out_total
	// Pull last two integer tokens as anomaly_in_total / anomaly_out_total.
	tail := tokens[uidIdx+1:]
	if len(tail) >= 2 {
		if v, err := strconv.Atoi(tail[len(tail)-2]); err == nil {
			ev.AnomalyScoreIn = v
		}
		if v, err := strconv.Atoi(tail[len(tail)-1]); err == nil {
			ev.AnomalyScoreOut = v
		}
	}

	return ev, nil
}

// isUniqueID is a loose check for Apache mod_unique_id values.
// Real values: typically 24-28 chars, base64url-ish, allowing '@'.
func isUniqueID(s string) bool {
	if len(s) < 20 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '@' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// tokenize splits a line on whitespace, preserving "..." and [...] as single tokens.
func tokenize(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var inDouble, inBracket bool
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case inDouble:
			cur.WriteRune(r)
			if r == '"' {
				inDouble = false
			}
		case inBracket:
			cur.WriteRune(r)
			if r == ']' {
				inBracket = false
			}
		case r == '"':
			cur.WriteRune(r)
			inDouble = true
		case r == '[':
			cur.WriteRune(r)
			inBracket = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	if inDouble || inBracket {
		return nil, fmt.Errorf("%w: unterminated quote", errAccessMalformed)
	}
	return out, nil
}
