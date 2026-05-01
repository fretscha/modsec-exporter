//go:build e2e

package modsec_exporter_e2e_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestReplayAgainstFixtures(t *testing.T) {
	const addr = "127.0.0.1:19555"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./bin/modsec-exporter",
		"--replay",
		"--access-log", "test/fixtures/access.log",
		"--error-log", "test/fixtures/error.log",
		"--listen", addr,
	)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer cmd.Wait()

	// Wait for ready, then scrape repeatedly until counts stabilize across two
	// consecutive scrapes 500ms apart (replay finished, all aggregation flushed).
	deadline := time.Now().Add(45 * time.Second)
	var body string
	var lastTotal float64
	stable := 0
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		r2, err2 := http.Get("http://" + addr + "/metrics")
		if err2 != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(r2.Body)
		r2.Body.Close()
		body = string(b)
		total := sumMetric(body, "http_requests_total") + sumMetric(body, "modsec_rule_triggered_total")
		if total == lastTotal && total > 0 {
			stable++
			if stable >= 2 {
				break
			}
		} else {
			stable = 0
			lastTotal = total
		}
		time.Sleep(500 * time.Millisecond)
	}
	if body == "" {
		out, _ := io.ReadAll(stdout)
		errOut, _ := io.ReadAll(stderr)
		t.Fatalf("never became ready\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}

	// Done scraping — ask the binary to shut down cleanly.
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}

	requireMin := func(metric string, min float64) {
		t.Helper()
		got := sumMetric(body, metric)
		if got < min {
			t.Errorf("%s = %.0f; want >= %.0f", metric, got, min)
		}
	}
	requireMin("http_requests_total", 1000)
	requireMin("modsec_rule_triggered_total", 100)
	requireMin("modsec_request_outcome_total", 50)

	if parseErrs := sumMetric(body, `modsec_exporter_log_lines_parsed_total{stream="access",result="parse_error"}`); parseErrs > 1000 {
		t.Errorf("too many access parse errors: %.0f", parseErrs)
	}
	t.Logf("smoke summary: http_requests=%.0f rules=%.0f outcomes=%.0f access_parse_err=%.0f error_parse_err=%.0f",
		sumMetric(body, "http_requests_total"),
		sumMetric(body, "modsec_rule_triggered_total"),
		sumMetric(body, "modsec_request_outcome_total"),
		sumMetric(body, `modsec_exporter_log_lines_parsed_total{stream="access",result="parse_error"}`),
		sumMetric(body, `modsec_exporter_log_lines_parsed_total{stream="error",result="parse_error"}`),
	)
}

// sumMetric naively sums all samples whose metric name (line prefix up to '{' or ' ') equals or
// matches the prefix. Good enough for smoke; use prometheus/expfmt for rich parsing.
func sumMetric(body, prefix string) float64 {
	var sum float64
	for _, line := range strings.Split(body, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		if !strings.HasPrefix(line, prefix) && name != prefix {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(parts[len(parts)-1], "%f", &v); err == nil {
			sum += v
		}
	}
	return sum
}
