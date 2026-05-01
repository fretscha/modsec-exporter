# modsec-exporter — Design

**Status:** Draft
**Date:** 2026-04-29
**Author:** fretscha

## 1. Goal

Expose Prometheus metrics derived from a paired Apache access log and ModSecurity / OWASP CRS 4.x error log, enabling three families of insight:

1. **Attack overview** — top CRS rules firing, severity distribution, top attacker countries / ASNs / IPs.
2. **WAF effectiveness** — anomaly score distribution, blocked-vs-passed traffic per rule, paranoia-level coverage.
3. **Service RED metrics** — request rate, error rate, latency, response sizes per host / method / status.

Out of scope for this exporter (defer to external batch tools):

- Per-IP / per-URI / per-message drill-down (cardinality cliff in Prometheus).
- False-positive batch reporting.
- Single-event rule-exclusion generation.
- JSON audit logs v2/v3 (plain-text only for v1).

## 2. Architecture (one-line summary)

Two log tailers feed pure parsers; a single central aggregator updates Prometheus metrics and maintains a small bounded buffer that joins access-log status codes onto the rules that fired during that request.

```
   ┌──────────────┐  Event   ┌──────────────┐
   │ access tail  │─────────▶│              │
   └──────────────┘          │              │  promhttp   ┌─────────┐
                             │  Aggregator  │────────────▶│/metrics │
   ┌──────────────┐  Event   │              │             └─────────┘
   │ error  tail  │─────────▶│              │
   └──────────────┘          └──────────────┘
                                    │
                                    ▼
                       bounded LRU (unique_id → access summary)
                       for the "blocked vs passed" join
```

## 3. Data flow & temporal ordering

Apache writes ModSecurity error events during request phase 2-4, but writes the access log entry only after the response is finalized (phase 5). Therefore **error events always arrive before the matching access event** for the same `unique_id`. The join buffer holds *pending error events* and drains them when the access entry shows up.

```
  error.log ──▶ ParseError ──▶ Aggregator ──▶ modsec_rule_triggered_total          (stream)
                                   │
                                   └─ buffer (unique_id → [pending error events])
                                                       │
  access.log ──▶ ParseAccess ──▶ Aggregator ──┐        │
                       │                       │       │
                       ├──▶ http_requests_total (stream)
                       │
                       └──▶ look up unique_id in buffer ──▶ drain pending events
                                                                  │
                                                                  ▼
                                              modsec_request_outcome_total
                                              {rule_id, severity, status_class, host}
                                                       (the targeted join)
```

### Step-by-step

1. **Error event arrives** (mid-request)
   - Emit `modsec_rule_triggered_total{rule_id, severity, hostname, paranoia_level}` immediately (stream metric, never waits).
   - Append `{rule_id, severity}` to `buffer[unique_id]`.
   - Update Top-N attacker tracker by client_ip.

2. **Access event arrives** (after response finalized)
   - Emit `http_requests_total`, `http_request_duration_seconds`, `http_response_size_bytes`, `http_requests_by_country_total` immediately (stream metrics).
   - Lookup `buffer[unique_id]`:
     - **hit** → for each pending event, emit `modsec_request_outcome_total{rule_id, severity, status_class, hostname}`; delete the entry.
     - **miss** → no rules fired for this request; nothing extra.
   - If access log's GeoIP field is `-;-;-` and MMDB configured, kick off async lookup (cache-fronted, never blocks).

3. **Periodic TTL sweep** (every 10s)
   - Drop pending entries older than 60s (rare — server crash mid-request, log rotation race). Emit those orphans as `modsec_request_outcome_total{status_class="unknown"}` so counts are preserved.
   - Buffer is also size-bounded (default 50k entries); on overflow, evict oldest first.

`status_class` is exposed (not a precomputed `blocked` boolean) so the user can write their own PromQL definition of "blocked" — `4xx`, or `4xx or 5xx`, or filter by severity.

## 4. Module layout

```
modsec-exporter/
├── cmd/
│   └── modsec-exporter/
│       └── main.go              # flag/env parsing, wire components, start servers
├── internal/
│   ├── tail/
│   │   ├── tail.go              # Tailer interface
│   │   ├── file.go              # production impl (nxadm/tail), rotation-aware
│   │   └── replay.go            # test/dev impl: read file start→EOF, then close
│   ├── parser/
│   │   ├── types.go             # AccessEvent, ErrorEvent struct definitions
│   │   ├── access.go            # ParseAccess(line string) (AccessEvent, error)
│   │   └── error.go             # ParseError(line string) (ErrorEvent, error)
│   ├── geoip/
│   │   ├── geoip.go             # Lookup interface + Disabled impl
│   │   └── mmdb.go              # MMDB-backed impl with LRU cache
│   ├── join/
│   │   └── buffer.go            # bounded LRU(unique_id → access summary), TTL eviction
│   ├── aggregator/
│   │   └── aggregator.go        # consumes both event channels, updates metrics, owns join buffer
│   ├── metrics/
│   │   ├── metrics.go           # all prometheus.{Counter,Histogram,Gauge}Vec definitions
│   │   └── topn.go              # Top-N tracker + custom Collector
│   └── server/
│       └── http.go              # /metrics (promhttp), /healthz, /readyz
├── test/
│   └── fixtures/                # sampled lines from real access.log/error.log
├── docker/
│   └── Dockerfile               # multi-stage, distroless final
├── docs/
│   └── design/2026-04-29-modsec-prom-exporter-design.md
├── go.mod
├── Makefile                     # test, lint, build, smoke-test
└── README.md
```

### Why this shape

- **Each `internal/` package is one focused concern** with a small public surface. Parsers are pure functions, tail is an interface with two impls, geoip is an interface (Disabled is the default), join is a single data structure, aggregator is the only stateful coordinator.
- **Pure-function parsers** mean every parser test is `input string → expected struct` — fast, deterministic, no I/O.
- **`tail.Tailer` as an interface** gives a free "replay" mode for CI and local dev — same code path as production, just a different impl.
- **Top-N is a custom `prometheus.Collector`**, not a `GaugeVec`, so it can clear and re-emit on every scrape without time-series bleed.

## 5. Metric model

### (a) Access stream — golden signals

```
http_requests_total{hostname, method, status_class}                    counter
http_request_duration_seconds{hostname, method, status_class}          histogram
http_response_size_bytes{hostname, status_class}                       histogram
http_requests_by_country_total{hostname, country, status_class}        counter
```

`status_class ∈ {"2xx","3xx","4xx","5xx"}` — keeps the latency histogram low-cardinality (4 classes × 12 buckets, not 50 codes × 12 buckets). Country lives on its own counter, not on the histogram, so we don't multiply 250 countries × 12 buckets.

### (b) ModSec rule stream

```
modsec_rule_triggered_total{hostname, rule_id, severity, paranoia_level}    counter
modsec_anomaly_score{hostname, direction="incoming|outgoing"}               histogram
modsec_attack_category_total{hostname, category}                            counter
```

`category` is derived from CRS `tag "attack-…"` values (sqli, xss, lfi, rfi, rce, fixation, scanner, generic, …) — bounded at ~15.

`severity` and `paranoia_level` are technically redundant with `rule_id` but kept so dashboards can `sum by(severity)` without joining against a rule catalog.

### (c) Joined metric

```
modsec_request_outcome_total{hostname, rule_id, severity, status_class}    counter
```

Headline insight:

```promql
sum by(rule_id)(rate(modsec_request_outcome_total{status_class="4xx"}[5m]))
  / sum by(rule_id)(rate(modsec_request_outcome_total[5m]))
```

= fraction of times this rule actually blocked vs. just warned. Exposes DetectionOnly mode and tuning gaps in one query.

### (d) Top-N attackers (custom collector, resets every scrape)

```
modsec_top_attacker_anomaly_score{client_ip, country, asn}      gauge
modsec_top_attacker_rules_triggered{client_ip, country, asn}    gauge
```

Capped at N=50 (config `--top-n`, 0 disables). Re-emitted each scrape from an internal sorted ring; old IPs never linger as stale series.

### (e) Operational health

```
modsec_exporter_log_lines_parsed_total{stream, result="ok|parse_error"}    counter
modsec_exporter_join_buffer_size                                            gauge
modsec_exporter_join_buffer_orphans_total                                   counter
modsec_exporter_geoip_lookups_total{result="hit|miss|disabled"}             counter
modsec_exporter_tail_errors_total{stream}                                   counter
modsec_exporter_build_info{version, go_version}                             gauge
```

### Cardinality budget

Worst case, single Apache, ~5 vhosts, full CRS 4.x, ~250 countries seen:

| Metric | Series |
|---|---:|
| http_requests_total | 200 |
| http_request_duration_seconds | 2 400 |
| http_response_size_bytes | 300 |
| http_requests_by_country_total | 6 250 |
| modsec_rule_triggered_total | 1 500 |
| modsec_anomaly_score | 120 |
| modsec_attack_category_total | 75 |
| modsec_request_outcome_total | 7 500 |
| top_attacker_* | 100 |
| exporter_* | ~20 |
| **Total** | **≈ 18k** |

Comfortable for any Prom instance. Roughly linear in vhost count.

### Histogram buckets (proposed)

- `http_request_duration_seconds`: Prometheus default (`0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10`)
- `http_response_size_bytes`: `1024, 8192, 65536, 524288, 4194304, 33554432` (1 KiB → 32 MiB)
- `modsec_anomaly_score`: `0, 1, 2, 3, 5, 7, 10, 15, 20, 30, 50, 100`

### What we deliberately don't expose

`client_ip` / `uri` / `user_agent` / `msg` are never label values (except `client_ip` inside the bounded Top-N gauge). For per-IP / per-URI / per-message investigation, pair this exporter with an external batch log-analysis tool that can handle unbounded cardinality.

## 6. Configuration

12-factor: env vars override flags override defaults. No YAML in v1.

```
modsec-exporter \
  --access-log /var/log/apache2/access.log \
  --error-log  /var/log/apache2/error.log \
  --listen     :9555 \
  --mmdb       /var/lib/geoip/country.mmdb     # empty → disables GeoIP fallback
  --top-n      50                              # 0 → disables Top-N gauges
  --buffer-size 50000                          # max pending unique_ids in join buffer
  --buffer-ttl  60s                            # max age of pending entry
  --sweep-interval 10s
  --replay                                     # one-shot mode: read both files start→EOF, then exit
  --log-level  info
```

Each flag has a `MODSEC_EXPORTER_*` env var equivalent.

**Defaults**:
- listen: `:9555` (verify against [Prom port registry](https://github.com/prometheus/prometheus/wiki/Default-port-allocations) before release).
- buffer-size 50 000, buffer-ttl 60s, sweep 10s, top-n 50.
- mmdb empty → GeoIP fallback disabled; exporter still works using only the access log's pre-baked field.
- replay false.

`--replay` makes development ergonomic: point at the fixtures, exporter reads once, populates metrics, exits 0. CI runs the same flow as a smoke test.

## 7. Error handling & resilience

**Log rotation.** `nxadm/tail` with `Follow=true, ReOpen=true, Poll=false` (inotify). Handles both rotation styles:
- `create` (logrotate default): old file moves, new file created → tail follows the new inode.
- `copytruncate`: file truncated → tail detects shrink, re-reads from offset 0.

Reopen failures increment `modsec_exporter_tail_errors_total{stream}`. Retry with exponential backoff, capped at 30s.

**File missing at startup.** Don't fatal-exit. Log warning, increment tail error counter, retry every 5s. Allows `systemctl start modsec-exporter` before Apache has written its first line.

**Malformed lines.** Parsers return `(Event, error)`. Aggregator increments `modsec_exporter_log_lines_parsed_total{stream, result="parse_error"}` and drops the line. Never kills the process — log injection is plausible. A debug-only `/debug/parse-errors` endpoint (off by default, behind `--debug` flag) keeps a ring of recent samples for diagnosis.

**MMDB unavailable / corrupted.** Lookup returns `Disabled` impl on load failure. Log error, increment `geoip_lookups_total{result="disabled"}`, continue. The exporter never depends on GeoIP for correctness — only completeness.

**Join buffer overflow.** When full (`--buffer-size`), evict oldest entry (LRU). Increment `modsec_exporter_join_buffer_orphans_total`. Alertable signal that traffic outpaced join window.

**TTL orphans.** Sweep emits them as `modsec_request_outcome_total{status_class="unknown"}` so rule-firing counts aren't lost. Distinguishable in PromQL — alert if `unknown` ratio exceeds 1%.

**Aggregator backpressure.** Single goroutine, two channel reads via `select`. Parsers are µs-fast. At 10k lines/s the aggregator is idle. If a parser ever becomes expensive, add small buffered channels (1k slots).

**Graceful shutdown.** SIGTERM/SIGINT: stop tailers, drain channels, run final TTL sweep (orphans counted), shut HTTP server. 5s deadline, then hard exit.

**Deliberately not handled**:
- Logs from before exporter started (tail opens at EOF; use `--replay` for backfill).
- Out-of-order lines (Apache writes monotonically; otherwise an Apache bug).
- Multi-host aggregation — one exporter per host, Prometheus aggregates upstream.

## 8. Testing strategy

TDD throughout. Three layers, each with a clear behavioral contract.

### Layer 1 — Unit tests (pure functions, table-driven)

```go
func TestParseAccess(t *testing.T) {
    cases := []struct {
        name string
        line string
        want AccessEvent
        err  bool
    }{
        {"crs-extended-with-geoip", `198.51.100.42 XX;65001;Documentation_Range_Only ...`, AccessEvent{ClientIP: "198.51.100.42", Country: "XX", ASN: "65001"}, false},
        {"missing-geoip", `192.0.2.10 -;-;- - [...]`, AccessEvent{ClientIP: "192.0.2.10", Country: ""}, false},
        {"truncated-line", `not a valid line`, AccessEvent{}, true},
        {"injection-attempt", `203.0.113.5 X;X;X - [2026-01-15 ...] "GET /\"\n[fake]\" HTTP/1.1" ...`, AccessEvent{}, false},
    }
    // ...
}
```

Same shape for `parser/error_test.go`, `join/buffer_test.go` (TTL eviction, LRU on overflow), `geoip/mmdb_test.go` (cache hit/miss, disabled fallback).

Fixtures sourced from real lines in `logs/access.log` and `logs/error.log` — copied (not symlinked) so tests don't break if logs change.

### Layer 2 — Aggregator integration (fake tailers, assert metrics)

```go
func TestJoinAttachesStatusToRules(t *testing.T) {
    agg := NewTestAggregator()  // uses real prometheus.Registry

    // Error events arrive first (real Apache ordering)
    agg.OnError(ErrorEvent{UniqueID: "abc", RuleID: "942100", Severity: "CRITICAL"})
    agg.OnError(ErrorEvent{UniqueID: "abc", RuleID: "920350", Severity: "WARNING"})

    // Access event arrives second
    agg.OnAccess(AccessEvent{UniqueID: "abc", Status: 403, Hostname: "www.example.com"})

    assertCounter(t, agg.Registry, "modsec_request_outcome_total",
        labels{"rule_id": "942100", "severity": "CRITICAL", "status_class": "4xx", "hostname": "www.example.com"}, 1)
    assertCounter(t, agg.Registry, "modsec_request_outcome_total",
        labels{"rule_id": "920350", "severity": "WARNING", "status_class": "4xx", "hostname": "www.example.com"}, 1)
    assertGauge(t, agg.Registry, "modsec_exporter_join_buffer_size", 0)  // drained
}

func TestOrphanedErrorEventsEmitAsUnknownAfterTTL(t *testing.T) { /* ... */ }
func TestBufferOverflowEvictsOldestAndCounts(t *testing.T) { /* ... */ }
func TestTopNCappedAndResetsBetweenScrapes(t *testing.T) { /* ... */ }
```

Behavior asserted via metric values (the public contract), not internal struct state.

### Layer 3 — Replay-mode smoke test

```go
// build tag: e2e
func TestReplayAgainstFixtures(t *testing.T) {
    cmd := exec.Command("./modsec-exporter", "--replay",
        "--access-log", "test/fixtures/access.log",
        "--error-log",  "test/fixtures/error.log",
        "--listen",     "127.0.0.1:0")
    // spin up, scrape /metrics, parse with prometheus expfmt, sanity-check totals

    if got := metric("http_requests_total"); got < 1000 { t.Fatalf("expected >1000 requests parsed, got %d", got) }
    if got := metric("modsec_rule_triggered_total"); got < 100 { t.Fatalf("expected rule triggers, got %d", got) }
    if parseErrs := metric(`modsec_exporter_log_lines_parsed_total{result="parse_error"}`); parseErrs > 10 {
        t.Fatalf("too many parse errors against real fixtures: %d", parseErrs)
    }
}
```

`make smoke` runs in CI. Catches regressions in parser regex, join logic, and HTTP serving in one go.

### Coverage target

- Parsers: ~100% of branches.
- Aggregator: every state transition (event-arrives-first, access-arrives-first, orphan, overflow, top-N cap).
- Tail / HTTP server: integration only.

### Tooling

- `go test ./...` — unit + integration
- `go test -tags=e2e ./...` — replay smoke
- `go vet ./...`, `staticcheck`, `golangci-lint run`
- `make test` — runs all of the above

## 9. Dependencies

Minimal. All BSD/MIT/Apache-2.0.

- `github.com/prometheus/client_golang` — Prom metrics + `promhttp`.
- `github.com/nxadm/tail` — file tailing with rotation handling.
- `github.com/oschwald/maxminddb-golang` — MMDB lookup (only if MMDB configured).
- Go stdlib otherwise.

## 10. Deployment

Single static binary (`CGO_ENABLED=0`). Deployed as a systemd unit alongside Apache:

```ini
[Service]
Type=simple
ExecStart=/usr/local/bin/modsec-exporter \
  --access-log /var/log/apache2/access.log \
  --error-log  /var/log/apache2/error.log \
  --listen     127.0.0.1:9555 \
  --mmdb       /var/lib/geoip/country.mmdb
User=modsec-exporter
Group=adm                                       # for log read access
Restart=on-failure
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
```

Container variant: distroless multi-stage Dockerfile. Mount logs read-only, MMDB read-only.

Prometheus scrape job:

```yaml
- job_name: modsec
  scrape_interval: 30s
  static_configs:
    - targets: ['apache-host-1:9555', 'apache-host-2:9555']
```

## 11. Open questions for v2 (not in scope)

- JSON audit log v2/v3 input.
- Multi-file aggregation in one process (currently one exporter per host).
- Remote-write push mode for ephemeral Apache instances.
- Optional Loki-style `/events` endpoint for per-request drill-down (we deliberately rejected this in v1; revisit if dashboards prove insufficient).
