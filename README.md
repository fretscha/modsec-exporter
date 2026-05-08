# modsec-exporter

[![CI](https://github.com/fretscha/modsec-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/fretscha/modsec-exporter/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/fretscha/modsec-exporter.svg)](https://pkg.go.dev/github.com/fretscha/modsec-exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/fretscha/modsec-exporter)](https://goreportcard.com/report/github.com/fretscha/modsec-exporter)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Prometheus exporter that tails Apache access logs and ModSecurity / OWASP CRS 4.x error logs and exposes:

- **Service RED metrics** — request rate, error rate, latency, response size, country breakdown.
- **WAF metrics** — rule trigger counts, severity / paranoia-level / attack-category breakdowns, anomaly score histograms.
- **A targeted "blocked vs. passed" join** keyed by Apache `unique_id`: for every rule fired, what HTTP status class did the request return?
- **Top-N attackers** — bounded gauge of the most active attacker IPs, with country / ASN.

For deeper investigation (per-IP / per-URI / per-rule-message drill-down), pair this exporter with a separate batch log-analysis tool of your choice — modsec-exporter deliberately keeps high-cardinality dimensions out of Prometheus to bound time-series count.

## Quickstart

**Option 1 — pre-built binary** (Linux amd64/arm64, statically linked):

```bash
# replace linux-amd64 with linux-arm64 if needed
curl -Lo modsec-exporter \
  https://github.com/fretscha/modsec-exporter/releases/latest/download/modsec-exporter-linux-amd64
chmod +x modsec-exporter
./modsec-exporter \
  --access-log /var/log/apache2/access.log \
  --error-log  /var/log/apache2/error.log \
  --listen     :9555
```

Verify with the bundled `checksums.txt` from the [release page](https://github.com/fretscha/modsec-exporter/releases/latest).

**Option 2 — go install**:

```bash
go install github.com/fretscha/modsec-exporter/cmd/modsec-exporter@latest
modsec-exporter \
  --access-log /var/log/apache2/access.log \
  --error-log  /var/log/apache2/error.log \
  --listen     :9555
```

**Option 3 — build from source**:

```bash
git clone https://github.com/fretscha/modsec-exporter.git
cd modsec-exporter
make build
./bin/modsec-exporter \
  --access-log /var/log/apache2/access.log \
  --error-log  /var/log/apache2/error.log \
  --listen     :9555
```

## Configuration

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--config` | — | — | path to TOML config file; mutually exclusive with `--access-log`/`--error-log` |
| `--access-log` | `MODSEC_EXPORTER_ACCESS_LOG` | — | single-site mode; required if `--config` not given |
| `--error-log` | `MODSEC_EXPORTER_ERROR_LOG` | — | single-site mode; required if `--config` not given |
| `--listen` | `MODSEC_EXPORTER_LISTEN` | `:9555` | |
| `--mmdb` | `MODSEC_EXPORTER_MMDB` | `""` | empty disables GeoIP fallback |
| `--top-n` | — | `50` | per site; `0` disables |
| `--buffer-size` | — | `50000` | join buffer cap per site |
| `--buffer-ttl` | — | `60s` | orphan threshold |
| `--sweep-interval` | — | `10s` | TTL sweep cadence |
| `--replay` | — | `false` | one-shot file read; metrics endpoint stays up until SIGINT/SIGTERM |

## Multi-site configuration

To monitor multiple Apache sites with one process, create a TOML config file:

```toml
[[site]]
name       = "shop"
access_log = "/var/log/apache2/shop-access.log"
error_log  = "/var/log/apache2/shop-error.log"

[[site]]
name       = "blog"
access_log = "/var/log/apache2/blog-access.log"
error_log  = "/var/log/apache2/blog-error.log"
```

Then start the exporter with `--config`:

```bash
modsec-exporter --config /etc/modsec-exporter/sites.toml --listen :9555
```

All Prometheus metrics carry a `site` label (e.g. `site="shop"`). Each site gets its own join buffer and Top-N tracker; GeoIP and the HTTP endpoint are shared.

## Headline PromQL

Fraction of times a CRS rule actually blocked the request (vs. just warned in DetectionOnly mode):

```promql
sum by(rule_id)(rate(modsec_request_outcome_total{status_class="4xx"}[5m]))
  / sum by(rule_id)(rate(modsec_request_outcome_total[5m]))
```

Top attacking countries by 4xx rate:

```promql
topk(10, sum by(country)(rate(http_requests_by_country_total{status_class="4xx"}[15m])))
```

False-positive-suspect rules — high firing rate, low block ratio:

```promql
(
  sum by(rule_id)(rate(modsec_rule_triggered_total[15m]))
) > 1
and on(rule_id)
(
  sum by(rule_id)(rate(modsec_request_outcome_total{status_class="4xx"}[15m]))
    / sum by(rule_id)(rate(modsec_request_outcome_total[15m]))
) < 0.1
```

## Cardinality

Worst case ~18k series for a single Apache with 5 vhosts and full CRS 4.x. See [the design doc](docs/design/2026-04-29-modsec-prom-exporter-design.md#cardinality-budget) for the breakdown.

`client_ip`, `uri`, `user_agent`, and `msg` are deliberately not exposed as labels (except `client_ip` inside the bounded Top-N gauge). For per-IP / per-URI investigation, pair this exporter with a batch log-analysis tool that can handle unbounded cardinality.

## Development

```bash
make test     # unit + integration
make smoke    # e2e replay smoke against test/fixtures
make lint
```

Smoke fixtures are gitignored. Generate them with the bundled `loggen` tool:

```bash
go run ./cmd/loggen \
  --count 5000 \
  --access-out test/fixtures/access.log \
  --error-out  test/fixtures/error.log
```

## Container

```bash
docker build -t modsec-exporter:dev -f docker/Dockerfile .
docker run --rm -v /var/log/apache2:/logs:ro -p 9555:9555 modsec-exporter:dev \
  --access-log /logs/access.log --error-log /logs/error.log
```

## Systemd

A hardened unit is provided at `deploy/modsec-exporter.service`. To install:

```bash
sudo cp bin/modsec-exporter /usr/local/bin/
sudo useradd -r -s /usr/sbin/nologin modsec-exporter
sudo usermod -aG adm modsec-exporter        # for log read access
sudo cp deploy/modsec-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now modsec-exporter
```

## Prometheus scrape

```yaml
- job_name: modsec
  scrape_interval: 30s
  static_configs:
    - targets: ['apache-host-1:9555']
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
