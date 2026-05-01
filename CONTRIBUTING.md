# Contributing to modsec-exporter

Thanks for your interest in improving modsec-exporter. This guide covers the practical bits.

## Development setup

Requirements: Go 1.22+ (build), `make` (convenience targets), `git`.

```bash
git clone https://github.com/fretscha/modsec-exporter.git
cd modsec-exporter
make test
```

## Tests

Three layers, all run via `go test`:

- **Unit / integration** — `make test` (covers parsers, join buffer, geoip, metrics, aggregator, tail, server). Runs in seconds.
- **End-to-end smoke** — `make smoke`. Requires fixtures under `test/fixtures/`. The fixtures are gitignored; generate synthetic ones with the bundled tool:

  ```bash
  go run ./cmd/loggen --count 5000 \
      --access-out test/fixtures/access.log \
      --error-out  test/fixtures/error.log
  make smoke
  ```

  CI uses 5 000 requests; locally you may scale up to 100 000 for soak-style testing.

- **Lint** — `make lint` runs `go vet`. CI additionally runs `golangci-lint` per `.golangci.yml`.

A change is considered ready when `make test && make lint && make smoke` are all green and the diff is reviewed.

## Code style

- Standard `gofmt` / `goimports` — CI enforces.
- Pure functions where possible (parsers, helpers).
- Tests are table-driven where it fits the case.
- Comments explain *why*, not *what* — names should already say what.

## Pull requests

- Open a draft PR early if the change is non-trivial; it's easier to course-correct on the design before code review.
- One PR per logical change. Refactors that touch many files are fine, but keep them separate from feature work.
- Reference any related issue with `Fixes #N` in the PR description.
- Include a "Test plan" section in the description: what you ran, what you observed.

## Commit messages

Conventional Commits style:

```
feat(parser): add JSON audit log v3 support
fix(geoip): handle IPv6 entries in MMDB
docs: clarify --buffer-ttl semantics
chore: bump prometheus client_golang to v1.x
```

Multi-line bodies are welcome for non-trivial changes — explain the *why* and any context that won't be obvious from the diff alone.

## Reporting bugs / requesting features

Use the templates under `.github/ISSUE_TEMPLATE/`. Include:

- Apache version, ModSecurity version, OWASP CRS version
- modsec-exporter version (output of `modsec-exporter --version` once that lands, or commit SHA otherwise)
- A sanitized log sample that reproduces the issue (RFC 5737 IPs / `example.com` hostnames are appreciated)

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
