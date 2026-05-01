# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** via one of:

1. **GitHub Security Advisories** — https://github.com/fretscha/modsec-exporter/security/advisories/new (preferred)
2. **Email** — Open a draft PR or issue requesting a private contact channel; do not include sensitive details until a private channel is established.

Please do **not** open a public GitHub issue for security reports.

## What to include

- Affected version (commit SHA or tag).
- Steps to reproduce, ideally with a sanitized log sample (RFC 5737 IPs, `example.com` hostnames).
- Impact assessment — what an attacker could do with the issue.
- Any suggested mitigation.

## What to expect

- **Acknowledgement** within 7 calendar days.
- A maintainer will work with you to confirm the issue, assess severity (CVSS-style), and agree on a disclosure timeline. Default coordinated-disclosure window is **90 days** from confirmation, shortened if the issue is actively exploited or if a fix is already public.
- Public disclosure happens after a fix is released. Reporters are credited (with permission) in the release notes.

## Scope

In scope:

- The `modsec-exporter` binary (`cmd/modsec-exporter`).
- The `loggen` development tool (`cmd/loggen`).
- Library packages under `internal/`.

Out of scope (report directly to upstream):

- Apache HTTPD, ModSecurity, or OWASP CRS rules themselves.
- Third-party dependencies — those go to their own maintainers (we'll coordinate if it surfaces here first).
- Issues that require root on the host running the exporter.

## Defensive design notes

- The exporter reads logs read-only. It never modifies the files it tails.
- The HTTP server exposes only `/metrics`, `/healthz`, `/readyz` — no admin endpoints, no inputs that affect parsing.
- Cardinality is bounded by design. A flood of unique attacker IPs is contained by the Top-N gauge cap and the join buffer's LRU eviction.
- Parser errors increment a counter and drop the line — there is no path from log content to crash. If you find one, that's the kind of issue this policy is designed to surface.
