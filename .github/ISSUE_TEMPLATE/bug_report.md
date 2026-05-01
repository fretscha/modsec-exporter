---
name: Bug report
about: Something isn't behaving the way the docs say it should
title: '[BUG] '
labels: bug
---

### Environment

- modsec-exporter version (commit SHA or tag):
- Apache version (`apachectl -v`):
- ModSecurity version (`apachectl -M | grep security`):
- OWASP CRS version (path or `git -C /etc/apache2/crs describe --tags`):
- OS / distribution:
- Go version (only if you built from source):

### What you did

A short description of the operation, plus the exact `modsec-exporter` flags
you ran with (or the relevant snippet of your systemd unit / Dockerfile).

### What you expected

What `--metrics` output / log message / behaviour did you anticipate?

### What actually happened

What did you observe? Paste a sanitized log sample if relevant — please replace
real IPs with RFC 5737 ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and
real hostnames with `example.com`.

### Anything else?

Reproduction steps, screenshots of dashboards, related issues, etc.
