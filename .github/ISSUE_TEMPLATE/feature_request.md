---
name: Feature request
about: Suggest a new metric, label, parser format, or behaviour
title: '[FEATURE] '
labels: enhancement
---

### Use case

What problem are you trying to solve? Describe the operational scenario —
e.g. "I want to alert on per-rule false-positive rate" or "we run nginx not
Apache and need a different log format."

### Proposed change

What would you like the exporter to do? Be concrete: a new metric name,
a new flag, a new log format, a new label.

### Alternatives considered

What else have you tried, or what else could solve this?

### Cardinality / performance impact (if relevant)

If your proposal adds metrics or labels, estimate the worst-case time-series
count it could add. The design doc has a cardinality budget — see
[docs/design/2026-04-29-modsec-prom-exporter-design.md](../../docs/design/2026-04-29-modsec-prom-exporter-design.md#cardinality-budget).
