# Architecture

SignalForge separates ingestion, detection, correlation, and response planning
so each security boundary can be reviewed and tested independently.

## Components

1. **Source adapters** accept dictionaries produced from bounded JSONL and map
   known vendor fields into `SecurityEvent`. Unknown input fields never become
   executable behavior.
2. **Canonical events** use a strict Pydantic envelope with UTC timestamps,
   validated IPs and ports, typed entities, a finite outcome/severity set, and
   a small observables map.
3. **Rule loading** uses `yaml.safe_load`, Pydantic contracts, semantic checks,
   file-size limits, duration limits, field-path validation, and restrictions
   on expensive regular-expression features.
4. **Detection** implements match, threshold, and sequence primitives. Events
   are deterministically ordered; threshold windows are consumed after firing;
   sequence matches are non-overlapping; missing group keys fail closed.
5. **Correlation** uses a union-find graph. Findings become adjacent when they
   share a typed entity within the correlation window. Connected components
   become incidents with a source timeline and an explicit explanation.
6. **Response planning** resolves suggested targets from evidence, but the data
   model permits only `pending_approval` and literally forbids
   `executable: true`.
7. **Replay** runs labeled attack and benign fixtures and measures expected,
   forbidden, and missing rule firings. A failed expectation produces a
   non-zero CLI exit for CI enforcement.

## Data contracts

Checked-in JSON Schemas under `schemas/` document the event, finding, incident,
and replay contracts. Stable content-derived finding and incident IDs make
results traceable across repeated runs; runtime timestamps are evidence of the
specific evaluation.

## Determinism

Event order is `(event.time, event.id)`, rules are ordered by ID, evidence uses
matched event order, and identifiers hash the rule ID plus matched evidence.
Only `detected_at`, report generation time, and latency measurements vary by
run.

## Complexity

- Match and threshold evaluation are linear after event sorting.
- Sequence evaluation is linear for groups that do not match the first stage;
  a worst-case group with many partial starts can approach quadratic work.
- Correlation is pairwise within each entity bucket, with path compression for
  connected-component construction.

The input/window bounds reduce denial-of-service exposure in this lab. A
production implementation would replace batch lists and worst-case pair scans
with partitioned state stores, watermarks, indexed timelines, and per-tenant
budgets.

## Production extension points

Adapters can be placed behind authenticated queue consumers; rule releases can
be signed and promoted through environments; findings can be persisted to an
append-only store; entity edges can move to a durable graph/state backend; and
approved response plans can be handed to a separately authenticated SOAR
executor. That executor is intentionally outside this repository's trust
boundary.
