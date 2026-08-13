# Rule authoring

Rules are declarative YAML contracts under `rules/`. A contribution is complete
only when its malicious scenario fires, its benign scenario stays quiet, and
the replay suite remains green.

## Required metadata

Every rule declares a stable `SF-*` ID, integer version, author, status,
description, severity, telemetry sources, ATT&CK tactics/techniques, known false
positives, investigation runbook, and optional approval-gated response plans.

## Detection primitives

- `match`: one event satisfies the matcher.
- `threshold`: at least `threshold` matching events share every `group_by`
  field inside `window`.
- `sequence`: ordered stages share every `group_by` field and complete inside
  `window`.

A matcher can constrain `sources`, `activities`, `outcomes`, `all` predicates,
and `none` predicates. Predicates support `eq`, `ne`, `in`, `not_in`, `exists`,
`contains`, restricted `regex`, `cidr`, `gte`, and `lte`.

## Example

```yaml
id: SF-EXAMPLE-AUTH-BURST
version: 1
name: Example authentication failure burst
author: Mohamed Ebraheem
description: Detects repeated failures for one identity and source.
type: threshold
severity: medium
status: test
required_sources: [application.auth]
tactics: [CredentialAccess]
techniques: [T1110]
false_positives:
  - A developer uses an expired local credential.
group_by: [actor.id, source_endpoint.ip]
window: 5m
threshold: 3
match:
  sources: [application.auth]
  activities: [ApiAuthentication]
  outcomes: [failure]
runbook:
  - Confirm credential ownership and review neighboring successes.
responses:
  - action: revoke_api_key
    target_field: actor.id
    description: Revoke only after an analyst confirms compromise.
    approval_required: true
```

## Validation and tuning

```bash
uv run signalforge validate-rules rules
uv run signalforge replay scenarios
uv run pytest
```

Use narrow group keys, the smallest defensible window, explicit source filters,
and concrete false-positive documentation. Add `none` exclusions only when they
represent an explainable, testable business condition. Never encode a secret in
a rule or fixture.

Increment `version` when behavior, thresholds, grouping, severity, or response
guidance changes. Keep the ID stable unless the analytic meaning changes.
