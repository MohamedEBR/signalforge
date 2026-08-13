# Threat model

## Scope and assets

The current trust boundary is a single local/CI process evaluating repository
rules and JSONL telemetry. Assets are detection integrity, normalized evidence,
rule provenance, analyst decisions, availability, and the confidentiality of
future real-world telemetry.

## Adversaries

- An attacker who can insert malformed or adversarial telemetry.
- A compromised contributor attempting to hide a detection or add unsafe rule
  behavior.
- An operator who mistakes a response suggestion for an approved action.
- A dependency or CI compromise that modifies release output.

## Threats and controls

| Threat | Current control | Residual risk / production requirement |
|---|---|---|
| YAML object construction or code execution | `yaml.safe_load`; no `eval`, templates, imports, or commands in rule semantics | Sign rule commits and require protected review |
| Catastrophic regular expression | 256-character limit; nested quantifiers, backreferences, and lookaround rejected | Prefer RE2 and per-rule execution budgets |
| Memory exhaustion from telemetry | 2 MB line limit, 100k records per file, max 16 scenario inputs | Stream ingestion and enforce tenant quotas |
| Unbounded state/window | Maximum seven-day rule window and twelve sequence stages | Watermarks, eviction, and durable state limits |
| Ambiguous correlation | Typed entities, explicit group fields, missing values fail closed, evidence timeline retained | Add entity provenance and tenant isolation |
| Automatic harmful containment | Model only accepts `pending_approval` and `executable: false` | Put approved execution in a separate service with RBAC and dual control |
| Rule tampering | Rules, scenarios, schemas, tests, replay reports, and CodeQL live in version control | Signed commits/releases and branch protection |
| Dependency compromise | Locked dependency graph, `pip-audit`, Dependabot, minimal runtime image | Pin container digests and generate/sign SBOMs |
| Cross-tenant data exposure | No tenancy or external ingestion in the lab | Mandatory tenant partition keys and authorization |
| Sensitive raw-data leakage | Synthetic fixtures; findings reference IDs and selected evidence | Redaction, access controls, retention policy, encryption |

## Trust assumptions

The local filesystem, Python interpreter, and CI runner are trusted. Raw input
is not trusted. Repository contributors are partially trusted and should be
reviewed. No network service, credential store, cloud API, or response executor
is present.

## Out of scope

SignalForge does not claim production availability, regulated-data handling,
multi-tenant isolation, exactly-once stream processing, or autonomous
containment. Those are explicit future boundaries rather than hidden claims.
