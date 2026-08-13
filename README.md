# SignalForge

SignalForge is a local-first detection-as-code lab for cloud, identity, and
network telemetry. It normalizes heterogeneous security events, evaluates
declarative rules, correlates related findings into explainable incidents, and
replays labeled attack and benign scenarios in CI.

The project is designed to demonstrate the engineering work behind a modern
detection platform—not just a collection of queries:

- typed, OCSF-inspired normalization for AWS CloudTrail, Microsoft Entra,
  SentinelFlow NIDS, Aegis audit records, and application authentication logs;
- safe YAML rules for event matches, thresholds, and ordered sequences;
- deterministic, evidence-rich findings with MITRE ATT&CK mappings;
- graph-style incident correlation across identities, IPs, and resources;
- human-in-the-loop response plans that are deliberately non-executable;
- labeled replay scenarios with precision, recall, and latency evidence.

Everything runs locally with synthetic data. No cloud account, API key, paid
service, or external security product is required.

## Quick start

Prerequisites: Python 3.11–3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run signalforge validate-rules rules
uv run signalforge replay scenarios
uv run pytest
```

The replay command writes a machine-readable report to `reports/replay.json`
and a recruiter-friendly summary to `reports/replay.md`. It exits non-zero if
an expected rule is missing or a forbidden rule fires.

## What the demo detects

| Scenario | Signal | Detection behavior |
|---|---|---|
| AWS persistence | Access key creation followed by role assumption | Sequence, grouped by cloud principal |
| Entra identity abuse | Conditional Access failure burst | Threshold, grouped by user and source IP |
| Entra privilege escalation | Failed sign-in, success, then role membership change | Three-stage sequence |
| Network-to-identity attack | High-confidence SentinelFlow alert followed by API auth failures | Cross-source correlation by IP |
| Aegis credential abuse | Workload revocation followed by denied token exchange | Cross-project workload sequence |
| Expected automation | Terraform-style key and role activity | Suppressed by an explicit, testable exclusion |

All addresses, account numbers, identities, and credentials in the scenarios
are synthetic or reserved for documentation.

## Pipeline

```text
raw JSONL -> source adapter -> typed SecurityEvent -> rule engine -> Finding
                                                               |
                                                               v
                                                   entity correlation
                                                               |
                                                               v
                                            Incident + pending response plan

labeled scenarios ---------------------------------------> replay metrics
```

SignalForge does not call `eval`, run shell commands, or execute response
actions. YAML is parsed with the safe loader, rules are schema validated,
windows and inputs are bounded, and a missing correlation field fails closed.
See [the threat model](docs/threat-model.md) and
[rule-authoring guide](docs/rule-authoring.md) for the security boundaries.

## Commands

```bash
# Validate every rule contract
uv run signalforge validate-rules rules

# Convert raw source records into the canonical event schema
uv run signalforge normalize raw.jsonl --output normalized.jsonl

# Evaluate rules against already-normalized events
uv run signalforge detect normalized.jsonl --rules rules --output findings.json

# Replay every labeled scenario and generate reports
uv run signalforge replay scenarios --rules rules \
  --json reports/replay.json --markdown reports/replay.md
```

## Repository map

```text
src/signalforge/   normalizers, validation, engine, correlation, CLI
rules/             version-controlled detection contracts
scenarios/         attack and benign JSONL fixtures plus expectations
tests/             unit, integration, security-boundary, and CLI tests
docs/              architecture, threat model, rule guide, and runbook
reports/           checked-in replay evidence
```

## Security and scope

SignalForge is a portfolio-grade laboratory, not a production SIEM or SOAR.
Production adoption would require durable state, authenticated ingestion,
tenant isolation, signed rule releases, operational telemetry, and formal
response integrations. The current response objects remain
`pending_approval` and `executable: false` by model invariant.

## License

Apache-2.0. See [LICENSE](LICENSE).
