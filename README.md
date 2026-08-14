# SignalForge

[![CI](https://github.com/MohamedEBR/signalforge/actions/workflows/ci.yml/badge.svg)](https://github.com/MohamedEBR/signalforge/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MohamedEBR/signalforge/actions/workflows/codeql.yml/badge.svg)](https://github.com/MohamedEBR/signalforge/actions/workflows/codeql.yml)

SignalForge turns cloud, identity, and network logs into explainable security
incidents. Detection rules are stored as code and tested against repeatable
attack and benign scenarios before they can be trusted.

The project connects my [SentinelFlow network detector](https://github.com/MohamedEBR/network_intrusion_detection)
with AWS, Microsoft Entra, workload identity, and application authentication
events to show how separate security signals become one investigation timeline.

## What I built

- **Five telemetry adapters:** AWS CloudTrail, Microsoft Entra, SentinelFlow,
  Aegis audit events, and application authentication logs.
- **Detection-as-code:** versioned YAML rules for single events, thresholds, and
  ordered sequences.
- **Cross-source correlation:** findings are joined through identities, IPs, and
  resources into evidence-backed incidents.
- **Repeatable validation:** labeled attack and benign scenarios run locally and
  in CI, measuring expected and unexpected detections.
- **Safe response planning:** suggested containment actions require human
  approval and cannot be executed by SignalForge.

## Results

| Evidence | Result |
|---|---:|
| Telemetry sources | 5 |
| Versioned detection rules | 6 |
| Attack and benign replay scenarios | 5 |
| Automated tests | 50 |
| Statement coverage | 94.87% |
| Precision / recall on the included labeled corpus | 1.000 / 1.000 |
| False positives / false negatives on that corpus | 0 / 0 |
| Median throughput over 25,000 events and six rules | 126,158 events/s |

GitHub Actions validates formatting, rules, tests, replay expectations, generated
schemas, dependencies, packages, and the production container. CodeQL runs on
every change. See the checked-in [replay report](reports/replay.md) and
[benchmark](reports/benchmark.json) for the underlying evidence.

## How it works

```text
CloudTrail ─┐
Entra ──────┤
SentinelFlow├──▶ normalized events ──▶ detection rules ──▶ findings
Aegis ──────┤                                                │
App auth ───┘                                                ▼
                                            correlated incident timeline
                                                        +
                                           pending response recommendations

labeled scenarios ──▶ replay engine ──▶ precision, recall, and latency
```

## Detection scenarios

| Scenario | What SignalForge looks for |
|---|---|
| AWS persistence | A new access key followed by role assumption |
| Entra credential abuse | Repeated Conditional Access failures |
| Entra privilege escalation | Failed sign-in, success, then privileged role change |
| Network-to-identity attack | SentinelFlow intrusion followed by API authentication failures from the same IP |
| Revoked workload activity | A workload attempts token exchange after revocation |
| Expected automation | Terraform-style activity that must remain suppressed |

Each malicious scenario declares which rules must fire. The benign scenario
declares which rules must stay quiet. CI fails when either expectation changes.

## Try it

Requires Python 3.11–3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run signalforge validate-rules rules
uv run signalforge replay scenarios
uv run pytest
```

The replay produces a JSON report for automation and a Markdown report with
incident explanations, evidence, ATT&CK mappings, and proposed next steps.

Other useful commands:

```bash
# Normalize raw JSONL from any supported source
uv run signalforge normalize raw.jsonl --output normalized.jsonl

# Evaluate normalized events and produce findings/incidents
uv run signalforge detect normalized.jsonl --rules rules --output findings.json

# Reproduce the throughput measurement
uv run python scripts/benchmark.py --output reports/benchmark.json
```

## Design choices

- Rules are parsed with a safe YAML loader and cannot execute code.
- Inputs, rule windows, sequence stages, and regular expressions are bounded.
- Missing identity or correlation fields fail closed.
- Events and evidence are deterministically ordered with content-derived IDs.
- Response objects only permit `pending_approval` and `executable: false`.
- Every rule includes ATT&CK mappings, known false positives, and a triage runbook.

Read the [architecture](docs/architecture.md),
[threat model](docs/threat-model.md),
[rule-authoring guide](docs/rule-authoring.md), and
[analyst runbook](docs/triage-runbook.md) for the deeper design.

## Repository guide

```text
src/signalforge   normalization, detection, correlation, replay, and CLI
rules             versioned detection rules
scenarios         labeled attack and benign event fixtures
tests             unit, integration, security-boundary, and CLI tests
schemas           generated event, finding, incident, and replay contracts
reports           replay and benchmark evidence
```

SignalForge is a batch detection and replay engine. A production deployment
would add authenticated streaming ingestion, durable state, tenant isolation,
and a separately authorized response service.

## License

Apache-2.0. See [LICENSE](LICENSE).
