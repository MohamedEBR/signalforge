# SignalForge replay report

Generated: 2026-08-13T22:58:37.013809+00:00

| Metric | Result |
|---|---:|
| Scenarios | 5 |
| Passed | 5 |
| Failed | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| Median engine time | 0.092 ms |

## Scenarios

| Scenario | Events | Findings | Incidents | Rules | Result |
|---|---:|---:|---:|---|---|
| Aegis workload use after revocation | 2 | 1 | 1 | SF-AEGIS-REVOKED-USE | PASS |
| AWS access key then cross-role activity | 2 | 1 | 1 | SF-AWS-ACCESS-KEY-ROLE-CHAIN | PASS |
| Expected automation and normal sign-in | 3 | 0 | 0 | none | PASS |
| Entra failures followed by role escalation | 5 | 2 | 1 | SF-ENTRA-CA-FAILURE-BURST, SF-ENTRA-PRIVILEGE-SEQUENCE | PASS |
| SentinelFlow intrusion plus API abuse | 3 | 2 | 1 | SF-NETWORK-AUTH-CORRELATION, SF-SENTINELFLOW-CRITICAL | PASS |

## Incident explanations

### Aegis workload use after revocation: INC-8EA2C6B80067A1F5C651

SignalForge correlated 1 finding(s) from 1 source(s) around workload:spiffe://aegis.local/ns/payments/sa/worker, resource:spiffe://aegis.local/ns/payments/sa/worker, resource:ledger-api. The evidence spans 2 ordered event(s); proposed actions remain non-executable pending explicit human approval.

- Severity: critical
- Confidence: 0.68
- Rules: SF-AEGIS-REVOKED-USE
- ATT&CK: T1550.001, T1078
- Response: rotate_workload_certificate(spiffe://aegis.local/ns/payments/sa/worker) — pending approval

### AWS access key then cross-role activity: INC-7218F029216C16E2D69C

SignalForge correlated 1 finding(s) from 1 source(s) around cloud_principal:arn:aws:iam::111122223333:user/alice, aws_account:111122223333, aws_account:444455556666. The evidence spans 2 ordered event(s); proposed actions remain non-executable pending explicit human approval.

- Severity: high
- Confidence: 0.68
- Rules: SF-AWS-ACCESS-KEY-ROLE-CHAIN
- ATT&CK: T1098, T1078.004
- Response: deactivate_access_key(AKIASYNTHETIC0001) — pending approval

### Entra failures followed by role escalation: INC-0158243E87EFEBCC4E42

SignalForge correlated 2 finding(s) from 1 source(s) around user:alice@example.test, entra_resource:Azure Portal, entra_resource:Global Administrator. The evidence spans 5 ordered event(s); proposed actions remain non-executable pending explicit human approval.

- Severity: critical
- Confidence: 0.76
- Rules: SF-ENTRA-CA-FAILURE-BURST, SF-ENTRA-PRIVILEGE-SEQUENCE
- ATT&CK: T1110, T1078, T1098.003
- Response: revoke_user_sessions(alice@example.test) — pending approval; remove_role_assignment(Global Administrator) — pending approval

### SentinelFlow intrusion plus API abuse: INC-5748C20FFACA4A4BF1F9

SignalForge correlated 2 finding(s) from 2 source(s) around network_endpoint:10.10.0.20, api_principal:unknown-api-key, api:payments-api. The evidence spans 3 ordered event(s); proposed actions remain non-executable pending explicit human approval.

- Severity: critical
- Confidence: 0.81
- Rules: SF-NETWORK-AUTH-CORRELATION, SF-SENTINELFLOW-CRITICAL
- ATT&CK: T1595, T1110
- Response: block_source_ip(198.51.100.88) — pending approval; isolate_source(198.51.100.88) — pending approval
