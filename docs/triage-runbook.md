# Analyst triage runbook

## 1. Establish evidence integrity

Record the incident ID, rule IDs and versions, source event IDs, evaluation
time, and replay/deployment version. Confirm all timestamps are UTC. For Aegis,
verify the audit hash chain before relying on the event sequence.

## 2. Validate the analytic

Review each rule's source requirements, matched fields, window, grouping, and
documented false positives. For SentinelFlow signals, require acceptable model
version and feature coverage. For identity actions, establish the human or
workload owner and compare the change with an approved request.

## 3. Scope the incident

Pivot on every typed entity in the incident: principal, workload, source IP,
target resource, cloud account, API, and certificate/key identifier. Search
before and after the incident window for successes, privilege changes, lateral
movement, persistence, and data access.

## 4. Decide containment

SignalForge response plans are suggestions only. An analyst must confirm the
target, document supporting evidence, assess business impact, and obtain the
required approval in the system of record. Execute containment through an
authorized operational platform—not through SignalForge.

## 5. Close the loop

Preserve evidence, record the disposition and root cause, add a sanitized
regression fixture, tune the rule if necessary, increment its version, and run
the complete replay suite. A false positive is not closed until its explanation
is reflected in tests or rule documentation.
