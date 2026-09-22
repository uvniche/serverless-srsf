# ReferenceApp Operations

## Deployment gate

Export the production and candidate effective policies to JSON after resolving identity policies, resource policies, permission boundaries, and organizational controls. Run:

```bash
PYTHONPATH=src python3 scripts/srsf_gate.py production.json candidate.json --audit-out iam-audit.jsonl
```

Exit code `2` means the rollout is halted. If the expansion is intentional, rerun in the approved CI environment with `SRSF_IAM_APPROVER` set to the approver's durable identity. Ship `iam-audit.jsonl`, the rollout traffic timeline, and start/end configuration hashes to the immutable delivery stream. A changed configuration hash during the rollout requires rollback and investigation.

F4 and F5 are security-critical and use rapid full cutover with automated rollback. F1 through F3 and F6 may use a gradual rollout only after the permission gate passes. For edge-exposed F1, include gateway authorizer and route-throttle configuration in the configuration hash.

## Denial of Wallet response

The rate monitor pages after three consecutive one-minute observations above the learned mean plus four standard deviations. Its baseline does not update during those observations.

1. Compare current per-function invocation rate with the seven-day baseline for the same time of day.
2. Check F1, F2, and F3 together to determine the actual chain multiplier.
3. Separate an attack from a launch, viral event, client retry loop, or replayed object event.
4. Estimate current cost per minute using request price plus GB-second price times memory and duration.
5. If financial exposure dominates availability risk, approve a throttle on the affected function only. Do not apply an account-wide concurrency reduction.
6. Notify the incident commander and financial owner. Preserve the decision, approver, thresholds, and timestamps in the audit stream.
7. Use delayed billing data for the 30-minute, 6-hour, and 3-day burn windows. Review a persistent 1.5× increase even if no fast alert fired.

## Ephemeral incident response

Start from the evidence stream, not from the current Lambda environment.

1. Identify affected correlation IDs and environment IDs.
2. Find initialization records and every subsequent delta for each environment.
3. Treat a warm-entry manifest that differs from the prior completion heartbeat as a high-confidence `/tmp` anomaly.
4. Verify an expected heartbeat exists for every invocation. Missing evidence is itself a detection signal.
5. Record function versions, dependency sets, environment digests, touched object keys, and classification rows.
6. Escalate content hashing for functions with small or sensitive working sets after a manifest anomaly.
7. Rotate credentials and replace versions if emitter or in-memory compromise is plausible.

## Weekly permission hygiene

Export granted and exercised actions per function from IAM Access Analyzer and CloudTrail, annotate deliberately dormant disaster-recovery permissions, and run:

```bash
PYTHONPATH=src python3 scripts/permission_footprint.py permission-usage.json
```

The total must be flat or decrease week over week. Every increase requires a named owner and remediation ticket. Scores are attention signals, not measures of reachable impact.

## Postmortem evidence template

- Incident window, customer impact, and operator-only financial impact
- Functions and immutable function versions involved
- Correlation IDs and environment IDs
- Initialization record and runtime dependency set per environment
- Warm-entry `/tmp` deltas and corresponding completion heartbeats
- Missing-heartbeat intervals
- Objects, rows, queues, and external endpoints touched
- Effective permissions and short-lived role sessions in force
- Rollout traffic timeline and start/end configuration hashes
- Invocation-rate baseline, anomaly threshold, cost burn windows, and chain multiplier
- Telemetry destinations consulted and any resolution or retention gaps
- Residual uncertainties, evidence that never existed, and explicitly scoped corrective actions

