# ReferenceApp operations

Project report reference: Modules 1-5 and Section 10. The module owner roles and interfaces are in [project-controls.md](project-controls.md); verification and operational acceptance are tracked in [evaluation.md](evaluation.md) and [handover.md](handover.md).

## Deployment authorization

Export complete production/candidate snapshots with `scope`, `principal`, and lists for `identity`, `resource`, `boundaries`, `session`, and `organization`. Empty lists explicitly declare absence; omitted inputs do not. Include representative allowed requests and negative targets in a shared JSON catalogue. The supported scope and unresolved cases are documented in the README.

```bash
PYTHONPATH=src python3 scripts/srsf_gate.py production.json candidate.json --catalogue requests.json --config-start start.json --config-end end.json --audit-out iam-audit.jsonl
```

Exit 2 halts automatic progression for expansions, unresolved coverage or security-configuration drift. A named authenticated reviewer may authorize a reviewed exception through protected `SRSF_IAM_APPROVER`; typing a name is not authentication. Preserve the decision matrix, complete policy snapshots, evaluator version, review reason, traffic-weight timeline and configuration hashes in the immutable audit destination. Local JSONL is staging, not durable acknowledgement. The example CI job tests fixture inputs; it does not discover live effective policies or enforce a production rollout.

Classify mixed-version tolerance per function. F4/F5 and the broker use rapid cutover in this template. Verify that the rollback target meets current security requirements before enabling automatic rollback: restoration of a revoked capability is unsafe. Other functions may use gradual deployment with availability checks and the bounded gate at the boundary. Include gateway authorizers and route throttles for exposed routes, asynchronous retries and direct version/alias invocation in the reachability review. The template does not enforce security suitability of rollback targets.

## Economic response

The acute detector uses distinct timestamped one-minute buckets, three confirmations and four standard deviations with a minimum noise floor of one invocation per minute. Learning freezes during suspected anomalies. Parameters are tunable, not validated detection guarantees. Missing metrics are evidence gaps; ingestion delay contributes to alert delay. Reset old per-minute rate state when upgrading.

1. Compare each function with independently calibrated demand patterns, including seasonality, legitimate bursts and retries.
2. Inspect F1-F6 and downstream storage, queue, inference and egress costs. Follow actual fan-out rather than assuming chain depth is a cost multiplier.
3. Separate total spend from excess above baseline. Keep the total monthly cap and excess allowance denominators distinct.
4. Supply observed/expected spend for both windows of each paired threshold to `scripts/spending_report.py`. Zero expected spend produces unexpected-activity findings, not a finite ratio. Obtain these windows from billing/usage data; the prototype does not collect them.
5. Page or ticket according to the paired window. Throttling remains a human decision accounting for rejected legitimate work and shared dependencies. Preserve approver, target, cost estimate and decision in retained audit evidence.

## Ephemeral incident response

Start with retained audit objects and durable receipts, then correlate application and provider records.

1. Identify functions, versions, environment IDs, invocation IDs and sequence numbers.
2. Read initialization evidence, runtime dependencies and declared bootstrap comparisons.
3. Compare each warm entry with its prior acknowledged exit from the same environment. An unexplained difference is a triage signal, not proof of compromise.
4. Treat missing entries, exits or sequences separately as evidence gaps. Reconcile against independent invocation counts over the same window using `scripts/reconcile_evidence.py`.
5. Inspect F2 CloudWatch error alarms on audit-path failure. An exit failure can follow completed application side effects; retries may duplicate downstream work. Logs with `ssrsf_evidence_gap` supply an independent diagnostic path.
6. Record touched object versions, rows and endpoints. Consider content hashing for sensitive working sets. Assess emitter tampering, in-memory compromise and background writers explicitly.

Continuous reconciliation and dedicated missing-record alarms need an operator-owned consumer; the script supplies a local reconciliation check. The absence of a record is not proof that no operation happened.

## Purge failure and reconciliation

Approval is granted by the separately authenticated `purge-approvers` route. Review exact object versions and the row, then submit the grant via F4. Do not expose grants in logs. F4/F5 assertions cannot replace the signed, service-owned approval record. An unavailable approval record or atomic nonce store blocks execution before STS acquisition.

The broker records an authorized decision before execution and atomically consumes the nonce. It updates the operations table after each target and writes retained outcomes with the scoped session identity. A replay is rejected, including after failure. A partial operation or unknown result requires inspection of actual target versions and the row before renewed approval. Never reuse a consumed grant. Abrupt termination can leave status `consumed` or `partial`; those records require reconciliation. Failure of both audit and operation recording can leave unknown outcomes. Grant expiry does not revoke an already issued 15-minute STS session.

## Weekly permission review

Review weighted unused grants with latency, availability and financial signals. Use thirty days only as an illustrative window; F6 or recovery paths may need longer. Annotate rarely exercised requirements. Every increase needs an owner and justification; remove permissions only after contextual review. The weights 1/3/10 are attention proxies, not validated risk scores.

## Postmortem evidence

Record impact including operator-only financial harm; immutable versions; environment/invocation/correlation IDs; sequences and retention receipts; bootstrap and warm-entry comparisons; missing evidence; dependencies and targets; approval/grant IDs and broker session/outcomes; policy snapshots and unresolved cases; rollout reachability and safe rollback target; cost baselines and total/excess spend; telemetry destinations and retention; and uncertainties that surviving evidence cannot resolve.
