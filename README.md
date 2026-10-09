# ReferenceApp - Serverless Site Reliability and Security Framework (SSRSF)

ReferenceApp is a serverless document-processing pipeline on AWS. It combines document ingestion, extraction, classification, administrative review, controlled deletion and scheduled reporting with durable audit telemetry, spending alerts and deployment authorization checks.

The infrastructure template and local tests are ready for deployment verification. Workload calibration, latency and cost measurements, and operational acceptance remain pending.

## Architecture

```text
Client --Cognito JWT--> Gateway --> F1 Ingest --> raw S3 --> F2 Extract
                                                           |
                                                        text S3 --> SQS --> F3 Classify --> DynamoDB

Administrator --JWT--> F4 AdminReview --> F5 Purge coordinator --> trusted PurgeBroker
Purge approver --JWT--> independent Approval service --> signed exact-target grant + approval store
PurgeBroker --> check approval --> atomic nonce consume --> scoped 15-minute STS session --> delete

Schedule --> F6 Report --> reports S3
Every minute --> RateMonitor --> per-function EWMA state --> SNS alert and throttle proposal
Every function --> conditional synchronous S3 write --> versioned, object-locked audit bucket
```

F4/F5 have no delete rights, signing-key access, approval-store access, or permission to assume the destructive role. Only the trusted broker can obtain destructive credentials; it enforces an independently issued grant first. Approval is issued through its own authenticated gateway route; F4/F5 cannot invoke that service. An operation grant lasts 60 seconds, while broker-held STS credentials last 900 seconds. The trusted components retain capability and are explicit compromise boundaries.

## Project modules and implementation

| Component | Implementation and coverage |
|---|---|
| Reference workflow | Six application functions, four trigger types, `/tmp` staging, PDF parsing with `pypdf`, optional external inference, admin workflow and scheduled aggregation. Local classification is a deterministic development fallback. |
| Durable forensic telemetry | Initialization plus entry and exit manifests, environment/invocation IDs and sequences, dependency observations, bootstrap comparison, warm-entry comparison with the previous acknowledged exit. Bounded retries precede processing; unavailable acknowledgements fail closed. Failed exit retention leaves an evidence gap and does not undo side effects. |
| Audit storage | Direct `PutObject` with checksum, content-addressed retry key and `If-None-Match: *`. Audit bucket policy requires conditional writes; COMPLIANCE Object Lock retains accepted versions for 30 days. Functions cannot read, delete or change retention. Queue acceptance is not an acknowledgement. Local stdout deliberately cannot acknowledge durability. |
| Spending monitoring | EWMA freezes learning on suspected anomalies, deduplicates timestamped minute buckets and monitors F1-F6. Missing metrics do not become zero traffic. `spending_report.py` separates total spend, excess, cap and allowance and requires both paired windows to breach. Billing windows and downstream charges must be supplied by the operator. Thresholds are illustrative and require calibration. |
| Telemetry confidentiality | Shared response latency floor includes audit work; F4/F5 use provisioned concurrency. Destination resolution, access, owner and retention budgets are recorded in the telemetry inventory. A floor cannot equalize all timing distributions. |
| Deployment authorization | A finite request catalogue yields production/candidate allow, deny or unresolved decisions with snapshots and evaluator version. Explicit denies and limiting-policy intersections are handled in a declared subset. Missing inputs, unsupported semantics and changed scopes outside coverage halt for named review. Optional start/end security configuration checks detect drift. |
| Controlled deletion | Separate approval service and broker, requester-bound signed grant, exact object versions and row ID, consistent independent approval lookup, atomic nonce consumption, target-restricted STS session policy, durable decisions and per-target outcomes. Partial deletion requires reconciliation and renewed authorization. |
| Permission maintenance | Weighted unused-permission report and weekly review; dormant recovery permissions need justification rather than automatic removal. |
| Verification and operations | Six implementation stages, component success/failure checks, integrated outages, retained expected/actual local records and pending owner acceptance. See `ops/project-controls.md`, `ops/evaluation.md` and `ops/handover.md`. |

## Local verification

Python 3.11 or newer is required. Install the parser dependency before running tests:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
PYTHONPATH=src .venv/bin/python scripts/verify_project.py --output verification-output/local-checks.json
PYTHONPATH=src .venv/bin/python scripts/permission_footprint.py fixtures/permission-usage.json
PYTHONPATH=src .venv/bin/python scripts/srsf_gate.py policies/f2-snapshot.json policies/f2-snapshot.json --catalogue policies/f2-catalogue.json
```

The verification command records individual expected/actual outcomes, runtime, configuration hashes and unresolved checks. Install `cfn-lint` to include template lint; an unavailable tool is recorded as `not_run`. CI retains the JSON record. Tests use in-memory AWS adapters and explicit test acknowledgement sinks. AWS entry points fail closed without a durable audit destination. The gate example demonstrates a finite catalogue and is not an export of production effective permissions.

## API and authorization

`POST /documents` requires a Cognito JWT and accepts UTF-8 text or a base64 API Gateway body up to 5 MB. `x-filename` is sanitized. The response is `202` with a document ID, raw key and digest. The public route is externally reachable but authenticated.

`POST /admin/approve-purge` requires a JWT with the `purge-approvers` group. Supply `document_id`, `raw_key`, `raw_version` and `text_version` for the exact versions reviewed. The independently trusted service returns `purge_token` and `operation_id`. The token is sensitive and must not be logged or disclosed. Group membership is the prototype's approval-scope policy: approvers may approve documents throughout the application buckets. Tenant-specific authority needs an additional policy.

`POST /admin/purge` requires the `admins` group:

- `{"action":"review","document_id":"..."}` returns the classification.
- `{"action":"purge","purge_token":"..."}` submits an independently approved operation through F5 to the broker.

Approval is a distinct request. An admin purge request alone cannot mint authorization. The broker deletes only the named raw/text versions and row; other versions remain. Deleting all historical content requires separately approved version-specific operations. Successful submission means work was requested, not that deletion completed. Consult the broker operation record for completion or partial failure; replay is rejected.

## AWS deployment

Use configured AWS credentials and SAM CLI:

```bash
sam validate --lint
sam build
sam deploy --guided --capabilities CAPABILITY_NAMED_IAM
```

Set `LatencyAlarmThresholdMs` to the deployment owner's selected p95 Lambda duration alert threshold during guided deployment. F1/F4 duration alarms complement the F1 error alarm; gateway end-to-end latency still needs measurement. Choose the threshold for the workload and confirm it with measurements.

Provision an administrator and an independent purge approver in their respective Cognito groups. Confirm an on-call subscription to `AlertTopicArn`; F2 and broker errors use an independent CloudWatch-to-SNS path. Verify retained entry/exit records and conditional-write enforcement before sending production traffic. Reconcile retained evidence with provider invocation counts using `scripts/reconcile_evidence.py` over matching time windows; this is an operator-run check, not a deployed continuous completeness detector.

Review changes to the named broker role and approval group as changes to trusted authorization infrastructure. Retained primary buckets and audit storage survive stack removal. COMPLIANCE audit retention cannot be shortened for already retained versions. F1 concurrency is capped at 50 as an explicit cost/availability trade-off. Existing rate state from the earlier per-minute detector must be reset before deploying the per-second detector.

## Limits

The IAM evaluator supports same-account role identity policies with absent resource policies, explicit denies, limiting policy intersections and `StringEquals`, `ArnEquals`, and `Bool` conditions. Empty limiting-policy lists explicitly mean absent; missing fields mean unresolved. Resource-based grants, cross-account evaluation, `NotAction`/`NotResource`, other operators and changed conditional or wildcard scopes require review. A finite catalogue does not prove authorization equivalence. The CLI's approver field records review; CI must authenticate reviewers and protect that input. Deployment wiring, provider-backed policy comparisons and production policy-change detection remain operator responsibilities.

EBE assumes serial invocations and no background writers. Manifests miss changes preserving size and mtime; selective content hashing is enabled for sensitive trust components and F5. The emitter remains inside the potentially compromised environment. Initialization checks an empty bootstrap manifest by default; functions with legitimate bootstrap files need a declared baseline. Audit delivery and nonce/approval stores create availability dependencies. Application handlers are repeatable for the same object/document identity, but object versions, queue deliveries and external inference may still multiply cost during retries.

The prototype does not unify both role paths behind a shared initial application chain, authenticate a configured inference endpoint, collect full billing windows automatically, or empirically validate timing leakage, seasonality, detection quality or cost. Those remaining implementation and verification items are explicit in `ops/evaluation.md`.

## Operations

The [control register](ops/project-controls.md) describes component responsibilities, interfaces and failure behavior. The [verification plan](ops/evaluation.md) covers local and deployed checks. Use the [handover record](ops/handover.md) to assign owners, set latency, availability and cost limits, and record deployment evidence and remaining risks.

See [operations](ops/operations.md) and [telemetry inventory](ops/telemetry-inventory.md) for incident response, recovery and destination controls.
