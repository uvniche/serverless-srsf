# Verification plan

Verify each component during normal operation and dependency failures, then exercise the complete workflow. Local checks cover application behavior and control contracts; deployed checks cover provider enforcement, recovery and operating overhead.

Follow the implementation sequence in [project-controls.md](project-controls.md). Each module has an accountable owner role, declared inputs/outputs and failure behavior. Assign deployment-specific named owners and acceptance limits in [handover.md](handover.md) before operational verification.

## Local verification records

```bash
PYTHONPATH=src python3 scripts/verify_project.py --output verification-output/local-checks.json
```

Run with installed project dependencies. Install `cfn-lint` to include infrastructure lint in this record. The script retains expected/actual outcomes for each local test, compilation, the finite IAM fixture and optional template lint, plus runtime/platform and configuration hashes. Missing checks appear as `not_run`; failures remain unresolved. This record explicitly marks deployment verification, performance measurements, owner acceptance and handover pending.

The JSON contains technical evidence and failure diagnostics; handle it under the telemetry inventory's CI/local-record access and retention rules. CI uploads the local verification record as a build artifact. That staging artifact does not satisfy immutable audit retention by itself.

## Component checks

Record each check's inputs and expected outcome before execution, then retain actual outcomes and unresolved defects. The following expectations are acceptance behavior, not claims of measured effectiveness.

| Module | Check inputs | Expected behavior | Local evidence | Live verification still required |
|---|---|---|---|---|
| 1 Durable forensic telemetry | Legitimate staging, undeclared file change, audit entry/exit failure, termination, emitter tampering | Entry retained before processing; warm entry compared with acknowledged prior exit; missing records generate separate gaps; failed entry blocks work; failed exit reports possible completed side effects | EBE contract tests, content-preserving mutation test, retry identity and sequence/count reconciliation | Retrieve required fields after termination, verify independent alerts and emitter suppression recognition; record capture/ingestion overhead |
| 2 Spending alerts | Steady demand, legitimate bursts, retries, elevated rates, downstream fan-out, below-threshold increases | Distinct buckets only; anomalous learning frozen; missing data not trained as zero; paired windows both breach; unexpected activity for zero expectation; total/excess denominators separate; human throttle decision | Detector persistence/deduplication tests, accounting and paired-window tests | Workload-specific calibration, alert delay, pre-alert excess spend, false pages, actual downstream bills and documented missed/below-threshold increases |
| 3 Telemetry confidentiality | Destination credentials and exports, retained identifiers, role-distinct timing | Access and resolution/retention match inventory; sensitive fields reviewed; configured floor includes protected work | Template/access configuration and inventory; shared response floor | Test access with deployed identities; measure role-path differences, latency and diagnostic impact for declared observer; review common façade design |
| 4 Deployment authorization | Expansions/contractions, denies, condition changes, out-of-scope resources, unsupported inputs | Newly allowed requests halt pending review; unsupported/unresolved cases never clear automatically; coverage/evaluator recorded; drift halts unreviewed progression | Bounded IAM tests and fixture gate | Compare supported decisions with provider outcomes, exercise real release halt/review and security-safe rollback, retain traffic/retry reachability timeline |
| 5 Controlled deletion | Valid approvals, forgery, expiry, replay, requester substitution, wrong target, concurrent duplicates, approval outage and partial deletion | Invalid grant causes no delete; independent authority checked; atomic consume before credentials; exact targets enforced; decision/outcomes retained; partial operations reconcile under same ID | Grant/broker failure tests and in-memory pipeline | Concurrent AWS duplicate requests, session-scope enforcement, approval/replay-service outages, abrupt termination and reconciliation recovery |

## Integrated checks

Run the full document workflow during audit-store and authorization-service outages. Confirm fail-closed behavior, legitimate completion rate, retry amplification and operator recovery. Record p50/p95/p99 latency, availability impact and recurring cost with controls enabled. Include the cost of audit writes, capture, provisioned concurrency, downstream inference and retries in workload baselines.

Retain provider, region, runtime, resource limits, warm/cold state, working-set size, telemetry delay, workload traces, configuration snapshots, policy catalogues, check inputs, expected/actual outcomes, unresolved defects and recovery instructions. Thresholds and weights are illustrative; no performance limits or success measurements are invented here.

## Handover acceptance

Complete the evidence register and named owner sign-offs in [handover.md](handover.md). Required checks must pass, owners must accept runbooks, and remaining risks must be recorded before handover. Local test success alone is insufficient.

Production integration tasks include a continuous independent evidence-gap consumer, live policy discovery and protected review workflow, full billing-window ingestion, authenticated inference egress, telemetry access verification and safe rollback enforcement. Portability and additional workflow types follow initial deployment verification.
