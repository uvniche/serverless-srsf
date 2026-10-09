# Project control register and implementation stages

Reference: **Serverless Site Reliability and Security Framework - Project Report**, October 2026, Sections 3.3-3.4 and 10. This report defines a design-stage project. Repository code and local checks are subsequent implementation evidence. Provisioning, operating measurements and handover acceptance remain pending.

Owners below identify responsible roles. Assign the deployment's named people and on-call contacts before handover; this repository does not invent those assignments.

| Module / report section | Accountable owner role | Input | Required output and implementation | Dependency failure |
|---|---|---|---|---|
| 1 Durable forensic telemetry / 4 | SRE observability owner | Invocation context, environment identity, `/tmp` manifests, runtime dependency set | `security/ebe.py`: retained initialization/entry/exit, receipts, linked sequence and correlation IDs; `reconcile_evidence.py`: evidence gaps | Entry ACK unavailable: block processing. Exit ACK unavailable: report gap, preserve side-effect status. Independent CloudWatch F2 alarm; continuous completeness alerts still need a consumer. |
| 2 Spending monitoring / 5 | SRE financial-response owner | Per-function timestamped invocation counts, unit costs, workload baselines, downstream spend windows | `rate_monitor.py`, `security/anomaly.py`, `spending_report.py`: frozen-learning EWMA, spend multiplier, separate total/excess indicators, paired-window escalation | Missing metrics: do not train as zero. Missing billing windows: no paired-window finding for that pair; investigate missing inputs. Never apply a throttle automatically. |
| 3 Telemetry confidentiality / 6 | Security/privacy owner with SRE | Trace fields, destinations, observer model, route latency | `ops/telemetry-inventory.md`, shared latency floor, F4/F5 warm capacity, primary-domain evidence retention | Audit dependency uses Module 1 behavior. New exports require access/resolution/retention review. Timing or diagnostic acceptance remains pending measurement. |
| 4 Deployment authorization / 7 | Platform release owner and independent reviewer | Complete current/candidate policy snapshots, finite request catalogue, security configuration snapshots | `security/iam.py`, `srsf_gate.py`: allow/deny/unresolved matrix, evaluator/coverage, review or halt, JSONL staging artifact | Unsupported or missing input and unapproved drift halt automatic progression. Unavailable review blocks release. Immutable upload and live-policy discovery remain deployment integration tasks. |
| 5 Controlled deletion / 8 | Security authorization owner; data operations owner | Authenticated approval request, independently issued exact-version/row grant | `approval.py`, `purge.py`, `purge_broker.py`: grant binding, expiry, independent lookup, atomic nonce consumption, scoped credentials and retained outcomes | Missing approval or replay store: no deletion. Partial/unknown outcomes: reconcile and obtain fresh approval; consumed grants cannot be retried. |

Each owner must retain decision evidence and review latency, availability and cost overhead before adoption. Primary evidence is in the retained audit bucket; local JSON files and CI artifacts are staging records.

## Section 10.1 implementation sequence

| Stage | Repository deliverable | Current boundary | Next acceptance requirement |
|---|---|---|---|
| 1 Provision reference workflow | `template.yaml`; F1-F6 handlers and dedicated roles; input limits and parser; Cognito gateway; F1 error and F1/F4 p95 duration alerts | Infrastructure specification and local pipeline checks exist | Provision in declared provider/region, verify triggers and service indicators, retain configuration snapshot |
| 2 Durable evidence | Acknowledged EBE, retention/access policy, local reconciliation, F2 audit-path error alarm | Local success/failure tests and template lint | Verify retention after environment termination and provider counts; install independent missing-record consumer |
| 3 Spend/confidentiality | Rate monitor, spending report, destination inventory, latency floor | Local detector/accounting tests; billing inputs are operator supplied | Calibrate demand and windows, capture downstream costs, measure timing/diagnostic impact and confirm access |
| 4 Deployment gates | Finite catalogue, evaluator, drift checks and CI fixture | Local bounded decisions; fixture CI is not a production deployment gate | Wire live policy snapshots, authenticate reviewers, retain rollout timeline/decisions and verify safe rollback |
| 5 Mediated deletion | Separate approval and broker, nonce table, exact targets and outcomes | Local approval, replay and partial-failure checks | Test concurrent AWS requests, provider-enforced scope, service outages and recovery |
| 6 Operational handover | Runbooks, control register, verification records and handover template | Documentation and local record generator exist | Assign named owners, agree deployment limits, pass required live checks and accept runbooks/remaining risks |

A local pass does not mark a stage accepted. Track deployment evidence and unresolved defects in `ops/handover.md` and follow `ops/evaluation.md` for the report's verification checks.
