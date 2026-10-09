# Operational handover record

Set workload-specific acceptance limits with component owners before running deployment checks. Complete this record with verification evidence, recovery instructions and owner approval.

## Deployment and ownership

| Required field | Value |
|---|---|
| Provider / account / region | Pending deployment assignment |
| Runtime, memory, concurrency and ephemeral storage | Pending deployed configuration snapshot |
| Release / policy catalogue / configuration hashes | Pending deployment evidence; local hashes are in generated verification records |
| Incident commander and escalation contacts | Pending named assignment |
| Module 1 observability owner | Pending named assignment |
| Module 2 financial-response owner | Pending named assignment |
| Module 3 security/privacy owner | Pending named assignment |
| Module 4 release owner and independent reviewer | Pending named assignment |
| Module 5 authorization and data operations owners | Pending named assignment |

## Agreed acceptance limits

Record limits before execution for p50/p95/p99 latency, availability during audit/authorization outages, authorized completion rate, audit retention/reconciliation, false pages, pre-alert excess spend, recurring cost and recovery effort. Values remain pending; do not copy the illustrative alert thresholds into performance acceptance criteria without calibration.

## Evidence register

For every required check retain: module and requirement, immutable check ID, input trace/failure injection, expected behavior specified before execution, actual outcome, timestamp, provider/region/runtime, configuration and policy snapshots, evidence location, unresolved defect, recovery action and responsible owner. Use `scripts/verify_project.py` for local test outcomes and hashes; retain separate live-cloud records for operational acceptance.

| Check group | Evidence / actual result | Acceptance |
|---|---|---|
| Module 1 termination, audit failures and missing evidence | Local contract checks generated on demand; live records pending | Pending |
| Module 2 calibrated demand, fan-out and delayed billing | Local detector/accounting checks generated on demand; measured traces pending | Pending |
| Module 3 destination access, resolution and route timing | Inventory exists; access and timing measurements pending | Pending |
| Module 4 provider decisions, rollout halt and safe rollback | Local bounded-policy checks generated on demand; provider/rollout evidence pending | Pending |
| Module 5 grant rejection, concurrency and reconciliation | Local broker checks generated on demand; provider/concurrency evidence pending | Pending |
| Integrated audit/authorization outages and recovery | Runbooks exist; integrated AWS outage records pending | Pending |

## Recovery and acceptance

Link tested audit-path recovery, safe deployment rollback, rate baseline reset, nonce/approval-store recovery and partial-purge reconciliation procedures. Record unresolved defects, accepted risks, exceptions and follow-up owners. Obtain dated acceptance from every component owner and the operational recipient. Handover is complete only after required checks pass, owners accept the runbooks and remaining risks are recorded. Sign-offs remain pending.
