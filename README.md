# ReferenceApp Serverless Reliability and Security Framework

ReferenceApp is a deployable AWS serverless document-ingestion pipeline that implements the application and the Serverless Reliability and Security Framework proposed in the supplied case study. It includes the six reference functions, immutable emit-before-execute evidence, rate anomaly detection, permission expansion gates, zero-standing destructive privilege, latency normalization, and operating runbooks.

## Architecture

```text
Public client ──HTTP──> F1 Ingest ──S3 event──> F2 Extract ──SQS──> F3 Classify
                           │                         │                    │
                        raw bucket              text bucket          DynamoDB

Admin ──JWT──> F4 AdminReview ──signed request──> F5 Purge ──assume 15m role──> delete

EventBridge schedule ──> F6 Report ──> reports bucket
EventBridge every min ──> SRSF RateMonitor ──> SNS alert and throttle proposal

Every function ──PutRecord only──> Firehose ──> object-locked audit bucket
```

The implementation deliberately separates application behavior from AWS adapters. Unit tests exercise a complete ingest, extract, classify, review, report, and purge lifecycle in memory; Lambda entry points use the same behavior with AWS services.

## What is implemented

| Case-study control | Implementation |
|---|---|
| Emit-Before-Execute | `security/ebe.py` records environment identity, runtime, version, environment digest, dependencies, `/tmp` manifest, warm-invocation deltas, correlation IDs, and heartbeats before handler execution. F5 additionally uses content hashing. |
| Tamper-evident evidence | Functions can only call `firehose:PutRecord`; Firehose writes to a versioned S3 bucket with Object Lock retention. Functions cannot read, overwrite, delete, or alter retention. |
| Cost as reliability | `security/anomaly.py` provides burn-rate helpers and a frozen-learning EWMA. The deployed rate monitor checks invocation rate every minute and publishes alert-and-propose notifications rather than throttling automatically. |
| Privacy-conscious telemetry | Public and admin routes share a configurable response latency floor. F4 and F5 use provisioned concurrency. Full-resolution evidence has one controlled destination; the inventory is in `ops/telemetry-inventory.md`. |
| Deployment security | `scripts/srsf_gate.py` fails on new actions or widened resources unless `SRSF_IAM_APPROVER` names an approver. Its JSONL output is suitable for the immutable audit path. F4/F5 use all-at-once deployment to minimize mixed-version exposure. |
| Zero standing privilege | Every function has a dedicated role. F5 holds no delete permission and assumes a tagged, 15-minute purge role only after verifying a short-lived F4-issued HMAC capability. `scripts/permission_footprint.py` scores unused grants 1/3/10. |

## Local verification

Python 3.11 or newer is the only local requirement.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src scripts
PYTHONPATH=src python3 scripts/permission_footprint.py fixtures/permission-usage.json
PYTHONPATH=src python3 scripts/srsf_gate.py policies/f2-baseline.json policies/f2-baseline.json
```

The test suite does not need AWS credentials or third-party packages.

## Deploy to AWS

Prerequisites are an AWS account, configured AWS credentials, and AWS SAM CLI. Validate before deployment:

```bash
sam validate --lint
sam build
sam deploy --guided
```

During the guided deployment, retain change-set confirmation. CloudFormation generates the purge signing key in Secrets Manager and grants read access only to F4 and F5. After deployment:

1. Subscribe the real on-call destination to the `AlertTopicArn` output and confirm the subscription.
2. Create an administrator in the Cognito user pool and add them to the `admins` group.
3. Exercise one document through the public endpoint and verify initialization and heartbeat records arrive in the audit bucket.
4. Confirm CloudWatch has one-minute invocation data before interpreting rate-monitor output. The first samples establish the baseline.
5. Record the production telemetry owners and retention decisions in the inventory.

The template retains primary data and immutable audit buckets if the stack is removed. F1 concurrency is capped at 50 to bound financial exposure; this is an explicit availability-versus-cost tradeoff and should be tuned for the workload.

## API

`POST /documents` accepts a UTF-8 or base64 API Gateway body up to 5 MB. An optional `x-filename` header is sanitized. It returns `202` with a document ID, object key, and SHA-256 digest.

`POST /admin/purge` requires a Cognito JWT whose `cognito:groups` claim contains `admins`.

- `{"action":"review","document_id":"..."}` returns the classification.
- `{"action":"purge","document_id":"...","raw_key":"incoming/.../file.txt"}` issues a signed 60-second purge request to F5.

## Security boundaries and known limits

- Manifest hashing detects create, delete, rename, size, and modification-time changes, but not an adversary that preserves size and mtime. F5 uses content hashing; other functions can enable it selectively.
- EBE makes `/tmp` persistence reconstructible; it does not prevent in-memory persistence or emitter suppression. Missing heartbeats must be alerted on by the log consumer.
- The IAM gate compares resolved policy input conservatively but does not call AWS policy simulation. Production CI should export the effective policy after boundaries and organization SCPs are applied, then pass that JSON to the gate.
- Rate detection reports anomalous spend risk, not attacker intent. It intentionally proposes a per-function throttle for human approval instead of applying one.
- Latency floors and warm capacity reduce application-path leakage but cannot mitigate provider-level hardware side channels.
- The demo classifier is deterministic and local unless `INFERENCE_ENDPOINT` is configured. A production endpoint needs authenticated egress and an explicit timeout/retry policy.

See [operations.md](ops/operations.md) for alerts, deployment checks, incident handling, and postmortem evidence.
