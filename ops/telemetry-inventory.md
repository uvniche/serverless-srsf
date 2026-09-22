# Telemetry Estate Inventory

This inventory defines the permitted telemetry destinations. Additions require a security and privacy review.

| Destination | Resolution | Owner | Retention | Purpose | Trust boundary |
|---|---|---|---|---|---|
| Object locked audit bucket | Per invocation EBE records | SRE | 30 days | Forensics and heartbeat detection | Primary AWS account |
| CloudWatch Lambda metrics | One minute aggregate | SRE | AWS default unless configured | Availability and rate anomaly detection | Primary AWS account |
| AWS X-Ray | Sampled per-invocation traces | SRE | 30 days | Correlation and dependency failures | Primary AWS account |
| SNS alert topic | Alert events only | On call | Delivery only | Page and proposed throttle | Primary AWS account plus subscribed endpoint |
| DynamoDB rate state | Per function EWMA state | SRE | Current state | Anomaly baseline | Primary AWS account |
| CI IAM audit artifact | Per deployment | Platform engineering | CI policy | Permission gate evidence before audit ingestion | CI provider |

Do not export per-invocation traces or millisecond timestamps to third-party analytics by default. A new destination must identify an owner, operational decision that needs the data, minimum sufficient resolution, encryption mechanism, access policy, and deletion period.
