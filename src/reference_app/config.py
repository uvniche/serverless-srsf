from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    raw_bucket: str = os.getenv("RAW_BUCKET", "referenceapp-raw-local")
    text_bucket: str = os.getenv("TEXT_BUCKET", "referenceapp-text-local")
    report_bucket: str = os.getenv("REPORT_BUCKET", "referenceapp-reports-local")
    table_name: str = os.getenv("TABLE_NAME", "referenceapp-local")
    queue_url: str = os.getenv("QUEUE_URL", "local://classify")
    audit_stream: str = os.getenv("AUDIT_STREAM", "")
    inference_endpoint: str = os.getenv("INFERENCE_ENDPOINT", "")
    purge_role_arn: str = os.getenv("PURGE_ROLE_ARN", "")
    purge_token_secret_arn: str = os.getenv("PURGE_TOKEN_SECRET_ARN", "")
    purge_token_secret: str = os.getenv("PURGE_TOKEN_SECRET", "local-development-only")
    latency_floor_ms: int = int(os.getenv("LATENCY_FLOOR_MS", "0"))


settings = Settings()
