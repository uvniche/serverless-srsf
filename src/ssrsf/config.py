from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mode: str = os.getenv("SSRSF_MODE", "aws" if os.getenv("AWS_LAMBDA_FUNCTION_NAME") or os.getenv("USE_AWS_SERVICES") == "1" else "local")
    raw_bucket: str = os.getenv("RAW_BUCKET", "ssrsf-raw-local")
    text_bucket: str = os.getenv("TEXT_BUCKET", "ssrsf-text-local")
    report_bucket: str = os.getenv("REPORT_BUCKET", "ssrsf-reports-local")
    table_name: str = os.getenv("TABLE_NAME", "ssrsf-local")
    queue_url: str = os.getenv("QUEUE_URL", "local://classify")
    inference_endpoint: str = os.getenv("INFERENCE_ENDPOINT", "")
    purge_role_arn: str = os.getenv("PURGE_ROLE_ARN", "")
    purge_token_secret_arn: str = os.getenv("PURGE_TOKEN_SECRET_ARN", "")
    purge_token_secret: str = os.getenv("PURGE_TOKEN_SECRET", "local-development-only")
    latency_floor_ms: int = int(os.getenv("LATENCY_FLOOR_MS", "0"))

    @property
    def is_aws(self) -> bool:
        return self.mode.lower() == "aws"

    @property
    def is_local(self) -> bool:
        return self.mode.lower() == "local"


settings = Settings()
