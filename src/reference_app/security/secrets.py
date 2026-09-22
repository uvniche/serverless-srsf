from __future__ import annotations

import functools
import json

from ..config import settings


@functools.lru_cache(maxsize=1)
def purge_token_secret() -> str:
    """Resolve the F4/F5-only signing key once per warm environment."""
    if not settings.purge_token_secret_arn:
        return settings.purge_token_secret
    import boto3

    value = boto3.client("secretsmanager").get_secret_value(SecretId=settings.purge_token_secret_arn)
    secret = value.get("SecretString")
    if not secret:
        raise RuntimeError("binary purge secrets are not supported")
    try:
        decoded = json.loads(secret)
        return str(decoded.get("token", secret))
    except json.JSONDecodeError:
        return secret
