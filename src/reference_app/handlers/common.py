from __future__ import annotations

import base64
import json
from typing import Any, Mapping


def response(status: int, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(body, separators=(",", ":")),
    }


def body_bytes(event: Mapping[str, Any], max_bytes: int = 5_000_000) -> bytes:
    raw = event.get("body", "")
    if event.get("isBase64Encoded"):
        data = base64.b64decode(raw, validate=True)
    else:
        data = raw.encode() if isinstance(raw, str) else bytes(raw)
    if not data or len(data) > max_bytes:
        raise ValueError("document must be between 1 byte and 5 MB")
    return data

