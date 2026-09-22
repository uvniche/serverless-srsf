from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Mapping


def issue(payload: Mapping[str, Any], secret: str, ttl_seconds: int = 60) -> str:
    body = {**payload, "exp": int(time.time()) + ttl_seconds}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    return urlsafe_b64encode(raw).decode().rstrip("=") + "." + urlsafe_b64encode(sig).decode().rstrip("=")


def verify(token: str, secret: str) -> dict[str, Any]:
    try:
        encoded, signature = token.split(".", 1)
        raw = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        supplied = urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except Exception as exc:
        raise ValueError("malformed purge token") from exc
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("invalid purge token")
    payload = json.loads(raw)
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("expired purge token")
    return payload

