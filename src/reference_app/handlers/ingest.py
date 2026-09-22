from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

from ..adapters import services
from ..config import settings
from ..security.ebe import instrument
from ..security.latency import uniform_latency
from .common import body_bytes, response

_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]")


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    try:
        data = body_bytes(event)
    except (ValueError, TypeError) as exc:
        return response(400, {"error": str(exc)})
    name = _SAFE_NAME.sub("_", (event.get("headers") or {}).get("x-filename", "upload.txt"))[:128]
    document_id = str(uuid.uuid4())
    key = f"incoming/{document_id}/{name}"
    svc.put_object(settings.raw_bucket, key, data)
    return response(202, {"document_id": document_id, "key": key,
                          "sha256": hashlib.sha256(data).hexdigest()})


@instrument("F1-Ingest")
@uniform_latency(settings.latency_floor_ms)
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())

