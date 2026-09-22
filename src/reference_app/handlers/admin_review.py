from __future__ import annotations

import json
import os
from typing import Any

from ..adapters import services
from ..config import settings
from ..security.ebe import instrument
from ..security.latency import uniform_latency
from ..security.purge_auth import issue
from ..security.secrets import purge_token_secret
from .common import response


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    claims = (event.get("requestContext") or {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    raw_groups = claims.get("cognito:groups", "")
    if isinstance(raw_groups, list):
        groups = set(map(str, raw_groups))
    else:
        groups = set(str(raw_groups).replace("[", "").replace("]", "").replace(",", " ").split())
    if "admins" not in groups and os.getenv("ALLOW_LOCAL_ADMIN") != "1":
        return response(403, {"error": "admin role required"})
    payload = json.loads(event.get("body") or "{}")
    document_id = str(payload.get("document_id", ""))
    if payload.get("action", "review") == "review":
        item = svc.get_item(document_id) if document_id else None
        return response(200 if item else 404, {"document": item} if item else {"error": "not found"})
    raw_key = str(payload.get("raw_key", ""))
    if not document_id or not raw_key.startswith(f"incoming/{document_id}/"):
        return response(400, {"error": "document_id and matching raw_key are required"})
    token = issue({"document_id": document_id, "raw_key": raw_key, "issuer": "F4"},
                  purge_token_secret())
    svc.invoke(os.environ.get("PURGE_FUNCTION_NAME", "F5-Purge"), {"purge_token": token})
    return response(202, {"status": "purge_requested", "document_id": document_id})


@instrument("F4-AdminReview")
@uniform_latency(settings.latency_floor_ms)
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())
