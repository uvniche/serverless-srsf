from __future__ import annotations

import json
import os
from typing import Any

from ..adapters import services
from ..config import settings
from ..security.ebe import instrument
from ..security.latency import uniform_latency
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
    if payload.get("action") != "purge":
        return response(400, {"error": "unknown action"})
    token = payload.get("purge_token")
    if not isinstance(token, str) or not token:
        return response(400, {"error": "independent approval grant required"})
    svc.invoke(os.environ.get("PURGE_FUNCTION_NAME", "F5-Purge"), {"purge_token": token})
    return response(202, {"status": "purge_requested"})


@uniform_latency(settings.latency_floor_ms)
@instrument("F4-AdminReview")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())
