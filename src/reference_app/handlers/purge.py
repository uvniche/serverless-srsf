from __future__ import annotations

from typing import Any

from ..adapters import services
from ..config import settings
from ..security.ebe import instrument
from ..security.purge_auth import verify
from ..security.secrets import purge_token_secret


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    payload = verify(str(event.get("purge_token", "")), purge_token_secret())
    if payload.get("issuer") != "F4":
        raise ValueError("purge token issuer is not authorized")
    svc.delete_object(settings.raw_bucket, payload["raw_key"])
    svc.delete_object(settings.text_bucket, f"text/{payload['document_id']}.txt")
    svc.delete_item(payload["document_id"])
    return {"purged": payload["document_id"]}


@instrument("F5-Purge", content_hash=True)
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    # The standing F5 role can only assume a narrowly-scoped, short-lived purge role.
    return handle(event, context, services(destructive=True))
