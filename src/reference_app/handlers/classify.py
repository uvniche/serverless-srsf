from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..adapters import services
from ..security.ebe import instrument


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    processed = 0
    for record in event.get("Records", []):
        body = json.loads(record["body"]) if isinstance(record.get("body"), str) else record["body"]
        text = svc.get_object(body["text_bucket"], body["text_key"]).decode("utf-8", errors="replace")
        svc.put_item({
            "document_id": body["document_id"],
            "classification": svc.classify(text),
            "classified_at": datetime.now(timezone.utc).isoformat(),
        })
        processed += 1
    return {"processed": processed}


@instrument("F3-Classify")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())

