from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from ..adapters import services
from ..config import settings
from ..security.ebe import instrument


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    processed = 0
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        document_id = key.split("/")[1]
        raw = svc.get_object(bucket, key)
        if len(raw) > 5_000_000:
            raise ValueError("object exceeds extraction limit")
        stage = Path(tempfile.gettempdir()) / f"{document_id}.stage"
        try:
            stage.write_bytes(raw)
            text = raw.decode("utf-8", errors="replace")
            text_key = f"text/{document_id}.txt"
            svc.put_object(settings.text_bucket, text_key, text.encode(), "text/plain; charset=utf-8")
            svc.enqueue({"document_id": document_id, "text_bucket": settings.text_bucket,
                         "text_key": text_key})
            processed += 1
        finally:
            stage.unlink(missing_ok=True)
    return {"processed": processed}


@instrument("F2-Extract")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())

