from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from ..adapters import services
from ..config import settings
from ..security.ebe import instrument


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    items = svc.scan_items()
    counts = Counter(str(item.get("classification", "unknown")) for item in items)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "documents": len(items),
              "classifications": dict(sorted(counts.items()))}
    key = "reports/" + datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ") + ".json"
    svc.put_object(settings.report_bucket, key, json.dumps(report, sort_keys=True).encode(), "application/json")
    return {"key": key, **report}


@instrument("F6-Report")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())

