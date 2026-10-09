"""F5 coordinates deletion and never obtains destructive credentials."""
from __future__ import annotations
import os
from typing import Any
from ..adapters import services
from ..security.ebe import instrument


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    token = event.get('purge_token')
    if not isinstance(token, str) or not token:
        raise ValueError('independently approved purge grant required')
    svc.invoke(os.environ.get('PURGE_BROKER_NAME', 'PurgeBroker'), {'purge_token': token})
    return {'status': 'broker_requested'}


@instrument('F5-Purge', content_hash=True)
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())
