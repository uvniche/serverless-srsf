"""Trusted destructive broker; grant authorization and nonce consumption precede STS."""
from __future__ import annotations
from typing import Any
from ..adapters import services
from ..config import settings
from ..security.ebe import acknowledge, default_sink, instrument
from ..security.purge_auth import validate_scope, verify
from ..security.secrets import purge_token_secret


def handle(event: dict[str, Any], context: Any, svc: Any, audit: Any = None) -> dict[str, Any]:
    grant = verify(str(event.get('purge_token', '')), purge_token_secret())
    validate_scope(grant)
    if grant.get('issuer') != 'ApprovalService':
        raise ValueError('independent approval required')
    # Consistent read from a service-owned record, not an F4/F5 assertion.
    if svc.get_grant(grant['nonce']) != grant:
        raise ValueError('approval unavailable or does not match grant')
    sink = audit or default_sink()
    base = {'schema': 'ssrsf.purge.v1', 'function': 'PurgeBroker',
            'operation_id': grant['nonce'], 'requester': grant['requester'], 'targets': grant}
    acknowledge(sink, {**base, 'type': 'authorized', 'idempotency_key': grant['nonce'] + '/authorized'}, context)
    verify(str(event['purge_token']), purge_token_secret())  # Recheck expiry after audit wait.
    svc.consume_nonce(grant['nonce'], grant['exp'])
    completed = []
    try:
        # Credentials never leave this separately trusted broker.
        destructive = svc.scoped_purge(grant)
        for label, operation in [
            ('raw', lambda: destructive.delete_object(settings.raw_bucket, grant['raw_key'], grant['raw_version'])),
            ('text', lambda: destructive.delete_object(settings.text_bucket, grant['text_key'], grant['text_version'])),
            ('row', lambda: destructive.delete_item(grant['document_id'])),
        ]:
            operation()
            completed.append(label)
            svc.record_outcome(grant['nonce'], list(completed), 'partial')
            acknowledge(sink, {**base, 'type': 'target_completed', 'target': label,
                'session_identity': getattr(destructive, 'session_identity', 'memory'),
                'idempotency_key': grant['nonce'] + '/' + label}, context)
        svc.record_outcome(grant['nonce'], completed, 'completed')
    except Exception:
        svc.record_outcome(grant['nonce'], completed, 'reconciliation_required')
        raise
    return {'purged': grant['document_id'], 'operation_id': grant['nonce'], 'completed': completed}


@instrument('PurgeBroker', content_hash=True)
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())
