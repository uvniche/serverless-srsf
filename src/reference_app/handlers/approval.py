"""Trusted approval service: invocable only by the gateway's authenticated route."""
from __future__ import annotations

import json
from typing import Any

from ..adapters import services
from ..security.ebe import instrument
from ..security.purge_auth import issue, validate_scope, verify
from ..security.secrets import purge_token_secret
from .common import response


def handle(event: dict[str, Any], context: Any, svc: Any) -> dict[str, Any]:
    claims = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {})
    groups = claims.get('cognito:groups', [])
    if isinstance(groups, str):
        groups = groups.replace('[', '').replace(']', '').replace(',', ' ').split()
    if 'purge-approvers' not in groups or not claims.get('sub'):
        return response(403, {'error': 'independent purge approver required'})
    data = json.loads(event.get('body') or '{}')
    # Human approves exact versions and row in the authenticated request.
    scope = {key: data.get(key) for key in ('document_id', 'raw_key', 'raw_version', 'text_version')}
    scope.update(issuer='ApprovalService', requester=claims['sub'],
                 text_key=f"text/{scope['document_id']}.txt",
                 actions=['s3:DeleteObjectVersion', 'dynamodb:DeleteItem'])
    token = issue(scope, purge_token_secret())
    grant = verify(token, purge_token_secret())
    validate_scope(grant)
    svc.save_grant(grant)
    return response(200, {'purge_token': token, 'operation_id': grant['nonce']})


@instrument('PurgeApproval', content_hash=True)
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return handle(event, context, services())
