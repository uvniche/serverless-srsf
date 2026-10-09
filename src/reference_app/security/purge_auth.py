from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Mapping


def issue(payload: Mapping[str, Any], secret: str, ttl_seconds: int = 60) -> str:
    if not 0 < ttl_seconds <= 60:
        raise ValueError('grant lifetime must be between 1 and 60 seconds')
    body = {**payload, 'nonce': str(uuid.uuid4()), 'exp': int(time.time()) + ttl_seconds}
    raw = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    return urlsafe_b64encode(raw).decode().rstrip('=') + '.' + urlsafe_b64encode(sig).decode().rstrip('=')


def verify(token: str, secret: str) -> dict[str, Any]:
    try:
        encoded, signature = token.split('.', 1)
        raw = urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        supplied = urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError('malformed purge grant') from exc
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError('invalid purge grant')
    if not isinstance(payload, dict) or int(payload.get('exp', 0)) <= int(time.time()):
        raise ValueError('expired purge grant')
    return payload


def validate_scope(payload: Mapping[str, Any]) -> None:
    import re
    document = payload.get('document_id', '')
    if not isinstance(document, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', document):
        raise ValueError('invalid document identifier')
    raw = payload.get('raw_key', '')
    if not isinstance(raw, str) or not raw.startswith(f'incoming/{document}/') or raw.endswith('/'):
        raise ValueError('raw key is outside the approved document')
    if any(c in raw for c in '*?') or any(ord(c) < 32 for c in raw):
        raise ValueError('raw key contains unsupported IAM wildcard characters')
    if payload.get('text_key') != f'text/{document}.txt':
        raise ValueError('text key is outside the approved document')
    if payload.get('actions') != ['s3:DeleteObjectVersion', 'dynamodb:DeleteItem']:
        raise ValueError('invalid delete actions')
    if not payload.get('requester') or not payload.get('nonce'):
        raise ValueError('requester and nonce are required')
    # Versioned buckets: a delete marker is not deletion of retained content.
    for name in ('raw_version', 'text_version'):
        if not isinstance(payload.get(name), str) or not payload[name] or payload[name] == 'null':
            raise ValueError('exact object versions are required')
