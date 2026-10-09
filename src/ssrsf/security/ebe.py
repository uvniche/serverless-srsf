from __future__ import annotations

import functools
import hashlib
import importlib.metadata
import json
import os
import platform
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TypeVar

F = TypeVar('F', bound=Callable[..., Any])
_LOCK = threading.RLock()  # Serial capture and processing; background writers are unsupported.
_ENVIRONMENT_ID = str(uuid.uuid4())
_INITIALIZED: set[str] = set()
_LAST_MANIFEST: dict[str, str] = {}
_SEQUENCE: dict[str, int] = {}


class AuditSink(Protocol):
    def emit(self, record: Mapping[str, Any]) -> str: ...


class AuditUnavailable(RuntimeError):
    pass


class StdoutAuditSink:
    """Local diagnostic sink; deliberately cannot acknowledge durable retention."""
    def emit(self, record: Mapping[str, Any]) -> str:
        print(json.dumps({'ssrsf_audit': record}, sort_keys=True))
        raise AuditUnavailable('stdout is not a durable audit acknowledgement')


class S3AuditSink:
    """Conditional write to a bucket with default Object Lock retention.

    Bucket policy must require If-None-Match and deny retention/delete rights.
    Content-addressed keys make a timed-out write retry unambiguous without reads.
    """
    def __init__(self, bucket: str, client: Any = None):
        self.bucket, self.client = bucket, client

    def emit(self, record: Mapping[str, Any]) -> str:
        if self.client is None:
            import boto3
            from botocore.config import Config
            self.client = boto3.client('s3', config=Config(
                connect_timeout=1, read_timeout=1, retries={'total_max_attempts': 1}))
        payload = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        key = 'evidence/' + hashlib.sha256(payload).hexdigest() + '.json'
        try:
            result = self.client.put_object(Bucket=self.bucket, Key=key, Body=payload,
                IfNoneMatch='*', ChecksumAlgorithm='SHA256', ServerSideEncryption='AES256',
                ContentType='application/json')
        except Exception as exc:
            if getattr(exc, 'response', {}).get('Error', {}).get('Code') == 'PreconditionFailed':
                return key  # The exact content-addressed record was already retained.
            raise
        if not result.get('VersionId'):
            raise AuditUnavailable('audit bucket did not return a retained version')
        return key + ':' + result['VersionId']


def default_sink() -> AuditSink:
    bucket = os.getenv('AUDIT_BUCKET', '')
    return S3AuditSink(bucket) if bucket else StdoutAuditSink()


def _hash_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def manifest(root: str | Path | None = None, *, content: bool = False) -> tuple[str, list[dict[str, Any]]]:
    base = Path(root or tempfile.gettempdir())
    entries = []
    for path in sorted(base.rglob('*')):
        if path.is_symlink():
            entries.append({'path': str(path.relative_to(base)), 'symlink': os.readlink(path)})
            continue
        if not path.is_file():
            continue
        stat = path.stat()
        item = {'path': str(path.relative_to(base)), 'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns}
        if content:
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    digest.update(chunk)
            item['content_sha256'] = digest.hexdigest()
        entries.append(item)
    return _hash_json(entries), entries


def environment_digest(env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    return _hash_json({key: hashlib.sha256(value.encode()).hexdigest() for key, value in sorted(source.items())})


def dependencies() -> list[str]:
    return sorted(f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions())


def _correlation_id(event: Mapping[str, Any], context: Any) -> str:
    headers = event.get('headers') or {}
    return str(headers.get('x-correlation-id') or headers.get('X-Correlation-Id')
               or getattr(context, 'aws_request_id', '') or uuid.uuid4())


def acknowledge(audit: AuditSink, record: Mapping[str, Any], context: Any = None) -> str:
    # Reserve time for exit capture. SDK timeouts bound each attempt on AWS.
    failure = None
    for attempt in range(3):
        remaining = getattr(context, 'get_remaining_time_in_millis', lambda: 10000)()
        if remaining < 2500:
            break
        try:
            receipt = audit.emit(record)
            if not receipt:
                raise AuditUnavailable('missing durable receipt')
            return receipt
        except Exception as exc:
            failure = exc
            if attempt < 2:
                time.sleep(.05 * (2 ** attempt))
    # Independent CloudWatch error/log alarm path, separate from the audit bucket.
    print(json.dumps({'ssrsf_evidence_gap': record.get('idempotency_key'),
                      'function': record.get('function'), 'phase': record.get('type')}))
    raise AuditUnavailable('durable audit acknowledgement unavailable') from failure


def instrument(function_name: str, *, content_hash: bool = False, sink: AuditSink | None = None,
               root: str | Path | None = None, bootstrap_hash: str | None = None) -> Callable[[F], F]:
    audit = sink or default_sink()
    def decorate(handler: F) -> F:
        @functools.wraps(handler)
        def wrapped(event: Mapping[str, Any], context: Any) -> Any:
            with _LOCK:
                sequence = _SEQUENCE.get(function_name, 0) + 1
                _SEQUENCE[function_name] = sequence
                invocation = str(getattr(context, 'aws_request_id', '') or uuid.uuid4())
                base = {'schema': 'ssrsf.ebe.v2', 'function': function_name,
                        'function_version': os.getenv('AWS_LAMBDA_FUNCTION_VERSION', 'local'),
                        'environment_id': _ENVIRONMENT_ID, 'invocation_id': invocation,
                        'sequence': sequence, 'correlation_id': _correlation_id(event, context)}
                def emit(kind: str, **fields: Any) -> str:
                    return acknowledge(audit, {**base, 'type': kind,
                        'timestamp_ms': int(time.time() * 1000),
                        'idempotency_key': f'{_ENVIRONMENT_ID}/{function_name}/{sequence}/{kind}',
                        **fields}, context)
                current_hash, entries = manifest(root, content=content_hash)
                cold = function_name not in _INITIALIZED
                previous = _LAST_MANIFEST.pop(function_name, None)
                if cold:
                    emit('initialization', runtime=platform.python_version(),
                         manifest_sha256=current_hash, manifest_entries=entries,
                         environment_sha256=environment_digest(), dependencies=dependencies(),
                         bootstrap_sha256=bootstrap_hash or _hash_json([]),
                         bootstrap_matches=current_hash == (bootstrap_hash or _hash_json([])))
                    _INITIALIZED.add(function_name)
                gap = not cold and previous is None
                entry_receipt = emit('entry', manifest_sha256=current_hash, manifest_entries=entries,
                     previous_exit_manifest_sha256=previous, evidence_gap=gap,
                     unexpected_delta=not gap and previous is not None and previous != current_hash)
                if gap:
                    print(json.dumps({'ssrsf_evidence_gap': invocation, 'function': function_name,
                                      'phase': 'missing-prior-exit'}))
                status = 'failed'
                try:
                    application_event = dict(event)
                    application_event['_ssrsf_correlation_id'] = base['correlation_id']
                    print(json.dumps({'ssrsf_application': {**base, 'type': 'processing_started'}}))
                    result = handler(application_event, context)
                    status = 'completed'
                    return result
                finally:
                    print(json.dumps({'ssrsf_application': {**base, 'type': 'processing_finished',
                                                           'operation_status': status}}))
                    final_hash, final_entries = manifest(root, content=content_hash)
                    emit('exit', manifest_sha256=final_hash, manifest_entries=final_entries,
                         entry_receipt=entry_receipt, operation_status=status)
                    _LAST_MANIFEST[function_name] = final_hash
        return wrapped  # type: ignore[return-value]
    return decorate
