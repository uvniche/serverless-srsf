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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TypeVar

F = TypeVar("F", bound=Callable[..., Any])
_LOCK = threading.Lock()
_ENVIRONMENT_ID = str(uuid.uuid4())
_INITIALIZED: set[str] = set()
_LAST_MANIFEST: dict[str, str] = {}


class AuditSink(Protocol):
    def emit(self, record: Mapping[str, Any]) -> None: ...


class StdoutAuditSink:
    def emit(self, record: Mapping[str, Any]) -> None:
        print(json.dumps({"srsf_audit": record}, sort_keys=True, separators=(",", ":")))


class FirehoseAuditSink:
    """Write-only delivery to an object-locked S3 destination via Firehose."""

    def __init__(self, stream_name: str):
        self.stream_name = stream_name

    def emit(self, record: Mapping[str, Any]) -> None:
        import boto3  # available in AWS Lambda; intentionally not a local dependency

        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        boto3.client("firehose").put_record(
            DeliveryStreamName=self.stream_name, Record={"Data": payload}
        )


def default_sink() -> AuditSink:
    stream = os.getenv("AUDIT_STREAM", "")
    return FirehoseAuditSink(stream) if stream else StdoutAuditSink()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def manifest(root: str | Path | None = None, *, content: bool = False) -> tuple[str, list[dict[str, Any]]]:
    base = Path(root or tempfile.gettempdir())
    entries: list[dict[str, Any]] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        stat = path.stat()
        item: dict[str, Any] = {
            "path": str(path.relative_to(base)),
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }
        if content:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            item["content_sha256"] = digest.hexdigest()
        entries.append(item)
    return _hash_json(entries), entries


def environment_digest(env: Mapping[str, str] | None = None) -> str:
    source = env or os.environ
    # Values are never emitted. Hashing names with value digests still catches changes.
    return _hash_json({key: hashlib.sha256(value.encode()).hexdigest() for key, value in sorted(source.items())})


def dependencies() -> list[str]:
    try:
        return sorted(f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions())
    except Exception:
        return []


def _correlation_id(event: Mapping[str, Any], context: Any) -> str:
    headers = event.get("headers") or {}
    supplied = headers.get("x-correlation-id") or headers.get("X-Correlation-Id")
    return str(supplied or getattr(context, "aws_request_id", "") or uuid.uuid4())


def instrument(function_name: str, *, content_hash: bool = False, sink: AuditSink | None = None) -> Callable[[F], F]:
    """Emit cold-start/delta evidence before a handler runs and a completion heartbeat after it."""

    audit = sink or default_sink()

    def decorate(handler: F) -> F:
        @functools.wraps(handler)
        def wrapped(event: Mapping[str, Any], context: Any) -> Any:
            correlation_id = _correlation_id(event, context)
            current_hash, entries = manifest(content=content_hash)
            with _LOCK:
                cold = function_name not in _INITIALIZED
                previous = _LAST_MANIFEST.get(function_name)
                _INITIALIZED.add(function_name)
            base = {
                "schema": "srsf.ebe.v1",
                "timestamp_ms": int(time.time() * 1000),
                "function": function_name,
                "function_version": os.getenv("AWS_LAMBDA_FUNCTION_VERSION", "local"),
                "environment_id": _ENVIRONMENT_ID,
                "correlation_id": correlation_id,
                "runtime": platform.python_version(),
                "manifest_sha256": current_hash,
            }
            if cold:
                audit.emit({
                    **base,
                    "type": "initialization",
                    "environment_sha256": environment_digest(),
                    "dependencies": dependencies(),
                    "manifest_entries": entries,
                })
            else:
                audit.emit({
                    **base,
                    "type": "invocation_delta",
                    "previous_manifest_sha256": previous,
                    "unexpected_delta": previous is not None and previous != current_hash,
                    "manifest_entries": entries,
                })
            try:
                return handler(dict(event), context)
            finally:
                final_hash, _ = manifest(content=content_hash)
                with _LOCK:
                    _LAST_MANIFEST[function_name] = final_hash
                audit.emit({
                    "schema": "srsf.ebe.v1",
                    "type": "heartbeat",
                    "timestamp_ms": int(time.time() * 1000),
                    "function": function_name,
                    "environment_id": _ENVIRONMENT_ID,
                    "correlation_id": correlation_id,
                    "manifest_sha256": final_hash,
                })

        return wrapped  # type: ignore[return-value]

    return decorate

