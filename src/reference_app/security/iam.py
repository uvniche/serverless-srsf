from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True, order=True)
class Grant:
    action: str
    resource: str


def _items(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else value


def effective_grants(policy: Mapping[str, Any]) -> set[Grant]:
    grants: set[Grant] = set()
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow" or "NotAction" in statement or "NotResource" in statement:
            continue
        for action in _items(statement.get("Action")):
            for resource in _items(statement.get("Resource", "*")):
                grants.add(Grant(action.lower(), resource))
    return grants


def _covers(pattern: str, value: str) -> bool:
    """Conservative coverage for AWS wildcard grants; ambiguous cases fail closed."""
    if pattern == "*" or pattern == value:
        return True
    if pattern.endswith("*") and "?" not in pattern and "*" not in pattern[:-1]:
        return value.startswith(pattern[:-1])
    return fnmatch.fnmatchcase(value, pattern) and "*" not in value and "?" not in value


def expansions(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> set[Grant]:
    before = effective_grants(baseline)
    after = effective_grants(candidate)
    return {grant for grant in after if not any(
        _covers(old.action, grant.action) and _covers(old.resource, grant.resource) for old in before
    )}


def configuration_hash(configuration: Mapping[str, Any]) -> str:
    data = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def load_policy(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)

