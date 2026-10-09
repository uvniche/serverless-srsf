from __future__ import annotations

import re
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


def _aws_match(pattern: str, value: str) -> bool:
    # AWS wildcards are only * and ?; shell character classes are literal.
    return re.fullmatch(re.escape(pattern).replace(r"\*", ".*").replace(r"\?", "."), value) is not None


def _covers(pattern: str, value: str) -> bool:
    """Conservative coverage for AWS wildcard grants; ambiguous cases fail closed."""
    if pattern == "*" or pattern == value:
        return True
    if pattern.endswith("*") and "?" not in pattern and "*" not in pattern[:-1]:
        return value.startswith(pattern[:-1])
    return _aws_match(pattern, value) and "*" not in value and "?" not in value


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



EVALUATOR_VERSION = 'ssrsf-bounded-iam.v1'
POLICY_FIELDS = ('identity', 'resource', 'boundaries', 'session', 'organization')


def authorization_decision(snapshot: Mapping[str, Any], request: Mapping[str, Any]) -> str:
    """Bounded same-account role evaluator. Unsupported semantics explicitly abstain.

    Resource-based grants, NotAction/NotResource, principal policies and cross-account
    evaluation require provider-backed review. Empty limiting-policy lists mean absent.
    """
    if snapshot.get('scope') != 'same-account-role' or any(k not in snapshot for k in POLICY_FIELDS):
        return 'unresolved'
    if not snapshot.get('principal') or snapshot['resource'] or request.get('principal') != snapshot.get('principal'):
        return 'unresolved'
    if any(k not in request for k in ('action', 'resource', 'context')):
        return 'unresolved'
    all_matches: dict[str, list[tuple[bool, bool]]] = {}
    try:
        for field in POLICY_FIELDS:
            policies = snapshot[field]
            if not isinstance(policies, list):
                return 'unresolved'
            matches = []
            for policy in policies:
                statements = policy.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                allow = deny = False
                for statement in statements:
                    if set(statement) - {'Sid', 'Effect', 'Action', 'Resource', 'Condition'}:
                        return 'unresolved'
                    if statement.get('Effect') not in ('Allow', 'Deny'):
                        return 'unresolved'
                    if 'Action' not in statement or 'Resource' not in statement:
                        return 'unresolved'
                    if any('${' in r for r in _items(statement['Resource'])):
                        return 'unresolved'
                    conditions = statement.get('Condition', {})
                    condition_matches = True
                    for operator, terms in conditions.items():
                        if operator not in ('StringEquals', 'ArnEquals', 'Bool'):
                            return 'unresolved'
                        for key, expected in terms.items():
                            if key not in request['context']:
                                return 'unresolved'
                            actual = str(request['context'][key])
                            values = [str(x) for x in _items(expected)]
                            if operator == 'Bool':
                                actual, values = actual.lower(), [x.lower() for x in values]
                                if actual not in ('true', 'false') or any(x not in ('true', 'false') for x in values):
                                    return 'unresolved'
                            condition_matches &= actual in values
                    match = (condition_matches
                             and any(_aws_match(a.lower(), request['action'].lower())
                                     for a in _items(statement.get('Action')))
                             and any(_aws_match(r, request['resource'])
                                     for r in _items(statement.get('Resource'))))
                    if match:
                        allow |= statement['Effect'] == 'Allow'
                        deny |= statement['Effect'] == 'Deny'
                matches.append((allow, deny))
            all_matches[field] = matches
    except (TypeError, AttributeError, KeyError):
        return 'unresolved'
    if any(deny for matches in all_matches.values() for _, deny in matches):
        return 'deny'
    if not any(allow for allow, _ in all_matches['identity']):
        return 'deny'
    for field in ('boundaries', 'session', 'organization'):
        if any(not allow for allow, _ in all_matches[field]):
            return 'deny'
    return 'allow'


def compare_authorization(before: Mapping[str, Any], after: Mapping[str, Any],
                          catalogue: list[dict[str, Any]]) -> dict[str, Any]:
    matrix = [{'request': r, 'production': authorization_decision(before, r),
               'candidate': authorization_decision(after, r)} for r in catalogue]
    unresolved = []
    if not catalogue:
        unresolved.append('empty request catalogue')
    if any(row['production'] == 'unresolved' or row['candidate'] == 'unresolved' for row in matrix):
        unresolved.append('missing inputs or unsupported authorization semantics')
    # Finite catalogue cannot establish changed wildcard or conditional scopes.
    # Only changed exact action/resource pairs represented in the catalogue clear automatically.
    represented = {(r.get('action', '').lower(), r.get('resource')) for r in catalogue}
    if before != after:
        try:
            for field in POLICY_FIELDS:
                if before.get(field) == after.get(field):
                    continue
                for snapshot in (before, after):
                    for policy in snapshot[field]:
                        statements = policy.get('Statement', [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        for statement in statements:
                            if statement.get('Condition'):
                                unresolved.append('changed conditional scope requires coverage review')
                            for action in _items(statement.get('Action')):
                                for resource in _items(statement.get('Resource')):
                                    if any(c in action + resource for c in '*?') or (action.lower(), resource) not in represented:
                                        unresolved.append('policy change extends beyond finite catalogue')
        except (KeyError, TypeError, AttributeError):
            unresolved.append('incomplete policy snapshots')
    return {'evaluator_version': EVALUATOR_VERSION, 'coverage': 'finite same-account role requests only',
            'matrix': matrix, 'unresolved': sorted(set(unresolved)),
            'expansions': [row['request'] for row in matrix
                           if row['production'] == 'deny' and row['candidate'] == 'allow']}
