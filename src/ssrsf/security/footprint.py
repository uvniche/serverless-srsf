from __future__ import annotations

from collections.abc import Iterable


DESTRUCTIVE = ("delete", "purge", "terminate", "disable", "remove", "kms:schedulekeydeletion")
MUTATING = ("put", "create", "update", "write", "invoke", "send", "publish", "start", "stop")


def weight(permission: str) -> int:
    lowered = permission.lower()
    if any(word in lowered for word in DESTRUCTIVE):
        return 10
    if any(word in lowered for word in MUTATING):
        return 3
    return 1


def unused_permissions(granted: Iterable[str], exercised: Iterable[str]) -> set[str]:
    used = {item.lower() for item in exercised}
    return {item for item in granted if item.lower() not in used}


def footprint(granted: Iterable[str], exercised: Iterable[str]) -> tuple[int, list[dict[str, object]]]:
    findings = [{"permission": p, "weight": weight(p)} for p in sorted(unused_permissions(granted, exercised))]
    return sum(int(f["weight"]) for f in findings), findings

