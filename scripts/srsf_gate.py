#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from ssrsf.security.iam import compare_authorization, configuration_hash, load_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail a deployment on unapproved IAM expansion")
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--config-start", type=Path)
    parser.add_argument("--config-end", type=Path)
    parser.add_argument("--approver", default=os.getenv("SRSF_IAM_APPROVER", ""))
    parser.add_argument("--audit-out", type=Path)
    args = parser.parse_args()
    before, after = load_policy(args.baseline), load_policy(args.candidate)
    with args.catalogue.open() as handle:
        catalogue = json.load(handle)
    comparison = compare_authorization(before, after, catalogue)
    config_hashes = None
    if bool(args.config_start) != bool(args.config_end):
        comparison["unresolved"].append("both configuration snapshots required")
    elif args.config_start:
        config_hashes = [configuration_hash(load_policy(p)) for p in (args.config_start, args.config_end)]
        if config_hashes[0] != config_hashes[1]:
            comparison["unresolved"].append("security configuration changed during rollout")
    needs_review = bool(comparison["expansions"] or comparison["unresolved"])
    record = {
        "schema": "ssrsf.iam-gate.v2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "baseline": before,
        "candidate": after,
        "comparison": comparison,
        "configuration_hashes": config_hashes,
        "approver": args.approver or None,
        "decision": "reviewed" if needs_review and args.approver else ("halted" if needs_review else "cleared-within-coverage"),
    }
    line = json.dumps(record, sort_keys=True)
    print(line)
    if args.audit_out:
        # CI should ship this JSONL artifact to the immutable audit delivery path.
        with args.audit_out.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    if needs_review and not args.approver:
        print("IAM expansion or unresolved coverage requires a named reviewer", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

