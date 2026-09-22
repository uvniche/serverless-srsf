#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from reference_app.security.iam import expansions, load_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail a deployment on unapproved IAM expansion")
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    parser.add_argument("--approver", default=os.getenv("SRSF_IAM_APPROVER", ""))
    parser.add_argument("--audit-out", type=Path)
    args = parser.parse_args()
    before, after = load_policy(args.baseline), load_policy(args.candidate)
    additions = sorted(expansions(before, after))
    record = {
        "schema": "srsf.iam-gate.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "baseline": before,
        "candidate": after,
        "expansions": [{"action": item.action, "resource": item.resource} for item in additions],
        "approver": args.approver or None,
        "decision": "approved" if not additions or args.approver else "halted",
    }
    line = json.dumps(record, sort_keys=True)
    print(line)
    if args.audit_out:
        # CI should ship this JSONL artifact to the immutable audit delivery path.
        with args.audit_out.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    if additions and not args.approver:
        print("IAM expansion requires a named approver", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

