#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from reference_app.security.footprint import footprint


def main() -> int:
    parser = argparse.ArgumentParser(description="Calculate weighted unused-permission footprint")
    parser.add_argument("inventory", type=Path, help="JSON mapping functions to granted/exercised lists")
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    output = {}
    total = 0
    for function, values in sorted(inventory.items()):
        score, findings = footprint(values.get("granted", []), values.get("exercised", []))
        output[function] = {"score": score, "unused": findings}
        total += score
    print(json.dumps({"total": total, "functions": output}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

