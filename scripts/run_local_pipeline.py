#!/usr/bin/env python3
"""Run the complete document processing pipeline locally without AWS credentials."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ssrsf.adapters import reset_services
from ssrsf.config import settings
from ssrsf.handlers import admin_review, approval, classify, extract, ingest, purge, purge_broker, report


def run_pipeline(content: str = "Confidential quarterly operational report and plans",
                 filename: str = "plan.txt",
                 as_admin: bool = True) -> dict[str, Any]:
    """Execute all pipeline steps locally in sequence."""
    svc = reset_services()
    results: dict[str, Any] = {}

    # 1. Ingest document (F1)
    ingest_event = {
        "body": content,
        "headers": {"x-filename": filename, "x-correlation-id": "local-run-1"},
    }
    ingest_res = ingest.handle(ingest_event, None, svc)
    ingest_data = json.loads(ingest_res["body"])
    doc_id = ingest_data["document_id"]
    raw_key = ingest_data["key"]
    results["1_ingest"] = {
        "statusCode": ingest_res["statusCode"],
        "document_id": doc_id,
        "key": raw_key,
        "sha256": ingest_data["sha256"],
    }

    # 2. Extract text (F2)
    extract_event = {
        "Records": [{"s3": {"bucket": {"name": settings.raw_bucket}, "object": {"key": raw_key}}}]
    }
    extract_res = extract.handle(extract_event, None, svc)
    results["2_extract"] = extract_res

    # 3. Classify content (F3)
    classify_event = {"Records": [{"body": json.dumps(svc.messages[-1])}]}
    classify_res = classify.handle(classify_event, None, svc)
    item = svc.get_item(doc_id)
    results["3_classify"] = {
        "processed": classify_res["processed"],
        "classification": item.get("classification") if item else None,
    }

    # 4. Generate report (F6)
    report_res = report.handle({}, None, svc)
    results["4_report"] = {
        "documents": report_res["documents"],
        "classifications": report_res["classifications"],
        "key": report_res["key"],
    }

    if as_admin:
        # 5. Admin Review (F4)
        old_admin = os.environ.get("ALLOW_LOCAL_ADMIN")
        os.environ["ALLOW_LOCAL_ADMIN"] = "1"
        try:
            review_res = admin_review.handle(
                {"body": json.dumps({"action": "review", "document_id": doc_id})}, None, svc
            )
            results["5_review"] = json.loads(review_res["body"])

            # 6. Approve Purge (Independent Approval Service)
            approval_event = {
                "requestContext": {
                    "authorizer": {
                        "jwt": {"claims": {"sub": "local-admin-1", "cognito:groups": ["purge-approvers"]}}
                    }
                },
                "body": json.dumps({
                    "document_id": doc_id,
                    "raw_key": raw_key,
                    "raw_version": "v1",
                    "text_version": "v1",
                }),
            }
            approval_res = approval.handle(approval_event, None, svc)
            token = json.loads(approval_res["body"])["purge_token"]
            results["6_approval"] = {"purge_token_issued": bool(token)}

            # 7. Request Purge through Admin Review (F4 -> F5)
            purge_req_res = admin_review.handle(
                {"body": json.dumps({"action": "purge", "document_id": doc_id, "purge_token": token})},
                None,
                svc,
            )
            results["7_purge_requested"] = json.loads(purge_req_res["body"])

            # 8. Coordinate Purge (F5 -> PurgeBroker)
            _, f5_event = svc.invocations[0]
            purge.handle(f5_event, None, svc)

            # 9. Execute Purge by PurgeBroker
            _, broker_event = svc.invocations[-1]
            broker_res = purge_broker.handle(broker_event, None, svc)
            results["8_broker_purge"] = broker_res
            results["9_verified_purged"] = doc_id not in svc.items
        finally:
            if old_admin is None:
                os.environ.pop("ALLOW_LOCAL_ADMIN", None)
            else:
                os.environ["ALLOW_LOCAL_ADMIN"] = old_admin

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--content", default="Confidential project roadmap for local execution", help="Document content")
    parser.add_argument("--filename", default="roadmap.txt", help="Filename")
    parser.add_argument("--no-purge", action="store_true", help="Skip review and purge steps")
    args = parser.parse_args()

    results = run_pipeline(content=args.content, filename=args.filename, as_admin=not args.no_purge)
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

