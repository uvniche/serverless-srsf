from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

from .adapters import services
from .config import settings
from .handlers import admin_review, approval, classify, extract, ingest, purge, purge_broker, report
from .server import process_local_pipeline, run_server


def cmd_serve(args: argparse.Namespace) -> int:
    run_server(host=args.host, port=args.port)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    svc = services()
    content_bytes: bytes
    filename = args.filename or "document.txt"

    target = Path(args.input).expanduser() if args.input else None
    if target and target.is_file():
        content_bytes = target.read_bytes()
        if not args.filename:
            filename = target.name
    elif args.input:
        content_bytes = args.input.encode("utf-8")
    else:
        print("Reading from standard input...")
        content_bytes = sys.stdin.buffer.read()

    event: dict[str, Any] = {
        "body": content_bytes.decode("utf-8", errors="replace"),
        "headers": {"x-filename": filename, "x-correlation-id": "cli-ingest"},
    }
    if b"%PDF-" in content_bytes[:10]:
        event["isBase64Encoded"] = True
        event["body"] = base64.b64encode(content_bytes).decode("ascii")

    res = ingest.handle(event, None, svc)
    body = json.loads(res["body"]) if isinstance(res.get("body"), str) else res
    doc_id = body.get("document_id")

    if doc_id and settings.is_local:
        pipeline = process_local_pipeline(doc_id, body["key"], svc)
        body["classification"] = pipeline.get("item", {}).get("classification")

    print(json.dumps(body, indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    svc = services()
    items = svc.scan_items()
    if not items:
        print("No documents found in database.")
        return 0
    print(json.dumps(items, indent=2))
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    svc = services()
    doc_id = args.document_id
    raw_key = f"incoming/{doc_id}/upload.txt"

    os.environ["ALLOW_LOCAL_ADMIN"] = "1"
    try:
        # Step 1: Request purge approval
        approval_event = {
            "requestContext": {
                "authorizer": {
                    "jwt": {"claims": {"sub": "cli-admin", "cognito:groups": ["purge-approvers"]}}
                }
            },
            "body": json.dumps({
                "document_id": doc_id,
                "raw_key": raw_key,
                "raw_version": "v1",
                "text_version": "v1",
            }),
        }
        app_res = approval.handle(approval_event, None, svc)
        app_data = json.loads(app_res["body"])
        token = app_data["purge_token"]

        # Step 2: Request purge
        purge_res = admin_review.handle(
            {"body": json.dumps({"action": "purge", "document_id": doc_id, "purge_token": token})},
            None,
            svc,
        )
        res_data = json.loads(purge_res["body"])

        if settings.is_local and hasattr(svc, "invocations") and svc.invocations:
            _, f5_event = svc.invocations[0]
            purge.handle(f5_event, None, svc)
            _, broker_event = svc.invocations[-1]
            broker_res = purge_broker.handle(broker_event, None, svc)
            res_data["broker_result"] = broker_res
            res_data["purged"] = doc_id not in svc.items

        print(json.dumps(res_data, indent=2))
        return 0
    finally:
        os.environ.pop("ALLOW_LOCAL_ADMIN", None)


def cmd_report(args: argparse.Namespace) -> int:
    svc = services()
    res = report.handle({}, None, svc)
    print(json.dumps(res, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ssrsf",
        description="Serverless Site Reliability and Security Framework (SSRSF) Application",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "aws"],
        default=None,
        help="Operating mode: 'local' (offline in-memory for testing) or 'aws' (cloud). Defaults to SSRSF_MODE or 'local'.",
    )

    subparsers = parser.add_subparsers(dest="command")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Run local server and web console (default)")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")

    # ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest a document from string or file")
    ingest_parser.add_argument("input", nargs="?", help="Text string or path to document file")
    ingest_parser.add_argument("--filename", help="Optional filename override")

    # list command
    subparsers.add_parser("list", help="List all documents in the database")

    # purge command
    purge_parser = subparsers.add_parser("purge", help="Execute two-man admin purge on a document")
    purge_parser.add_argument("document_id", help="Document ID to purge")

    # report command
    subparsers.add_parser("report", help="Generate document aggregation report")

    args = parser.parse_args(argv)

    if args.mode:
        os.environ["SSRSF_MODE"] = args.mode

    if not args.command or args.command == "serve":
        return cmd_serve(args if args.command == "serve" else argparse.Namespace(host="127.0.0.1", port=8000))
    elif args.command == "ingest":
        return cmd_ingest(args)
    elif args.command == "list":
        return cmd_list(args)
    elif args.command == "purge":
        return cmd_purge(args)
    elif args.command == "report":
        return cmd_report(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

