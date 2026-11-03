#!/usr/bin/env python3
"""Interactive CLI for Serverless Site Reliability and Security Framework (SSRSF).

Allows user-driven inputs to test ingestion, extraction, classification,
audit trail, and two-man administrative purge workflows without AWS credentials.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

# Ensure src is in python path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ssrsf.adapters import get_memory_services, local_classify
from ssrsf.config import settings
from ssrsf.handlers import admin_review, approval, classify, extract, ingest, purge, purge_broker, report

# ANSI color codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner() -> None:
    print(f"{CYAN}{BOLD}")
    print("=" * 64)
    print("      SSRSF — Interactive Serverless Security Console       ")
    print("=" * 64)
    print(f"{RESET}{DIM}Local in-memory mode active. Zero AWS credentials required.{RESET}\n")


def ingest_document_flow(svc: Any) -> None:
    print(f"\n{BOLD}--- Step 1: Ingest Document ---{RESET}")
    print("How would you like to provide document input?")
    print("  [1] Type or paste text directly")
    print("  [2] Load from a file path (e.g. .txt, .pdf, .json)")
    choice = input(f"{CYAN}Choice [1/2]: {RESET}").strip()

    filename = "document.txt"
    content_bytes: bytes

    if choice == "2":
        path_str = input(f"{CYAN}Enter file path: {RESET}").strip()
        file_path = Path(path_str).expanduser()
        if not file_path.is_file():
            print(f"{RED}Error: File '{file_path}' does not exist.{RESET}")
            return
        filename = file_path.name
        content_bytes = file_path.read_bytes()
        print(f"{GREEN}Loaded {len(content_bytes)} bytes from {filename}{RESET}")
    else:
        text_input = input(f"{CYAN}Enter text content: {RESET}")
        custom_name = input(f"{CYAN}Enter filename (default: document.txt): {RESET}").strip()
        if custom_name:
            filename = custom_name
        content_bytes = text_input.encode("utf-8")

    # Ingest event (F1)
    event = {
        "body": content_bytes.decode("utf-8", errors="replace"),
        "headers": {"x-filename": filename, "x-correlation-id": "interactive-cli"},
    }
    # If binary / pdf, pass base64
    if not filename.endswith(".txt") and not filename.endswith(".json") and b"%PDF-" in content_bytes[:10]:
        event["isBase64Encoded"] = True
        event["body"] = base64.b64encode(content_bytes).decode("ascii")

    print(f"\n{YELLOW}>> Running F1 (Ingest)...{RESET}")
    res = ingest.handle(event, None, svc)
    if res["statusCode"] not in (200, 202):
        print(f"{RED}Ingest failed ({res['statusCode']}): {res['body']}{RESET}")
        return

    body = json.loads(res["body"])
    doc_id = body["document_id"]
    raw_key = body["key"]
    print(f"{GREEN}✓ Ingested successfully!{RESET}")
    print(f"  • Document ID : {BOLD}{doc_id}{RESET}")
    print(f"  • Raw S3 Key  : {raw_key}")
    print(f"  • SHA-256     : {body['sha256']}")

    # Extract text (F2)
    print(f"\n{YELLOW}>> Running F2 (Extract)...{RESET}")
    extract_event = {
        "Records": [{"s3": {"bucket": {"name": settings.raw_bucket}, "object": {"key": raw_key}}}]
    }
    extract_res = extract.handle(extract_event, None, svc)
    text_key = f"text/{doc_id}.txt"
    extracted_text = svc.get_object(settings.text_bucket, text_key).decode("utf-8", errors="replace")
    print(f"{GREEN}✓ Text extracted successfully ({extract_res.get('processed', 1)} record processed){RESET}")
    preview = (extracted_text[:120] + "...") if len(extracted_text) > 120 else extracted_text
    print(f"  • Text Preview: {DIM}{preview.strip()}{RESET}")

    # Classify content (F3)
    print(f"\n{YELLOW}>> Running F3 (Classify)...{RESET}")
    if svc.messages:
        classify_event = {"Records": [{"body": json.dumps(svc.messages[-1])}]}
        classify.handle(classify_event, None, svc)
        item = svc.get_item(doc_id)
        classification = item.get("classification") if item else "unknown"
        badge = f"{RED}[SENSITIVE]{RESET}" if classification == "sensitive" else f"{GREEN}[GENERAL]{RESET}"
        print(f"{GREEN}✓ Classified & stored in DynamoDB!{RESET}")
        print(f"  • Classification: {BOLD}{badge}")
        print(f"  • DB Record     : {json.dumps(item)}")


def list_documents(svc: Any) -> None:
    print(f"\n{BOLD}--- DynamoDB Document Records ---{RESET}")
    items = svc.scan_items()
    if not items:
        print(f"{DIM}No documents stored in the database yet.{RESET}")
        return

    print(f"{'DOCUMENT ID':<38} | {'CLASSIFICATION':<15} | {'CLASSIFIED AT'}")
    print("-" * 80)
    for it in items:
        doc_id = it.get("document_id", "N/A")
        classification = it.get("classification", "N/A")
        classified_at = it.get("classified_at", "N/A")
        badge = f"{RED}sensitive{RESET}" if classification == "sensitive" else f"{GREEN}general{RESET}"
        print(f"{doc_id:<38} | {badge:<24} | {classified_at}")


def inspect_document(svc: Any) -> None:
    doc_id = input(f"{CYAN}Enter Document ID: {RESET}").strip()
    item = svc.get_item(doc_id)
    if not item:
        print(f"{RED}Document '{doc_id}' not found in database.{RESET}")
        return

    print(f"\n{BOLD}Details for Document: {doc_id}{RESET}")
    print(f"• DynamoDB Item: {json.dumps(item, indent=2)}")

    text_key = f"text/{doc_id}.txt"
    try:
        raw_text = svc.get_object(settings.text_bucket, text_key).decode("utf-8", errors="replace")
        print(f"• Extracted Text:\n{DIM}{raw_text}{RESET}")
    except KeyError:
        print(f"• Extracted Text: {YELLOW}(Not found in S3 bucket {settings.text_bucket}){RESET}")


def purge_workflow(svc: Any) -> None:
    print(f"\n{BOLD}--- Controlled Deletion (Two-Man Rule) ---{RESET}")
    items = svc.scan_items()
    if not items:
        print(f"{RED}No documents available in the database to purge.{RESET}")
        return

    print("Existing documents:")
    for i, it in enumerate(items, 1):
        print(f"  [{i}] {it.get('document_id')} ({it.get('classification')})")

    choice = input(f"{CYAN}Select document number or paste Document ID: {RESET}").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(items):
        doc_id = items[int(choice) - 1]["document_id"]
    else:
        doc_id = choice

    item = svc.get_item(doc_id)
    if not item:
        print(f"{RED}Document not found.{RESET}")
        return

    # Find raw key from objects
    raw_key = None
    for (bucket, key) in svc.objects.keys():
        if bucket == settings.raw_bucket and f"incoming/{doc_id}/" in key:
            raw_key = key
            break

    if not raw_key:
        raw_key = f"incoming/{doc_id}/upload.txt"

    os.environ["ALLOW_LOCAL_ADMIN"] = "1"
    try:
        # Step 1: Admin review (F4)
        print(f"\n{YELLOW}[1/4] Admin reviewing document ({doc_id})...{RESET}")
        review_res = admin_review.handle(
            {"body": json.dumps({"action": "review", "document_id": doc_id})}, None, svc
        )
        print(f"{GREEN}✓ Admin review response: {review_res['body']}{RESET}")

        # Step 2: Independent Approver issues signed token
        print(f"\n{YELLOW}[2/4] Independent Approver generating signed purge token...{RESET}")
        approval_event = {
            "requestContext": {
                "authorizer": {
                    "jwt": {"claims": {"sub": "approver-user", "cognito:groups": ["purge-approvers"]}}
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
        token_data = json.loads(approval_res["body"])
        token = token_data.get("purge_token")
        op_id = token_data.get("operation_id")
        print(f"{GREEN}✓ Purge grant issued!{RESET}")
        print(f"  • Operation ID: {op_id}")
        print(f"  • Purge Token : {token[:35]}... (valid 60 seconds)")

        confirm = input(f"\n{RED}{BOLD}Execute destructive purge via PurgeBroker? (y/n): {RESET}").lower().strip()
        if confirm != "y":
            print(f"{YELLOW}Purge cancelled.{RESET}")
            return

        # Step 3: Admin submits purge to F5
        print(f"\n{YELLOW}[3/4] Admin submitting purge request with token to Purge coordinator (F5)...{RESET}")
        purge_req_res = admin_review.handle(
            {"body": json.dumps({"action": "purge", "document_id": doc_id, "purge_token": token})},
            None,
            svc,
        )
        print(f"{GREEN}✓ Purge coordinator accepted request: {purge_req_res['body']}{RESET}")

        # Step 4: Execute PurgeBroker
        print(f"\n{YELLOW}[4/4] PurgeBroker assuming scoped session and executing deletion...{RESET}")
        if svc.invocations:
            _, broker_event = svc.invocations[-1]
            broker_res = purge_broker.handle(broker_event, None, svc)
            print(f"{GREEN}✓ PurgeBroker completed: {json.dumps(broker_res)}{RESET}")

        # Verify deletion
        if doc_id not in svc.items:
            print(f"\n{GREEN}{BOLD}✓ Verified: Document {doc_id} successfully deleted from DynamoDB and S3!{RESET}")
        else:
            print(f"\n{RED}Warning: Document still present in database.{RESET}")

    finally:
        os.environ.pop("ALLOW_LOCAL_ADMIN", None)


def generate_report_flow(svc: Any) -> None:
    print(f"\n{BOLD}--- Running F6 (Scheduled Report) ---{RESET}")
    res = report.handle({}, None, svc)
    print(f"{GREEN}✓ Report generated successfully!{RESET}")
    print(f"  • Total Documents: {res['documents']}")
    print(f"  • Breakdown      : {json.dumps(res['classifications'])}")
    print(f"  • S3 Report Key  : {res['key']}")


def main() -> None:
    print_banner()
    svc = get_memory_services()

    while True:
        print(f"\n{BOLD}Main Menu:{RESET}")
        print("  [1] Upload / Ingest Document (custom text or file)")
        print("  [2] View stored documents (DynamoDB)")
        print("  [3] Inspect a document's details")
        print("  [4] Admin Review & Purge workflow (Two-Man Rule)")
        print("  [5] Run F6 Report (aggregate statistics)")
        print("  [6] Exit")

        choice = input(f"\n{CYAN}Select option [1-6]: {RESET}").strip()

        if choice == "1":
            ingest_document_flow(svc)
        elif choice == "2":
            list_documents(svc)
        elif choice == "3":
            inspect_document(svc)
        elif choice == "4":
            purge_workflow(svc)
        elif choice == "5":
            generate_report_flow(svc)
        elif choice == "6" or choice.lower() in ("exit", "quit", "q"):
            print(f"\n{CYAN}Goodbye!{RESET}")
            break
        else:
            print(f"{RED}Invalid option, please choose 1-6.{RESET}")


if __name__ == "__main__":
    main()

