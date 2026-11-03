from __future__ import annotations

import io
import json
import logging
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .adapters import services
from .config import settings
from .handlers import admin_review, approval, classify, extract, ingest, purge, purge_broker, report

logger = logging.getLogger("ssrsf.server")


def process_local_pipeline(document_id: str, raw_key: str, svc: Any) -> dict[str, Any]:
    """Simulates S3 and SQS triggers locally after document ingestion."""
    # F2: Extract
    extract_event = {
        "Records": [{"s3": {"bucket": {"name": settings.raw_bucket}, "object": {"key": raw_key}}}]
    }
    extract_res = extract.handle(extract_event, None, svc)

    # F3: Classify (from enqueued SQS message)
    classify_res = {}
    if hasattr(svc, "messages") and svc.messages:
        classify_event = {"Records": [{"body": json.dumps(svc.messages[-1])}]}
        classify_res = classify.handle(classify_event, None, svc)

    item = svc.get_item(document_id) or {}
    return {
        "extract": extract_res,
        "classify": classify_res,
        "item": item,
    }


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSRSF - Serverless Security Console</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --primary: #38bdf8;
      --accent: #22c55e;
      --danger: #ef4444;
      --warning: #f59e0b;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      color: var(--primary);
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-mode {
      background: #0369a1;
      color: #e0f2fe;
    }
    .badge-sensitive {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }
    .badge-general {
      background: rgba(34, 197, 94, 0.2);
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 20px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }
    h2 {
      font-size: 18px;
      margin-top: 0;
      margin-bottom: 12px;
      color: var(--text);
    }
    label {
      display: block;
      font-size: 13px;
      color: var(--muted);
      margin-bottom: 6px;
    }
    input[type="text"], textarea {
      width: 100%;
      background: #0f172a;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 10px;
      border-radius: 6px;
      box-sizing: border-box;
      margin-bottom: 12px;
      font-family: inherit;
    }
    button {
      background: var(--primary);
      color: #0f172a;
      border: none;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.9; }
    button.btn-danger {
      background: var(--danger);
      color: white;
      padding: 4px 10px;
      font-size: 12px;
    }
    button.btn-outline {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 14px;
    }
    th, td {
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
    }
    pre {
      background: #0f172a;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 12px;
      border: 1px solid var(--border);
    }
    .empty {
      color: var(--muted);
      text-align: center;
      padding: 30px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>SSRSF Control Console</h1>
        <div style="font-size: 13px; color: var(--muted); margin-top: 4px;">Serverless Site Reliability & Security Framework</div>
      </div>
      <div>
        <span class="badge badge-mode">Mode: {{MODE}}</span>
      </div>
    </header>

    <div class="grid">
      <!-- Ingest Card -->
      <div class="card">
        <h2>1. Ingest Document</h2>
        <form id="ingest-form" onsubmit="handleIngest(event)">
          <label>Document Filename</label>
          <input type="text" id="filename" placeholder="e.g. security-plan.txt" value="sample.txt" required>
          
          <label>Content (Text or Paste)</label>
          <textarea id="content" rows="4" placeholder="Enter document content here... (Tip: include 'secret' or 'confidential' to test sensitivity classification)">Confidential quarterly infrastructure operational report.</textarea>
          
          <div style="display: flex; gap: 10px; align-items: center;">
            <button type="submit" id="submit-btn">Ingest & Process</button>
            <span id="ingest-status" style="font-size: 13px;"></span>
          </div>
        </form>
      </div>

      <!-- Live Database Table -->
      <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h2 style="margin: 0;">2. Database Records (DynamoDB)</h2>
          <div style="display: flex; gap: 8px;">
            <button class="btn-outline" onclick="loadDocuments()">↻ Refresh</button>
            <button class="btn-outline" onclick="loadReport()">📊 System Report</button>
          </div>
        </div>
        <div id="docs-container">Loading documents...</div>
      </div>

      <!-- System Report Output -->
      <div id="report-card" class="card" style="display: none;">
        <h2>3. Aggregated Report (F6)</h2>
        <pre id="report-output"></pre>
      </div>
    </div>
  </div>

  <script>
    async function loadDocuments() {
      const res = await fetch('/documents');
      const docs = await res.json();
      const container = document.getElementById('docs-container');
      
      if (!docs || docs.length === 0) {
        container.innerHTML = '<div class="empty">No documents in the database yet. Ingest one above!</div>';
        return;
      }

      let html = '<table><thead><tr><th>Document ID</th><th>Classification</th><th>Classified At</th><th>Action</th></tr></thead><tbody>';
      for (const d of docs) {
        const isSensitive = d.classification === 'sensitive';
        const badge = isSensitive 
          ? '<span class="badge badge-sensitive">Sensitive</span>' 
          : '<span class="badge badge-general">General</span>';
        
        html += `<tr>
          <td><code style="color: var(--primary);">${d.document_id}</code></td>
          <td>${badge}</td>
          <td style="color: var(--muted); font-size: 12px;">${d.classified_at || 'N/A'}</td>
          <td>
            <button class="btn-danger" onclick="purgeDocument('${d.document_id}')">Controlled Purge</button>
          </td>
        </tr>`;
      }
      html += '</tbody></table>';
      container.innerHTML = html;
    }

    async function handleIngest(e) {
      e.preventDefault();
      const btn = document.getElementById('submit-btn');
      const status = document.getElementById('ingest-status');
      const filename = document.getElementById('filename').value;
      const content = document.getElementById('content').value;

      btn.disabled = true;
      status.style.color = 'var(--muted)';
      status.innerText = 'Ingesting and processing...';

      try {
        const res = await fetch('/documents', {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'x-filename': filename
          },
          body: content
        });
        const data = await res.json();
        status.style.color = 'var(--accent)';
        status.innerText = `✓ Processed (${data.document_id.slice(0, 8)}...) - Classification: ${data.classification || 'general'}`;
        loadDocuments();
      } catch (err) {
        status.style.color = 'var(--danger)';
        status.innerText = 'Error: ' + err.message;
      } finally {
        btn.disabled = false;
      }
    }

    async function purgeDocument(docId) {
      if (!confirm(`Execute controlled two-man purge for document: ${docId}?`)) return;
      try {
        // Step 1: Request approval token
        const appRes = await fetch('/admin/approve-purge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ document_id: docId })
        });
        const appData = await appRes.json();
        
        // Step 2: Execute purge with token
        const purgeRes = await fetch('/admin/purge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'purge',
            document_id: docId,
            purge_token: appData.purge_token
          })
        });
        const purgeData = await purgeRes.json();
        alert('Purge successful: ' + JSON.stringify(purgeData));
        loadDocuments();
      } catch (err) {
        alert('Purge failed: ' + err.message);
      }
    }

    async function loadReport() {
      const res = await fetch('/report');
      const data = await res.json();
      const card = document.getElementById('report-card');
      const pre = document.getElementById('report-output');
      card.style.display = 'block';
      pre.innerText = JSON.stringify(data, null, 2);
    }

    loadDocuments();
  </script>
</body>
</html>
"""


class SSRSFRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        svc = services()

        if path == "/" or path == "/index.html":
            html = HTML_DASHBOARD.replace("{{MODE}}", settings.mode.upper())
            content = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/documents":
            items = svc.scan_items()
            self._send_json(200, items)
            return

        if path.startswith("/documents/"):
            doc_id = path.removeprefix("/documents/")
            item = svc.get_item(doc_id)
            if not item:
                self._send_json(404, {"error": "Document not found"})
                return
            text_key = f"text/{doc_id}.txt"
            extracted_text = ""
            try:
                extracted_text = svc.get_object(settings.text_bucket, text_key).decode("utf-8", errors="replace")
            except Exception:
                pass
            self._send_json(200, {"item": item, "text": extracted_text})
            return

        if path == "/report":
            res = report.handle({}, None, svc)
            self._send_json(200, res)
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        svc = services()

        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b""

        if path == "/documents":
            # Ingest F1
            filename = self.headers.get("x-filename", "upload.txt")
            event = {
                "body": body_bytes.decode("utf-8", errors="replace"),
                "headers": {"x-filename": filename, "x-correlation-id": "server-request"},
            }
            res = ingest.handle(event, None, svc)
            data = json.loads(res["body"]) if isinstance(res.get("body"), str) else res

            # Auto-run local pipeline stages (F2 & F3) for local mode
            if settings.is_local and "document_id" in data:
                pipeline_out = process_local_pipeline(data["document_id"], data["key"], svc)
                data["classification"] = pipeline_out.get("item", {}).get("classification", "unknown")

            self._send_json(res.get("statusCode", 202), data)
            return

        if path == "/admin/approve-purge":
            # Independent approval route
            body_dict = {}
            if body_bytes:
                try:
                    body_dict = json.loads(body_bytes.decode("utf-8"))
                except Exception:
                    pass

            doc_id = body_dict.get("document_id", "")
            raw_key = body_dict.get("raw_key", f"incoming/{doc_id}/upload.txt")
            event = {
                "requestContext": {
                    "authorizer": {
                        "jwt": {"claims": {"sub": "local-approver", "cognito:groups": ["purge-approvers"]}}
                    }
                },
                "body": json.dumps({
                    "document_id": doc_id,
                    "raw_key": raw_key,
                    "raw_version": body_dict.get("raw_version", "v1"),
                    "text_version": body_dict.get("text_version", "v1"),
                }),
            }
            res = approval.handle(event, None, svc)
            data = json.loads(res["body"]) if isinstance(res.get("body"), str) else res
            self._send_json(res.get("statusCode", 200), data)
            return

        if path == "/admin/purge":
            # Admin review & purge route
            os.environ["ALLOW_LOCAL_ADMIN"] = "1"
            try:
                event = {"body": body_bytes.decode("utf-8", errors="replace")}
                res = admin_review.handle(event, None, svc)
                data = json.loads(res["body"]) if isinstance(res.get("body"), str) else res

                # In local mode, coordinate F5 & PurgeBroker automatically
                if settings.is_local and isinstance(data, dict) and data.get("status") == "purge_requested":
                    if hasattr(svc, "invocations") and svc.invocations:
                        # F5 coordinator
                        _, f5_event = svc.invocations[0]
                        purge.handle(f5_event, None, svc)
                        # Purge broker
                        _, broker_event = svc.invocations[-1]
                        broker_res = purge_broker.handle(broker_event, None, svc)
                        data["broker_result"] = broker_res
                        data["purged"] = True

                self._send_json(res.get("statusCode", 200), data)
            finally:
                os.environ.pop("ALLOW_LOCAL_ADMIN", None)
            return

        self._send_json(404, {"error": "Not found"})


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = HTTPServer((host, port), SSRSFRequestHandler)
    print("=" * 64)
    print(f"  SSRSF Server running in {settings.mode.upper()} mode")
    print(f"  Local Web Console: http://{host}:{port}/")
    print("=" * 64)
    print("Available API Endpoints:")
    print(f"  • POST http://{host}:{port}/documents")
    print(f"  • GET  http://{host}:{port}/documents")
    print(f"  • GET  http://{host}:{port}/documents/<id>")
    print(f"  • POST http://{host}:{port}/admin/approve-purge")
    print(f"  • POST http://{host}:{port}/admin/purge")
    print(f"  • GET  http://{host}:{port}/report")
    print("\nPress Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()
