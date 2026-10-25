from __future__ import annotations

import json
import os
import unittest

from ssrsf.adapters import MemoryServices, reset_services, services
from ssrsf.config import settings
from ssrsf.handlers import admin_review, approval, classify, extract, ingest, purge, purge_broker, rate_monitor, report
from ssrsf.security import ebe


class LocalExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_services()

    def test_services_returns_memory_services_without_credentials(self) -> None:
        svc = services()
        self.assertIsInstance(svc, MemoryServices)
        svc.put_object("b1", "k1", b"hello")
        self.assertEqual(svc.get_object("b1", "k1"), b"hello")

    def test_default_audit_sink_is_local_and_acknowledges(self) -> None:
        sink = ebe.default_sink()
        self.assertIsInstance(sink, ebe.LocalAuditSink)
        receipt = ebe.acknowledge(sink, {"function": "local-test", "type": "entry", "idempotency_key": "k1"})
        self.assertTrue(receipt.startswith("evidence/"))
        self.assertTrue(receipt.endswith(":local-v1"))

    def test_lambda_handlers_work_locally_without_aws_credentials(self) -> None:
        # F1 Ingest lambda_handler
        res = ingest.lambda_handler({"body": "secret document content", "headers": {"x-filename": "doc.txt"}}, None)
        self.assertEqual(res["statusCode"], 202)
        body = json.loads(res["body"])
        doc_id = body["document_id"]
        key = body["key"]

        # F2 Extract lambda_handler
        ext_res = extract.lambda_handler({
            "Records": [{"s3": {"bucket": {"name": settings.raw_bucket}, "object": {"key": key}}}]
        }, None)
        self.assertEqual(ext_res["processed"], 1)

        # F3 Classify lambda_handler
        svc = services()
        self.assertTrue(len(svc.messages) > 0)
        cls_res = classify.lambda_handler({"Records": [{"body": json.dumps(svc.messages[-1])}]}, None)
        self.assertEqual(cls_res["processed"], 1)
        item = svc.get_item(doc_id)
        self.assertIsNotNone(item)
        self.assertEqual(item["classification"], "sensitive")

        # F6 Report lambda_handler
        rep_res = report.lambda_handler({}, None)
        self.assertEqual(rep_res["documents"], 1)

        # SRSF-RateMonitor lambda_handler
        rate_res = rate_monitor.lambda_handler({}, None)
        self.assertIn("checked", rate_res)


if __name__ == "__main__":
    unittest.main()

