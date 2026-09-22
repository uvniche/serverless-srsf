from __future__ import annotations

import json
import os
import unittest

from reference_app.adapters import MemoryServices
from reference_app.config import settings
from reference_app.handlers import admin_review, classify, extract, ingest, purge, report


class PipelineTests(unittest.TestCase):
    def test_end_to_end_and_purge(self) -> None:
        svc = MemoryServices()
        accepted = ingest.handle({"body": "confidential quarterly plan", "headers": {"x-filename": "plan.txt"}}, None, svc)
        body = json.loads(accepted["body"])
        self.assertEqual(accepted["statusCode"], 202)

        extracted = extract.handle({"Records": [{"s3": {"bucket": {"name": settings.raw_bucket},
            "object": {"key": body["key"]}}}]}, None, svc)
        self.assertEqual(extracted["processed"], 1)
        self.assertEqual(len(svc.messages), 1)

        classified = classify.handle({"Records": [{"body": json.dumps(svc.messages[0])}]}, None, svc)
        self.assertEqual(classified["processed"], 1)
        self.assertEqual(svc.items[body["document_id"]]["classification"], "sensitive")

        generated = report.handle({}, None, svc)
        self.assertEqual(generated["documents"], 1)

        old = os.environ.get("ALLOW_LOCAL_ADMIN")
        os.environ["ALLOW_LOCAL_ADMIN"] = "1"
        try:
            lookup = admin_review.handle({"body": json.dumps({"action": "review", "document_id": body["document_id"]})}, None, svc)
            self.assertEqual(lookup["statusCode"], 200)
            review = admin_review.handle({"body": json.dumps({"action": "purge", "document_id": body["document_id"],
                "raw_key": body["key"]})}, None, svc)
        finally:
            if old is None:
                os.environ.pop("ALLOW_LOCAL_ADMIN", None)
            else:
                os.environ["ALLOW_LOCAL_ADMIN"] = old
        self.assertEqual(review["statusCode"], 202)
        _, event = svc.invocations[0]
        result = purge.handle(event, None, svc)
        self.assertEqual(result["purged"], body["document_id"])
        self.assertNotIn(body["document_id"], svc.items)

    def test_admin_rejects_non_admin(self) -> None:
        svc = MemoryServices()
        result = admin_review.handle({"body": "{}"}, None, svc)
        self.assertEqual(result["statusCode"], 403)

    def test_upload_limit(self) -> None:
        result = ingest.handle({"body": ""}, None, MemoryServices())
        self.assertEqual(result["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
