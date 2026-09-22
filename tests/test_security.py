from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from reference_app.security.anomaly import FrozenEWMA, burn_rate
from reference_app.security.ebe import environment_digest, manifest
from reference_app.security.footprint import footprint
from reference_app.security.iam import configuration_hash, expansions
from reference_app.security.purge_auth import issue, verify


class SecurityTests(unittest.TestCase):
    def test_manifest_detects_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a"
            path.write_text("one")
            first, _ = manifest(directory)
            path.write_text("longer")
            second, _ = manifest(directory)
            self.assertNotEqual(first, second)

    def test_environment_digest_never_contains_values(self) -> None:
        secret = "do-not-emit-this"
        digest = environment_digest({"SECRET": secret})
        self.assertNotIn(secret, digest)
        self.assertEqual(len(digest), 64)

    def test_ewma_freezes_during_anomaly(self) -> None:
        detector = FrozenEWMA(alpha=.2, deviations=2, confirmations=2)
        for value in [10, 10, 11, 9, 10]:
            detector.observe(value)
        baseline = detector.mean
        detector.observe(100)
        result = detector.observe(100)
        self.assertTrue(result.anomalous)
        self.assertEqual(detector.mean, baseline)
        self.assertIn("propose", result.proposed_action or "")

    def test_burn_rate(self) -> None:
        self.assertEqual(burn_rate(144, 10), 14.4)
        with self.assertRaises(ValueError):
            burn_rate(1, 0)

    def test_iam_expansion_halts(self) -> None:
        before = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:raw/*"}]}
        after = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"], "Resource": "arn:raw/*"}]}
        result = expansions(before, after)
        self.assertEqual({g.action for g in result}, {"s3:deleteobject"})

    def test_iam_contraction_passes(self) -> None:
        before = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:raw/*"}]}
        after = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:raw/incoming/*"}]}
        self.assertEqual(expansions(before, after), set())

    def test_configuration_hash_is_deterministic(self) -> None:
        self.assertEqual(configuration_hash({"b": 2, "a": 1}), configuration_hash({"a": 1, "b": 2}))

    def test_weighted_permission_footprint(self) -> None:
        score, unused = footprint(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], ["s3:GetObject"])
        self.assertEqual(score, 13)
        self.assertEqual(len(unused), 2)

    def test_purge_token_tamper_detection(self) -> None:
        token = issue({"document_id": "d1", "issuer": "F4"}, "secret")
        self.assertEqual(verify(token, "secret")["document_id"], "d1")
        with self.assertRaises(ValueError):
            verify(token + "x", "secret")


if __name__ == "__main__":
    unittest.main()

