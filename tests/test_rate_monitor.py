from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone

from ssrsf.handlers.rate_monitor import lambda_handler_impl


class FakeCloudWatch:
    def __init__(self, value: float, minutes_ago: int = 1):
        self.value = value
        self.timestamp = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=minutes_ago)
    def get_metric_statistics(self, **kwargs): return {"Datapoints": [{"Sum": self.value, "Timestamp": self.timestamp}]}


class FakeTable:
    def __init__(self): self.items = {}
    def get_item(self, Key, **kwargs): return {"Item": self.items.get(Key["function"], {})}
    def put_item(self, Item, **kwargs): self.items[Item["function"]] = Item


class FakeDynamo:
    def __init__(self): self.table = FakeTable()
    def Table(self, name): return self.table


class FakeSns:
    def __init__(self): self.messages = []
    def publish(self, **kwargs): self.messages.append(kwargs)


class RateMonitorTests(unittest.TestCase):
    def test_persists_baseline(self) -> None:
        os.environ["RATE_STATE_TABLE"] = "state"
        os.environ["ALERT_TOPIC_ARN"] = "topic"
        os.environ["MONITORED_FUNCTIONS"] = "F1,F2"
        db, sns = FakeDynamo(), FakeSns()
        result = lambda_handler_impl({}, None, (FakeCloudWatch(10), db, sns))
        self.assertEqual(result["checked"], 2)
        self.assertEqual(set(db.table.items), {"F1", "F2"})
        self.assertEqual(sns.messages, [])

    def test_duplicate_bucket_and_missing_data_do_not_train(self) -> None:
        os.environ.update(RATE_STATE_TABLE="state", ALERT_TOPIC_ARN="topic", MONITORED_FUNCTIONS="F1")
        db, sns = FakeDynamo(), FakeSns()
        cloudwatch = FakeCloudWatch(10)
        lambda_handler_impl({}, None, (cloudwatch, db, sns))
        initial = dict(db.table.items["F1"])
        result = lambda_handler_impl({}, None, (cloudwatch, db, sns))
        self.assertEqual(result["results"][0]["status"], "already-observed")
        cloudwatch.get_metric_statistics = lambda **kwargs: {"Datapoints": []}
        result = lambda_handler_impl({}, None, (cloudwatch, db, sns))
        self.assertEqual(result["results"][0]["status"], "missing-metric-evidence")
        self.assertEqual(db.table.items["F1"], initial)

    def test_alerts_after_three_anomalous_windows(self) -> None:
        os.environ["RATE_STATE_TABLE"] = "state"
        os.environ["ALERT_TOPIC_ARN"] = "topic"
        os.environ["MONITORED_FUNCTIONS"] = "F1"
        db, sns = FakeDynamo(), FakeSns()
        lambda_handler_impl({}, None, (FakeCloudWatch(10, 5), db, sns))
        for minute in (4, 3, 2):
            result = lambda_handler_impl({}, None, (FakeCloudWatch(100, minute), db, sns))
        self.assertTrue(result["results"][0]["anomalous"])
        self.assertEqual(len(sns.messages), 1)


if __name__ == "__main__":
    unittest.main()
