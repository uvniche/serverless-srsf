from __future__ import annotations

import os
import unittest

from reference_app.handlers.rate_monitor import lambda_handler_impl


class FakeCloudWatch:
    def __init__(self, value: float): self.value = value
    def get_metric_statistics(self, **kwargs): return {"Datapoints": [{"Sum": self.value}]}


class FakeTable:
    def __init__(self): self.items = {}
    def get_item(self, Key): return {"Item": self.items.get(Key["function"], {})}
    def put_item(self, Item): self.items[Item["function"]] = Item


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

    def test_alerts_after_three_anomalous_windows(self) -> None:
        os.environ["RATE_STATE_TABLE"] = "state"
        os.environ["ALERT_TOPIC_ARN"] = "topic"
        os.environ["MONITORED_FUNCTIONS"] = "F1"
        db, sns = FakeDynamo(), FakeSns()
        lambda_handler_impl({}, None, (FakeCloudWatch(10), db, sns))
        for _ in range(3):
            result = lambda_handler_impl({}, None, (FakeCloudWatch(100), db, sns))
        self.assertTrue(result["results"][0]["anomalous"])
        self.assertEqual(len(sns.messages), 1)


if __name__ == "__main__":
    unittest.main()
