from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from ..security.anomaly import FrozenEWMA
from ..security.ebe import instrument


def _clients() -> tuple[Any, Any, Any]:
    import boto3
    return boto3.client("cloudwatch"), boto3.resource("dynamodb"), boto3.client("sns")


def lambda_handler_impl(event: dict[str, Any], context: Any, clients: tuple[Any, Any, Any] | None = None) -> dict[str, Any]:
    cloudwatch, dynamodb, sns = clients or _clients()
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    table = dynamodb.Table(os.environ["RATE_STATE_TABLE"])
    topic = os.environ["ALERT_TOPIC_ARN"]
    names = [name for name in os.environ.get("MONITORED_FUNCTIONS", "").split(",") if name]
    results = []
    for function_name in names:
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/Lambda", MetricName="Invocations",
            Dimensions=[{"Name": "FunctionName", "Value": function_name}],
            StartTime=now - timedelta(minutes=2), EndTime=now,
            Period=60, Statistics=["Sum"],
        )
        rate = max((float(point.get("Sum", 0)) for point in response.get("Datapoints", [])), default=0.0)
        state = table.get_item(Key={"function": function_name}).get("Item", {})
        detector = FrozenEWMA(alpha=.2, deviations=4, confirmations=3)
        if "mean" in state:
            detector.mean = float(state["mean"])
            detector.variance = float(state.get("variance", 0))
            detector.consecutive = int(state.get("consecutive", 0))
        detection = detector.observe(rate)
        table.put_item(Item={
            "function": function_name,
            "mean": Decimal(str(detector.mean or 0)),
            "variance": Decimal(str(detector.variance)),
            "consecutive": detector.consecutive,
            "updated_at": now.isoformat(),
        })
        record = {"function": function_name, "rate": rate, "anomalous": detection.anomalous,
                  "mean": detection.mean, "standard_deviation": detection.standard_deviation,
                  "proposed_action": detection.proposed_action}
        results.append(record)
        if detection.anomalous:
            sns.publish(TopicArn=topic, Subject=f"ReferenceApp rate anomaly: {function_name}",
                        Message=json.dumps(record, sort_keys=True))
    return {"checked": len(results), "results": results}


@instrument("SRSF-RateMonitor")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return lambda_handler_impl(event, context)
