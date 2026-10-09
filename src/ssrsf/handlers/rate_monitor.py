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
        points = [p for p in response.get("Datapoints", [])
                  if p.get("Timestamp") and p["Timestamp"] < now]
        state = table.get_item(Key={"function": function_name}, ConsistentRead=True).get("Item", {})
        if not points:
            results.append({"function": function_name, "status": "missing-metric-evidence"})
            continue
        point = max(points, key=lambda p: p["Timestamp"])
        bucket = point["Timestamp"].isoformat()
        if state.get("last_bucket", "") >= bucket:
            results.append({"function": function_name, "status": "already-observed"})
            continue
        rate = float(point["Sum"]) / 60  # Invocation rate in requests per second.
        detector = FrozenEWMA(alpha=float(os.getenv("RATE_ALPHA", ".2")),
                              deviations=float(os.getenv("RATE_DEVIATIONS", "4")),
                              confirmations=int(os.getenv("RATE_CONFIRMATIONS", "3")), noise_floor=1/60)
        if "mean" in state:
            detector.mean = float(state["mean"])
            detector.variance = float(state.get("variance", 0))
            detector.consecutive = int(state.get("consecutive", 0))
            if state.get("last_bucket") and point["Timestamp"] - datetime.fromisoformat(state["last_bucket"]) != timedelta(minutes=1):
                detector.consecutive = 0  # Missing minute breaks consecutive confirmation.
        detection = detector.observe(rate)
        item = {
            "function": function_name,
            "mean": Decimal(str(detector.mean or 0)),
            "variance": Decimal(str(detector.variance)),
            "consecutive": detector.consecutive,
            "updated_at": now.isoformat(),
            "last_bucket": bucket,
        }
        try:
            if "last_bucket" in state:
                table.put_item(Item=item, ConditionExpression="last_bucket = :prior",
                               ExpressionAttributeValues={":prior": state["last_bucket"]})
            else:
                table.put_item(Item=item, ConditionExpression="attribute_not_exists(last_bucket)")
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                results.append({"function": function_name, "status": "concurrent-observation"})
                continue
            raise
        record = {"function": function_name, "rate_per_second": rate, "anomalous": detection.anomalous,
                  "mean": detection.mean, "standard_deviation": detection.standard_deviation,
                  "proposed_action": detection.proposed_action}
        results.append(record)
        if detection.anomalous:
            sns.publish(TopicArn=topic, Subject=f"SSRSF rate anomaly: {function_name}",
                        Message=json.dumps(record, sort_keys=True))
    return {"checked": len(results), "results": results}


@instrument("SRSF-RateMonitor")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return lambda_handler_impl(event, context)
