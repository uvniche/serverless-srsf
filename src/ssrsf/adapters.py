from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .config import settings


class AwsServices:
    def __init__(self):
        try:
            import boto3
            self.s3 = boto3.client("s3")
            self.sqs = boto3.client("sqs")
            self.ddb = boto3.resource("dynamodb")
            self.lambda_client = boto3.client("lambda")
        except Exception as exc:
            raise RuntimeError(f"AWS services unavailable (use local mode without AWS credentials): {exc}") from exc

    def save_grant(self, grant: dict[str, Any]) -> None:
        self.ddb.Table(os.environ["PURGE_GRANTS_TABLE"]).put_item(
            Item={"nonce": grant["nonce"], "grant": grant, "expires_at": grant["exp"] + 86400},
            ConditionExpression="attribute_not_exists(nonce)")

    def get_grant(self, nonce: str) -> dict[str, Any] | None:
        return self.ddb.Table(os.environ["PURGE_GRANTS_TABLE"]).get_item(
            Key={"nonce": nonce}, ConsistentRead=True).get("Item", {}).get("grant")

    def consume_nonce(self, nonce: str, expiry: int) -> None:
        self.ddb.Table(os.environ["PURGE_OPERATIONS_TABLE"]).put_item(
            Item={"nonce": nonce, "grant_expiry": expiry, "status": "consumed", "completed": []},
            ConditionExpression="attribute_not_exists(nonce)")

    def record_outcome(self, nonce: str, completed: list[str], status: str) -> None:
        self.ddb.Table(os.environ["PURGE_OPERATIONS_TABLE"]).update_item(
            Key={"nonce": nonce}, UpdateExpression="SET completed = :c, #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":c": completed, ":s": status},
            ConditionExpression="attribute_exists(nonce)")

    def scoped_purge(self, grant: dict[str, Any]) -> Any:
        import boto3
        region = os.environ["AWS_REGION"]
        account = os.environ["AWS_ACCOUNT_ID"]
        partition = os.environ.get("AWS_PARTITION", "aws")
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:DeleteObjectVersion",
             "Resource": f"arn:{partition}:s3:::{settings.raw_bucket}/{grant['raw_key']}",
             "Condition": {"StringEquals": {"s3:VersionId": grant['raw_version']}}},
            {"Effect": "Allow", "Action": "s3:DeleteObjectVersion",
             "Resource": f"arn:{partition}:s3:::{settings.text_bucket}/{grant['text_key']}",
             "Condition": {"StringEquals": {"s3:VersionId": grant['text_version']}}},
            {"Effect": "Allow", "Action": "dynamodb:DeleteItem",
             "Resource": f"arn:{partition}:dynamodb:{region}:{account}:table/{settings.table_name}",
             "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [grant['document_id']]}}},
        ]}
        response = boto3.client("sts").assume_role(RoleArn=settings.purge_role_arn,
            RoleSessionName="purge-" + grant['nonce'], DurationSeconds=900,
            Policy=json.dumps(policy, separators=(",", ":")))
        creds = response["Credentials"]
        kwargs = dict(aws_access_key_id=creds["AccessKeyId"],
                      aws_secret_access_key=creds["SecretAccessKey"],
                      aws_session_token=creds["SessionToken"])
        scoped = AwsServices()
        scoped.s3 = boto3.client("s3", **kwargs)
        scoped.ddb = boto3.resource("dynamodb", **kwargs)
        scoped.session_identity = response["AssumedRoleUser"]["Arn"]
        return scoped

    def put_object(self, bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type,
                           ServerSideEncryption="AES256")

    def get_object(self, bucket: str, key: str) -> bytes:
        return self.s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    def delete_object(self, bucket: str, key: str, version: str) -> None:
        self.s3.delete_object(Bucket=bucket, Key=key, VersionId=version)

    def enqueue(self, payload: dict[str, Any]) -> None:
        self.sqs.send_message(QueueUrl=settings.queue_url, MessageBody=json.dumps(payload))

    def put_item(self, item: dict[str, Any]) -> None:
        self.ddb.Table(settings.table_name).put_item(Item=item)

    def get_item(self, document_id: str) -> dict[str, Any] | None:
        return self.ddb.Table(settings.table_name).get_item(Key={"document_id": document_id}).get("Item")

    def delete_item(self, document_id: str) -> None:
        self.ddb.Table(settings.table_name).delete_item(Key={"document_id": document_id})

    def scan_items(self) -> list[dict[str, Any]]:
        table = self.ddb.Table(settings.table_name)
        kwargs = {"ProjectionExpression": "document_id, classification"}
        items = []
        while True:
            result = table.scan(**kwargs)
            items.extend(result.get("Items", []))
            if "LastEvaluatedKey" not in result:
                return items
            kwargs["ExclusiveStartKey"] = result["LastEvaluatedKey"]

    def invoke(self, function_name: str, payload: dict[str, Any]) -> None:
        self.lambda_client.invoke(FunctionName=function_name, InvocationType="Event",
                                  Payload=json.dumps(payload).encode())

    def classify(self, text: str) -> str:
        if not settings.inference_endpoint:
            return local_classify(text)
        req = urllib.request.Request(settings.inference_endpoint,
                                     data=json.dumps({"text": text[:8000]}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return str(json.loads(response.read())["classification"])


@dataclass
class MemoryServices:
    objects: dict[tuple[str, str], bytes] = field(default_factory=dict)
    items: dict[str, dict[str, Any]] = field(default_factory=dict)
    messages: list[dict[str, Any]] = field(default_factory=list)
    grants: dict[str, dict[str, Any]] = field(default_factory=dict)
    operations: dict[str, dict[str, Any]] = field(default_factory=dict)
    invocations: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def save_grant(self, grant: dict[str, Any]) -> None:
        self.grants[grant["nonce"]] = dict(grant)

    def get_grant(self, nonce: str) -> dict[str, Any] | None:
        return self.grants.get(nonce)

    def consume_nonce(self, nonce: str, expiry: int) -> None:
        if nonce in self.operations:
            raise ValueError("purge grant already consumed")
        self.operations[nonce] = {"status": "consumed", "completed": []}

    def record_outcome(self, nonce: str, completed: list[str], status: str) -> None:
        self.operations[nonce] = {"status": status, "completed": list(completed)}

    def scoped_purge(self, grant: dict[str, Any]) -> Any:
        return self

    def put_object(self, bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.objects[(bucket, key)] = data

    def get_object(self, bucket: str, key: str) -> bytes:
        return self.objects[(bucket, key)]

    def delete_object(self, bucket: str, key: str, version: str) -> None:
        self.objects.pop((bucket, key), None)

    def enqueue(self, payload: dict[str, Any]) -> None:
        self.messages.append(payload)

    def put_item(self, item: dict[str, Any]) -> None:
        self.items[item["document_id"]] = item

    def get_item(self, document_id: str) -> dict[str, Any] | None:
        return self.items.get(document_id)

    def delete_item(self, document_id: str) -> None:
        self.items.pop(document_id, None)

    def scan_items(self) -> list[dict[str, Any]]:
        return list(self.items.values())

    def invoke(self, function_name: str, payload: dict[str, Any]) -> None:
        self.invocations.append((function_name, payload))

    def classify(self, text: str) -> str:
        return local_classify(text)


def local_classify(text: str) -> str:
    lowered = text.lower()
    return "sensitive" if any(word in lowered for word in ("secret", "password", "confidential")) else "general"


_SHARED_LOCAL_SERVICES = MemoryServices()


def get_memory_services() -> MemoryServices:
    return _SHARED_LOCAL_SERVICES


def reset_services() -> MemoryServices:
    global _SHARED_LOCAL_SERVICES
    _SHARED_LOCAL_SERVICES = MemoryServices()
    return _SHARED_LOCAL_SERVICES


def services() -> Any:
    if os.getenv("USE_AWS_SERVICES") == "1":
        return AwsServices()
    return _SHARED_LOCAL_SERVICES
