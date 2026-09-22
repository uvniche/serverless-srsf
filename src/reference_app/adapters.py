from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .config import settings


class AwsServices:
    def __init__(self, *, destructive: bool = False):
        import boto3

        self.s3 = boto3.client("s3")
        self.sqs = boto3.client("sqs")
        self.ddb = boto3.resource("dynamodb")
        self.lambda_client = boto3.client("lambda")
        if destructive and settings.purge_role_arn:
            creds = boto3.client("sts").assume_role(
                RoleArn=settings.purge_role_arn,
                RoleSessionName="referenceapp-purge",
                DurationSeconds=900,
                Tags=[{"Key": "Purpose", "Value": "ReferenceAppPurge"}],
            )["Credentials"]
            self.s3 = boto3.client("s3", aws_access_key_id=creds["AccessKeyId"],
                                   aws_secret_access_key=creds["SecretAccessKey"],
                                   aws_session_token=creds["SessionToken"])
            self.ddb = boto3.resource("dynamodb", aws_access_key_id=creds["AccessKeyId"],
                                      aws_secret_access_key=creds["SecretAccessKey"],
                                      aws_session_token=creds["SessionToken"])

    def put_object(self, bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type,
                           ServerSideEncryption="aws:kms")

    def get_object(self, bucket: str, key: str) -> bytes:
        return self.s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    def delete_object(self, bucket: str, key: str) -> None:
        self.s3.delete_object(Bucket=bucket, Key=key)

    def enqueue(self, payload: dict[str, Any]) -> None:
        self.sqs.send_message(QueueUrl=settings.queue_url, MessageBody=json.dumps(payload))

    def put_item(self, item: dict[str, Any]) -> None:
        self.ddb.Table(settings.table_name).put_item(Item=item)

    def get_item(self, document_id: str) -> dict[str, Any] | None:
        return self.ddb.Table(settings.table_name).get_item(Key={"document_id": document_id}).get("Item")

    def delete_item(self, document_id: str) -> None:
        self.ddb.Table(settings.table_name).delete_item(Key={"document_id": document_id})

    def scan_items(self) -> list[dict[str, Any]]:
        return self.ddb.Table(settings.table_name).scan(ProjectionExpression="document_id, classification").get("Items", [])

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
    invocations: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def put_object(self, bucket: str, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.objects[(bucket, key)] = data

    def get_object(self, bucket: str, key: str) -> bytes:
        return self.objects[(bucket, key)]

    def delete_object(self, bucket: str, key: str) -> None:
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


def services(*, destructive: bool = False) -> AwsServices:
    if not os.getenv("AWS_EXECUTION_ENV"):
        raise RuntimeError("AWS services requested outside Lambda; inject MemoryServices for local use")
    return AwsServices(destructive=destructive)
