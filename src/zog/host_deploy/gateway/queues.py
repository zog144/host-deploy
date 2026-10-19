"""Strict SQS queue target validation for the execution gateway."""

import json
import re
from urllib.parse import urlsplit


AWS_REGION = "us-east-1"
PRIMARY_QUEUE_NAME = "zog-build-requests.fifo"
DEAD_LETTER_QUEUE_NAME = "zog-build-dead-letter.fifo"
_ACCOUNT_ID = re.compile(r"[0-9]{12}")


class QueueConfigurationError(ValueError):
    """An SQS target or queue policy does not match the gateway contract."""


def canonical_queue_target(value, expected_name):
    if (
        not isinstance(expected_name, str)
        or not expected_name.endswith(".fifo")
        or "/" in expected_name
    ):
        raise QueueConfigurationError("invalid expected FIFO queue name")
    if not isinstance(value, str) or len(value) > 512:
        raise QueueConfigurationError("SQS queue target is invalid")
    value = value.strip()
    arn = re.fullmatch(
        rf"arn:aws:sqs:{AWS_REGION}:([0-9]{{12}}):{re.escape(expected_name)}",
        value,
    )
    if arn:
        return f"https://sqs.{AWS_REGION}.amazonaws.com/{arn.group(1)}/{expected_name}"
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != f"sqs.{AWS_REGION}.amazonaws.com"
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise QueueConfigurationError(
            f"SQS queue target must be the {AWS_REGION} {expected_name} queue"
        )
    parts = parsed.path.rstrip("/").split("/")
    if (
        len(parts) != 3
        or parts[0] != ""
        or not _ACCOUNT_ID.fullmatch(parts[1])
        or parts[2] != expected_name
    ):
        raise QueueConfigurationError(f"SQS queue target must name {expected_name}")
    return f"https://sqs.{AWS_REGION}.amazonaws.com/{parts[1]}/{expected_name}"


def queue_account_id(queue_url):
    parsed = urlsplit(queue_url)
    parts = parsed.path.split("/")
    if len(parts) != 3 or not _ACCOUNT_ID.fullmatch(parts[1]):
        raise QueueConfigurationError("canonical queue URL has invalid account identity")
    return parts[1]


def expected_queue_arn(queue_url, name):
    return f"arn:aws:sqs:{AWS_REGION}:{queue_account_id(queue_url)}:{name}"


def _attributes(client, url):
    response = client.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["QueueArn", "FifoQueue", "RedrivePolicy", "SqsManagedSseEnabled"],
    )
    attributes = response.get("Attributes")
    if not isinstance(attributes, dict):
        raise QueueConfigurationError("SQS did not return queue attributes")
    return attributes


def verify_queue_configuration(client, primary_target, dead_letter_target):
    primary = canonical_queue_target(primary_target, PRIMARY_QUEUE_NAME)
    dead_letter = canonical_queue_target(dead_letter_target, DEAD_LETTER_QUEUE_NAME)
    if queue_account_id(primary) != queue_account_id(dead_letter):
        raise QueueConfigurationError("primary and dead-letter queues use different accounts")

    primary_attributes = _attributes(client, primary)
    dead_attributes = _attributes(client, dead_letter)
    primary_arn = expected_queue_arn(primary, PRIMARY_QUEUE_NAME)
    dead_arn = expected_queue_arn(dead_letter, DEAD_LETTER_QUEUE_NAME)

    for attributes, expected_arn, label in (
        (primary_attributes, primary_arn, "primary"),
        (dead_attributes, dead_arn, "dead-letter"),
    ):
        if attributes.get("QueueArn") != expected_arn:
            raise QueueConfigurationError(f"{label} queue ARN mismatch")
        if attributes.get("FifoQueue") != "true":
            raise QueueConfigurationError(f"{label} queue is not FIFO")
        if attributes.get("SqsManagedSseEnabled") != "true":
            raise QueueConfigurationError(
                f"{label} queue does not use SQS-managed encryption"
            )

    try:
        redrive = json.loads(primary_attributes.get("RedrivePolicy", ""))
    except (TypeError, ValueError):
        raise QueueConfigurationError("primary queue has no valid redrive policy") from None
    if redrive.get("deadLetterTargetArn") != dead_arn:
        raise QueueConfigurationError("primary queue redrive target mismatch")
    maximum = redrive.get("maxReceiveCount")
    if isinstance(maximum, bool):
        normalized_maximum = None
    elif isinstance(maximum, int):
        normalized_maximum = maximum
    elif isinstance(maximum, str) and maximum.isdigit():
        normalized_maximum = int(maximum)
    else:
        normalized_maximum = None
    if normalized_maximum is None or normalized_maximum < 2:
        raise QueueConfigurationError("primary queue maxReceiveCount is invalid")
    return {
        "primary_url": primary,
        "dead_letter_url": dead_letter,
        "primary_arn": primary_arn,
        "dead_letter_arn": dead_arn,
        "max_receive_count": normalized_maximum,
    }


def queue_status(client, primary_target, dead_letter_target):
    configuration = verify_queue_configuration(
        client, primary_target, dead_letter_target
    )
    result = {}
    for key in ("primary", "dead_letter"):
        url = configuration[key + "_url"]
        response = client.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed",
            ],
        )
        attributes = response.get("Attributes", {})
        result[key] = {
            "approximate_available": int(attributes.get("ApproximateNumberOfMessages", "0")),
            "approximate_in_flight": int(
                attributes.get("ApproximateNumberOfMessagesNotVisible", "0")
            ),
            "approximate_delayed": int(
                attributes.get("ApproximateNumberOfMessagesDelayed", "0")
            ),
        }
    result["max_receive_count"] = configuration["max_receive_count"]
    return result
