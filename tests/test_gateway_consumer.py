import json
from pathlib import Path

import pytest

from zog.host_deploy import checkpoint
from zog.host_deploy.gateway.consumer import GatewayConsumer, administrative_status
from zog.host_deploy.gateway.ledger import (
    accept,
    claim_handoff,
    load_request,
    owned_workspace,
    reconcile_request,
    release_handoff,
)
from zog.host_deploy.gateway.protocol import canonical_bytes
from zog.host_deploy.gateway.queues import (
    DEAD_LETTER_QUEUE_NAME,
    PRIMARY_QUEUE_NAME,
    QueueConfigurationError,
    canonical_queue_target,
    verify_queue_configuration,
)
from zog.host_deploy.workspace import initialize, locked


ACCOUNT = "123456789012"
PRIMARY_URL = (
    "https://sqs.us-east-1.amazonaws.com/"
    + ACCOUNT
    + "/"
    + PRIMARY_QUEUE_NAME
)
DLQ_URL = (
    "https://sqs.us-east-1.amazonaws.com/"
    + ACCOUNT
    + "/"
    + DEAD_LETTER_QUEUE_NAME
)
PRIMARY_ARN = f"arn:aws:sqs:us-east-1:{ACCOUNT}:{PRIMARY_QUEUE_NAME}"
DLQ_ARN = f"arn:aws:sqs:us-east-1:{ACCOUNT}:{DEAD_LETTER_QUEUE_NAME}"


def request(workspace_id, request_id="0123456789abcdef0123456789abcdef"):
    return {
        "schema": 1,
        "request_id": request_id,
        "workspace_id": workspace_id,
        "operation": "host.status",
        "origin": {
            "repository": "zog144/host-deploy",
            "issue_number": 8,
            "trigger_actor": "zog144",
        },
        "parameters": {},
    }


def message(value, *, message_id="message-1", receive_count=1):
    return {
        "MessageId": message_id,
        "ReceiptHandle": "receipt-" + message_id,
        "Body": canonical_bytes(value).decode("ascii"),
        "Attributes": {"ApproximateReceiveCount": str(receive_count)},
    }


class FakeSQS:
    def __init__(self, messages=(), fail_delete=0, max_receive_count="3"):
        self.messages = list(messages)
        self.fail_delete = fail_delete
        self.max_receive_count = max_receive_count
        self.deleted = []
        self.receive_calls = []

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        if "ApproximateNumberOfMessages" in AttributeNames:
            return {
                "Attributes": {
                    "ApproximateNumberOfMessages": str(len(self.messages)),
                    "ApproximateNumberOfMessagesNotVisible": "0",
                    "ApproximateNumberOfMessagesDelayed": "0",
                }
            }
        if QueueUrl == PRIMARY_URL:
            return {
                "Attributes": {
                    "QueueArn": PRIMARY_ARN,
                    "FifoQueue": "true",
                    "SqsManagedSseEnabled": "true",
                    "RedrivePolicy": json.dumps(
                        {
                            "deadLetterTargetArn": DLQ_ARN,
                            "maxReceiveCount": self.max_receive_count,
                        }
                    ),
                }
            }
        if QueueUrl == DLQ_URL:
            return {
                "Attributes": {
                    "QueueArn": DLQ_ARN,
                    "FifoQueue": "true",
                    "SqsManagedSseEnabled": "true",
                    "RedrivePolicy": "",
                }
            }
        raise AssertionError(QueueUrl)

    def receive_message(self, **kwargs):
        self.receive_calls.append(kwargs)
        if not self.messages:
            return {}
        return {"Messages": [self.messages.pop(0)]}

    def delete_message(self, **kwargs):
        if self.fail_delete:
            self.fail_delete -= 1
            raise RuntimeError("simulated uncertain delete")
        self.deleted.append(kwargs)
        return {}


def consumer(tmp_path, client):
    return GatewayConsumer(
        tmp_path / "gateway",
        PRIMARY_ARN,
        DLQ_ARN,
        client=client,
    )


def test_queue_targets_accept_exact_arn_or_url_and_verify_redrive():
    assert canonical_queue_target(PRIMARY_ARN, PRIMARY_QUEUE_NAME) == PRIMARY_URL
    assert canonical_queue_target(PRIMARY_URL + "/", PRIMARY_QUEUE_NAME) == PRIMARY_URL
    configuration = verify_queue_configuration(FakeSQS(), PRIMARY_ARN, DLQ_ARN)
    assert configuration["primary_url"] == PRIMARY_URL
    assert configuration["dead_letter_url"] == DLQ_URL
    assert configuration["max_receive_count"] == 3


@pytest.mark.parametrize("value", [5, "5"])
def test_queue_redrive_accepts_integer_or_decimal_string_max_receive_count(value):
    configuration = verify_queue_configuration(
        FakeSQS(max_receive_count=value),
        PRIMARY_ARN,
        DLQ_ARN,
    )
    assert configuration["max_receive_count"] == 5


@pytest.mark.parametrize(
    "value",
    [True, False, None, 1, "1", -5, 5.0, "5.0", "", "five"],
)
def test_queue_redrive_rejects_invalid_max_receive_count(value):
    with pytest.raises(
        QueueConfigurationError,
        match="primary queue maxReceiveCount is invalid",
    ):
        verify_queue_configuration(
            FakeSQS(max_receive_count=value),
            PRIMARY_ARN,
            DLQ_ARN,
        )


def test_valid_message_is_durable_before_ack_and_waits_for_owned_workspace(tmp_path):
    workspace_id = "fedcba9876543210fedcba9876543210"
    value = request(workspace_id)
    client = FakeSQS()
    result = consumer(tmp_path, client).handle_message(message(value))
    assert result == {
        "accepted": True,
        "duplicate": False,
        "request_id": value["request_id"],
        "acknowledgement": "acked",
        "admission": "pending",
    }
    assert client.deleted == [{"QueueUrl": PRIMARY_URL, "ReceiptHandle": "receipt-message-1"}]
    state = load_request(tmp_path / "gateway", value["request_id"])
    assert state["states"]["acceptance"] == "accepted"
    assert state["states"]["admission"] == "pending"
    assert state["states"]["dispatch"] == "not_started"
    transport = json.loads(
        (
            tmp_path
            / "gateway/requests"
            / value["request_id"]
            / "transport.json"
        ).read_text()
    )
    assert transport["acknowledgement"] == "acked"


def test_redelivery_of_same_request_is_idempotent(tmp_path):
    workspace_id = "fedcba9876543210fedcba9876543210"
    value = request(workspace_id)
    client = FakeSQS()
    gateway = consumer(tmp_path, client)
    first = gateway.handle_message(message(value, receive_count=1))
    second = gateway.handle_message(message(value, receive_count=2))
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    state = load_request(tmp_path / "gateway", value["request_id"])
    assert len(state["history"]) == 2
    transport = json.loads(
        (
            tmp_path
            / "gateway/requests"
            / value["request_id"]
            / "transport.json"
        ).read_text()
    )
    assert [item["receive_count"] for item in transport["deliveries"]] == [1, 2]


def test_crash_during_delete_preserves_attempt_marker_for_redelivery(tmp_path):
    workspace_id = "fedcba9876543210fedcba9876543210"
    value = request(workspace_id)

    class CrashDuringDelete(FakeSQS):
        def delete_message(self, **kwargs):
            raise KeyboardInterrupt("simulated process loss")

    client = CrashDuringDelete()
    gateway = consumer(tmp_path, client)
    with pytest.raises(KeyboardInterrupt):
        gateway.handle_message(message(value))
    transport_path = (
        tmp_path / "gateway/requests" / value["request_id"] / "transport.json"
    )
    assert json.loads(transport_path.read_text())["acknowledgement"] == "delete_attempting"

    retry = FakeSQS()
    result = consumer(tmp_path, retry).handle_message(
        message(value, receive_count=2)
    )
    assert result["duplicate"] is True
    assert result["acknowledgement"] == "acked"


def test_delete_uncertainty_is_recorded_and_safe_to_retry(tmp_path):
    workspace_id = "fedcba9876543210fedcba9876543210"
    value = request(workspace_id)
    client = FakeSQS(fail_delete=1)
    gateway = consumer(tmp_path, client)
    first = gateway.handle_message(message(value))
    assert first["acknowledgement"] == "delete_uncertain"
    transport_path = (
        tmp_path / "gateway/requests" / value["request_id"] / "transport.json"
    )
    assert json.loads(transport_path.read_text())["acknowledgement"] == "delete_uncertain"

    second = gateway.handle_message(message(value, receive_count=2))
    assert second["duplicate"] is True
    assert second["acknowledgement"] == "acked"
    assert json.loads(transport_path.read_text())["acknowledgement"] == "acked"


def test_malformed_message_is_retained_for_redrive_with_bounded_evidence(tmp_path):
    client = FakeSQS()
    bad = {
        "MessageId": "bad-message",
        "ReceiptHandle": "bad-receipt",
        "Body": '{"schema":1,"unknown":true}',
        "Attributes": {"ApproximateReceiveCount": "2"},
    }
    result = consumer(tmp_path, client).handle_message(bad)
    assert result["accepted"] is False
    assert client.deleted == []
    evidence = list((tmp_path / "gateway/failures/bad-message").glob("*.json"))
    assert len(evidence) == 1
    saved = json.loads(evidence[0].read_text())
    assert saved["receive_count"] == 2
    assert "Body" not in saved
    assert len(saved["body_sha256"]) == 64


def test_request_identity_conflict_is_never_acked(tmp_path):
    first_workspace = "fedcba9876543210fedcba9876543210"
    second_workspace = "00112233445566778899aabbccddeeff"
    client = FakeSQS()
    gateway = consumer(tmp_path, client)
    gateway.handle_message(message(request(first_workspace)))
    conflict = gateway.handle_message(
        message(
            request(second_workspace),
            message_id="message-2",
            receive_count=1,
        )
    )
    assert conflict["accepted"] is False
    assert len(client.deleted) == 1
    evidence = list((tmp_path / "gateway/failures/message-2").glob("*.json"))
    assert len(evidence) == 1


def test_poll_uses_long_poll_visibility_and_single_message(tmp_path):
    workspace_id = "fedcba9876543210fedcba9876543210"
    client = FakeSQS([message(request(workspace_id))])
    gateway = consumer(tmp_path, client)
    gateway.poll_once(wait_seconds=0)
    assert client.receive_calls == [
        {
            "QueueUrl": PRIMARY_URL,
            "MaxNumberOfMessages": 1,
            "WaitTimeSeconds": 0,
            "VisibilityTimeout": 60,
            "AttributeNames": ["ApproximateReceiveCount"],
        }
    ]


def test_checkpoint_handoff_is_required_before_workspace_admission(tmp_path):
    work = tmp_path / "work"
    workspace = initialize(work, "example", "development", "us-east-1")
    non_handoff = tmp_path / "copy.zip"
    checkpoint.export(work, non_handoff, handoff=False)
    with pytest.raises(ValueError, match="handoff checkpoint"):
        claim_handoff(tmp_path / "gateway", non_handoff)

    value = request(workspace["workspace_id"])
    accept(
        tmp_path / "gateway",
        value,
        message_id="message-1",
        receive_count=1,
        at="2026-10-09T12:00:00Z",
    )
    pending = reconcile_request(
        tmp_path / "gateway",
        value["request_id"],
        at="2026-10-09T12:00:01Z",
    )
    assert pending["states"]["admission"] == "pending"

    handoff = tmp_path / "handoff.zip"
    checkpoint.export(work, handoff, handoff=True)
    claimed = claim_handoff(tmp_path / "gateway", handoff)
    assert claimed["workspace_id"] == workspace["workspace_id"]
    with pytest.raises(RuntimeError, match="retired"):
        with locked(work):
            pass

    admitted = reconcile_request(
        tmp_path / "gateway",
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )
    assert admitted["states"]["admission"] == "admitted"
    assert admitted["states"]["dispatch"] == "not_started"


def test_claim_recovery_finishes_after_restore_before_owner_marker(tmp_path, monkeypatch):
    work = tmp_path / "work"
    workspace = initialize(work, "recovery", "development", "us-east-1")
    handoff = tmp_path / "handoff.zip"
    checkpoint.export(work, handoff, handoff=True)

    original = checkpoint.restore
    calls = {"count": 0}

    def interrupted(archive, target):
        result = original(archive, target)
        calls["count"] += 1
        raise RuntimeError("lost reply after restore")

    monkeypatch.setattr(checkpoint, "restore", interrupted)
    with pytest.raises(RuntimeError, match="lost reply"):
        claim_handoff(tmp_path / "gateway", handoff)
    monkeypatch.setattr(checkpoint, "restore", original)

    result = claim_handoff(tmp_path / "gateway", handoff)
    assert result["workspace_id"] == workspace["workspace_id"]
    assert calls["count"] == 1
    assert owned_workspace(tmp_path / "gateway", workspace["workspace_id"])


def test_interrupted_claim_refuses_restored_workspace_substitution(tmp_path, monkeypatch):
    work = tmp_path / "work"
    initialize(work, "bound", "development", "us-east-1")
    handoff = tmp_path / "handoff.zip"
    checkpoint.export(work, handoff, handoff=True)

    original = checkpoint.restore

    def interrupted(archive, target):
        original(archive, target)
        raise RuntimeError("lost reply after restore")

    monkeypatch.setattr(checkpoint, "restore", interrupted)
    with pytest.raises(RuntimeError, match="lost reply"):
        claim_handoff(tmp_path / "gateway", handoff)
    monkeypatch.setattr(checkpoint, "restore", original)

    target = next((tmp_path / "gateway/workspaces").iterdir())
    workspace = json.loads((target / "workspace.json").read_text())
    workspace["name"] = "substituted"
    (target / "workspace.json").write_text(json.dumps(workspace))

    with pytest.raises(RuntimeError, match="differs from bound"):
        claim_handoff(tmp_path / "gateway", handoff)


def test_release_handoff_retires_gateway_copy(tmp_path):
    work = tmp_path / "work"
    workspace = initialize(work, "release", "development", "us-east-1")
    incoming = tmp_path / "incoming.zip"
    checkpoint.export(work, incoming, handoff=True)
    claim_handoff(tmp_path / "gateway", incoming)

    outgoing = tmp_path / "outgoing.zip"
    release_handoff(tmp_path / "gateway", workspace["workspace_id"], outgoing)
    assert outgoing.exists()
    assert owned_workspace(tmp_path / "gateway", workspace["workspace_id"]) is None
    with pytest.raises(RuntimeError, match="retired"):
        with locked(
            tmp_path / "gateway/workspaces" / workspace["workspace_id"]
        ):
            pass


def test_admission_respects_existing_workspace_lock(tmp_path):
    work = tmp_path / "work"
    workspace = initialize(work, "busy", "development", "us-east-1")
    handoff = tmp_path / "handoff.zip"
    checkpoint.export(work, handoff, handoff=True)
    claim_handoff(tmp_path / "gateway", handoff)
    value = request(workspace["workspace_id"])
    accept(
        tmp_path / "gateway",
        value,
        message_id="message-1",
        receive_count=1,
        at="2026-10-09T12:00:00Z",
    )
    owned = tmp_path / "gateway/workspaces" / workspace["workspace_id"]
    with locked(owned):
        state = reconcile_request(
            tmp_path / "gateway",
            value["request_id"],
            at="2026-10-09T12:00:01Z",
        )
    assert state["states"]["admission"] == "pending"
    observation = json.loads(
        (
            tmp_path
            / "gateway/requests"
            / value["request_id"]
            / "admission.json"
        ).read_text()
    )
    assert observation["reason"] == "workspace_busy"


def test_administrative_status_is_bounded_and_does_not_receive_dlq(tmp_path):
    client = FakeSQS()
    result = administrative_status(
        tmp_path / "gateway",
        PRIMARY_ARN,
        DLQ_ARN,
        client,
    )
    assert result["queues"]["max_receive_count"] == 3
    assert result["queues"]["primary"]["approximate_available"] == 0
    assert result["ledger"]["requests"] == 0
    assert client.receive_calls == []


def test_systemd_service_is_persistent_and_has_no_host_uptime_timer():
    service = (
        Path(__file__).resolve().parents[1]
        / "src/zog/host_deploy/gateway/host-deploy-gateway.service"
    ).read_text()
    assert "Restart=on-failure" in service
    assert "StateDirectory=host-deploy-gateway" in service
    assert "EnvironmentFile=-/etc/host-deploy/gateway.env" in service
    assert "RuntimeMaxSec" not in service
    assert "id-token" not in service
    assert "AWS_ACCESS_KEY_ID" not in service
