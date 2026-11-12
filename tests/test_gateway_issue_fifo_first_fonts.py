"""Original issue → authorized Actions sender → FIFO → durable gateway acceptance.

No AWS, SSM, compiler process or catalogue-installation side effects. The
separate native operator must select the exact installed root-owned catalogue.
"""
import copy
import json
import os
from pathlib import Path

import pytest

from zog.host_deploy.gateway import (
    github_configuration, github_dispatch, protocol, task_catalogue,
    generic_pipeline,
)
from zog.host_deploy.gateway.consumer import GatewayConsumer
from zog.host_deploy.gateway.ledger import load_request
from test_gateway_consumer import FakeSQS, PRIMARY_URL, PRIMARY_ARN, DLQ_ARN

SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
PIN = "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
WORKSPACE_ID = "2" * 32
LANE = "first-fonts"
ACTOR = "zog144"
ISSUE_NUMBER = 101
REQUEST_ID = github_dispatch.first_fonts_request_id(ISSUE_NUMBER)
REGION = "us-east-1"
ACCOUNT = "123456789012"
REVIEWED_PR7 = "3ee7f24b0869feead798e35d75722d63e2e5b7c9"


def intent():
    return {
        "schema": 1, "workspace_id": WORKSPACE_ID,
        "operation": "build.submit",
        "parameters": {"lane": LANE, "task": "graphics-fonts-image-v1"},
    }


def issue_event():
    return {
        "action": "opened",
        "repository": {"full_name": "zog144/host-deploy", "id": 789},
        "sender": {"login": ACTOR, "type": "User"},
        "issue": {
            "number": ISSUE_NUMBER, "state": "open",
            "user": {"login": ACTOR},
            "body": github_dispatch.ISSUE_MARKER + "\n```json\n" +
                    json.dumps(intent()) + "\n```",
        },
    }


def actions_environment():
    return {
        "GITHUB_EVENT_NAME": "issues", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR": ACTOR, "GITHUB_TRIGGERING_ACTOR": ACTOR,
        "GITHUB_REPOSITORY": "zog144/host-deploy",
        "GITHUB_REPOSITORY_ID": "789",
        "ZOG_GATEWAY_DISPATCH_REVISION": "a" * 40,
        "ZOG_GATEWAY_AWS_REGION": REGION,
        "ZOG_GATEWAY_QUEUE_URL": PRIMARY_URL,
        "ZOG_GATEWAY_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/zog-github-sqs",
        "ZOG_GATEWAY_AUTHORIZED_ACTORS": json.dumps([ACTOR]),
        "ZOG_GATEWAY_ALLOWED_OPERATIONS": '["build.submit"]',
        "ZOG_GATEWAY_FONTS_ENABLED": "true",
    }


class CapturingFIFO(FakeSQS):
    def __init__(self):
        super().__init__()
        self.sent = []

    def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return {"MessageId": "fifo-original-1", "SequenceNumber": "1001"}


def prepare(tmp_path, *, event=None, environment=None):
    event_path = tmp_path / "github-event.json"
    request_path = tmp_path / "prepared.json"
    event_path.write_text(json.dumps(issue_event() if event is None else event))
    summary = github_configuration.prepare_configured(
        event_path, request_path,
        actions_environment() if environment is None else environment,
    )
    return request_path, summary


def catalogue():
    entries = task_catalogue.REVIEWED_IMAGE_TASKS["graphics-fonts-image-v1"]
    return task_catalogue.validate({
        "schema": task_catalogue.SCHEMA,
        "tasks": {
            "graphics-fonts-image-v1": {
                "source_repository": "zog144/image-build",
                "source_revision": SOURCE,
                "lane": LANE, "lane_owner": "compiler-host",
                "monthly_pin_repository_path": "project/pins/2026-10-01/commit-pin.py",
                "monthly_pin_identity": PIN, "pin_date": "2026-10-01",
                "retained_acceptance_sha256": "sha256:" + "c" * 64,
                "entries": [{"id": x, "project": y, "recipe": z}
                            for x, y, z in entries["entries"]],
                "arguments": {
                    "mode": "image", "selection": "d" * 64,
                    "compiler_base": "sha256:" + "e" * 64,
                    "targets": list(entries["targets"]),
                },
            },
        },
    })


def test_real_issue_configuration_fifo_receiver_round_trip_and_redelivery(tmp_path):
    filename, summary = prepare(tmp_path)
    request = protocol.loads_request(filename.read_bytes())
    assert request["origin"] == {
        "repository": "zog144/host-deploy",
        "issue_number": ISSUE_NUMBER,
        "trigger_actor": ACTOR,
    }
    assert summary["issue_number"] == ISSUE_NUMBER
    assert request["source"] == github_dispatch.FIRST_FONTS_SOURCE
    assert request["request_id"] == github_dispatch.first_fonts_request_id(ISSUE_NUMBER)
    client = CapturingFIFO()
    sent = github_dispatch.submit_request(PRIMARY_URL, request, client=client)
    assert sent["request_sha256"] == protocol.request_digest(request)
    assert client.sent == [{
        "QueueUrl": PRIMARY_URL,
        "MessageBody": protocol.canonical_bytes(request).decode("ascii"),
        "MessageGroupId": WORKSPACE_ID,
        "MessageDeduplicationId": REQUEST_ID,
    }]
    state_dir = tmp_path / "gateway"
    receiver = GatewayConsumer(state_dir, PRIMARY_ARN, DLQ_ARN, client=client)
    message = {
        "MessageId": sent["message_id"],
        "ReceiptHandle": "receipt-1",
        "Body": client.sent[0]["MessageBody"],
        "Attributes": {"ApproximateReceiveCount": "1"},
    }
    result = receiver.handle_message(message)
    assert result == {
        "accepted": True, "duplicate": False, "request_id": REQUEST_ID,
        "acknowledgement": "acked", "admission": "pending",
    }
    retained = load_request(state_dir, REQUEST_ID)
    assert retained["request"] == request
    assert retained["request_sha256"] == sent["request_sha256"]
    assert retained["states"]["dispatch"] == "not_started"
    assert receiver.approved_generic_catalogue is None
    assert receiver._advance_one_reviewed() is None
    redelivery = dict(message, MessageId="fifo-original-replay",
                      ReceiptHandle="receipt-2")
    assert receiver.handle_message(redelivery)["duplicate"] is True
    assert load_request(state_dir, REQUEST_ID)["request"] == request
    assert len(client.sent) == 1
    assert len(client.deleted) == 2


@pytest.mark.parametrize("mutation", [
    lambda e, env: e.update(action="edited"),
    lambda e, env: e["sender"].update(login="intruder"),
    lambda e, env: e["issue"]["user"].update(login="intruder"),
    lambda e, env: e["repository"].update(full_name="other/repo"),
    lambda e, env: e["issue"].update(number=0),
    lambda e, env: env.update(GITHUB_RUN_ATTEMPT="2"),
    lambda e, env: env.update(GITHUB_EVENT_NAME="pull_request"),
    lambda e, env: env.update(ZOG_GATEWAY_ALLOWED_OPERATIONS='["host.status"]'),
    lambda e, env: env.update(GITHUB_REPOSITORY_ID="42"),
])
def test_unauthorized_or_nonoriginal_issue_event_never_prepares_fifo(tmp_path, mutation):
    event, env = issue_event(), actions_environment()
    mutation(event, env)
    with pytest.raises(github_dispatch.GitHubDispatchError):
        prepare(tmp_path, event=event, environment=env)
    assert not (tmp_path / "prepared.json").exists()


def test_exact_first_fonts_receipt_and_source_are_required_for_gateway_catalogue():
    selected = catalogue()
    item = task_catalogue.select(
        selected, "graphics-fonts-image-v1",
        repository="zog144/image-build", revision=SOURCE, lane=LANE,
        monthly_pin_repository_path="project/pins/2026-10-01/commit-pin.py",
        monthly_pin_identity=PIN,
    )
    assert item["arguments"]["compiler_base"] == "sha256:" + "e" * 64
    stage = {"request_id": REQUEST_ID, "task":item, "source":{
             "repository":"zog144/image-build","revision":SOURCE}}
    # Actual pipeline.submit carries the original compiler receipt reference.
    op = generic_pipeline._request(stage, "submit", REQUEST_ID, {
        "request_id":REQUEST_ID,"recipe_identity":"sha256:"+"f"*64})
    assert op["arguments"]["compiler_base"] == item["arguments"]["compiler_base"]
    for field in ("compiler_base", "targets"):
        bad = copy.deepcopy(selected)
        bad["tasks"]["graphics-fonts-image-v1"]["arguments"].pop(field)
        with pytest.raises(task_catalogue.TaskCatalogueError):
            task_catalogue.validate(bad)
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.select(selected, "graphics-fonts-image-v1",
                              repository="zog144/image-build", revision="f"*40,
                              lane=LANE)


def test_selected_pr7_files_match_exact_source_review():
    base = os.environ.get("ZOG_HOSTDEPLOY_FONTS_PR7")
    if base is None:
        pytest.skip("cross-repository source pin is exercised by trusted-host CI")
    root = Path(base)
    for name in ("task_catalogue.py", "graphics_base_acceptance.py",
                 "graphics_catalogue_owner.py"):
        relative = Path("src/zog/host_deploy/gateway") / name
        selected = Path("src/zog/host_deploy/gateway") / name
        assert (root / relative).read_bytes() == selected.read_bytes()
    assert REVIEWED_PR7 == "3ee7f24b0869feead798e35d75722d63e2e5b7c9"


def test_workflow_issue_opened_and_actions_to_sqs_only():
    workflow = Path(".github/workflows/gateway-issue-dispatch.yml").read_text()
    assert "types: [opened]" in workflow
    assert "github.run_attempt == 1" in workflow
    assert "github_configuration --event" in workflow
    assert "github_dispatch submit" in workflow
    assert "vars.ZOG_GATEWAY_SUBMIT_ENABLED == 'true'" in workflow
    assert "id-token: write" in workflow
    assert "send_command" not in workflow.lower()
    assert "ssm:" not in workflow.lower()
