"""First Fonts original issues.opened -> reviewed immutable request -> one FIFO attempt.

All tests are offline; no real GitHub issue, SQS message or SSM command.
"""
import copy
import json
from pathlib import Path

import pytest

from zog.host_deploy.gateway import github_dispatch as dispatch
from zog.host_deploy.gateway.github_configuration import prepare_configured
from zog.host_deploy.gateway.protocol import canonical_bytes, request_digest


WORKSPACE = "123456789abcdef0123456789abcdef0"
SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
TASK = "graphics-fonts-image-v1"
QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/zog-build-requests.fifo"


def intent():
    return {
        "schema": 1,
        "workspace_id": WORKSPACE,
        "operation": "build.submit",
        "parameters": {"lane": "compiler-fonts", "task": TASK},
    }


def issue_event(*, number=104, actor="zog144", request=None):
    payload = intent() if request is None else request
    return {
        "action": "opened",
        "repository": {"full_name": "zog144/host-deploy", "id": 789},
        "sender": {"login": actor, "type": "User"},
        "issue": {
            "number": number,
            "state": "open",
            "user": {"login": actor},
            "body": dispatch.ISSUE_MARKER + "\n```json\n"
                    + json.dumps(payload, sort_keys=True) + "\n```",
        },
    }


def settings():
    return {
        "GITHUB_EVENT_NAME": "issues",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR": "zog144",
        "GITHUB_TRIGGERING_ACTOR": "zog144",
        "GITHUB_REPOSITORY": "zog144/host-deploy",
        "GITHUB_REPOSITORY_ID": "789",
        "ZOG_GATEWAY_DISPATCH_REVISION": "e4ac0873367cdb8a0ebe8aec34387c87d99c81e9",
        "ZOG_GATEWAY_AWS_REGION": "us-east-1",
        "ZOG_GATEWAY_QUEUE_URL": QUEUE,
        "ZOG_GATEWAY_ROLE_ARN": "arn:aws:iam::123456789012:role/zog-gateway",
        "ZOG_GATEWAY_AUTHORIZED_ACTORS": '["zog144"]',
        "ZOG_GATEWAY_ALLOWED_OPERATIONS": '["build.submit"]',
        "ZOG_GATEWAY_FONTS_ENABLED": "true",
    }


def prepared(tmp_path, *, event=None, env=None):
    event = issue_event() if event is None else event
    env = settings() if env is None else env
    tmp_path.mkdir(parents=True, exist_ok=True)
    event_path = tmp_path / "opened.json"
    event_path.write_text(json.dumps(event))
    output = tmp_path / "prepared.json"
    summary = prepare_configured(event_path, output, env)
    return summary, json.loads(output.read_text()), output


def test_original_issue_constructs_stable_gateway_identity_and_exact_source(tmp_path):
    summary, request, output = prepared(tmp_path)
    expected_id = dispatch.first_fonts_request_id(104)
    assert request == {
        "schema": 1, "request_id": expected_id, "workspace_id": WORKSPACE,
        "operation": "build.submit",
        "parameters": {"lane": "compiler-fonts", "task": TASK},
        "source": {"repository": "zog144/image-build", "commit": SOURCE},
        "origin": {
            "repository": "zog144/host-deploy", "issue_number": 104,
            "trigger_actor": "zog144",
        },
    }
    assert summary["request_id"] == expected_id
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_bytes() == canonical_bytes(request) + b"\n"
    assert dispatch.first_fonts_request_id(104) == expected_id
    assert dispatch.first_fonts_request_id(105) != expected_id
    assert dispatch.FIRST_FONTS_SOURCE["commit"] == SOURCE
    assert request_digest(request) == request_digest(copy.deepcopy(request))


def test_same_original_issue_has_same_identity_after_multiple_preparations(tmp_path):
    first, request, _ = prepared(tmp_path / "one")
    second, again, _ = prepared(tmp_path / "two")
    assert first == second and request == again


@pytest.mark.parametrize("mutation", [
    lambda e: e.update(action="edited"),
    lambda e: e["repository"].update(full_name="zog144/image-build"),
    lambda e: e["repository"].update(id=123),
    lambda e: e["sender"].update(login="intruder"),
    lambda e: e["issue"]["user"].update(login="intruder"),
    lambda e: e["issue"].update(state="closed"),
    lambda e: e["issue"].update(number=0),
    lambda e: e["issue"].update(body="malformed"),
])
def test_wrong_event_or_actor_refused_before_any_request_file(tmp_path, mutation):
    event = issue_event()
    mutation(event)
    with pytest.raises(ValueError):
        prepared(tmp_path, event=event)
    assert not (tmp_path / "prepared.json").exists()


@pytest.mark.parametrize("field,value", [
    ("source", {"repository": "zog144/image-build", "commit": SOURCE}),
    ("request_id", "f" * 32),
    ("origin", {"repository": "zog144/host-deploy", "issue_number": 104,
                "trigger_actor": "zog144"}),
])
def test_issue_body_cannot_choose_immutable_dispatch_fields(tmp_path, field, value):
    request = intent()
    request[field] = value
    with pytest.raises(ValueError):
        prepared(tmp_path, event=issue_event(request=request))
    assert not (tmp_path / "prepared.json").exists()


@pytest.mark.parametrize("key,value", [
    ("GITHUB_RUN_ATTEMPT", "2"),
    ("GITHUB_EVENT_NAME", "workflow_dispatch"),
    ("GITHUB_TRIGGERING_ACTOR", "someone-else"),
    ("GITHUB_REPOSITORY", "zog144/image-build"),
    ("ZOG_GATEWAY_AUTHORIZED_ACTORS", '["someone-else"]'),
    ("ZOG_GATEWAY_ALLOWED_OPERATIONS", '["build.status"]'),
    ("ZOG_GATEWAY_FONTS_ENABLED", ""),
    ("ZOG_GATEWAY_FONTS_ENABLED", "false"),
    ("ZOG_GATEWAY_DISPATCH_REVISION", "main"),
])
def test_missing_native_operator_enablement_or_invalid_workflow_identity_holds(
        tmp_path, key, value):
    env = settings()
    env[key] = value
    with pytest.raises(ValueError):
        prepared(tmp_path, env=env)
    assert not (tmp_path / "prepared.json").exists()


class FakeSQS:
    def __init__(self, *, fails=False):
        self.calls = []
        self.fails = fails

    def send_message(self, **kwargs):
        self.calls.append(kwargs)
        if self.fails:
            raise TimeoutError("uncertain acknowledgement")
        return {"MessageId": "fifo-message", "SequenceNumber": "123"}


def test_exact_one_fifo_send_with_stable_issue_deduplication(tmp_path):
    _, request, _ = prepared(tmp_path)
    sqs = FakeSQS()
    receipt = dispatch.submit_request(QUEUE, request, client=sqs)
    assert len(sqs.calls) == 1
    assert sqs.calls[0] == {
        "QueueUrl": QUEUE,
        "MessageBody": canonical_bytes(request).decode("ascii"),
        "MessageGroupId": WORKSPACE,
        "MessageDeduplicationId": dispatch.first_fonts_request_id(104),
    }
    assert receipt["request_id"] == dispatch.first_fonts_request_id(104)
    assert receipt["request_sha256"] == request_digest(request)


def test_uncertain_acknowledgement_is_not_automatically_retried(tmp_path):
    _, request, _ = prepared(tmp_path)
    sqs = FakeSQS(fails=True)
    with pytest.raises(TimeoutError):
        dispatch.submit_request(QUEUE, request, client=sqs)
    assert len(sqs.calls) == 1


def test_existing_gateway_default_branch_event_workflow_and_template():
    repo = Path(__file__).resolve().parents[1]
    wf = (repo / ".github/workflows/gateway-issue-dispatch.yml").read_text()
    template = (repo / ".github/ISSUE_TEMPLATE/first-fonts-gateway.md").read_text()
    assert "issues:\n    types: [opened]" in wf
    assert "github.run_attempt == 1" in wf
    assert "ZOG_GATEWAY_FONTS_ENABLED: ${{ vars.ZOG_GATEWAY_FONTS_ENABLED }}" in wf
    assert "vars.ZOG_GATEWAY_DISPATCH_REVISION" in wf
    assert "ZOG_GATEWAY_SUBMIT_ENABLED" in wf
    assert "github_configuration --event" in wf
    assert "github_dispatch submit --request" in wf
    assert "id-token: write" in wf
    assert "persist-credentials: false" in wf
    assert "pull_request_target" not in wf
    assert "github.event.issue.body }}" not in wf
    assert dispatch.ISSUE_MARKER in template
    assert TASK in template
    assert '"source"' not in template and '"request_id"' not in template
    source = (repo / "src/zog/host_deploy/gateway/github_dispatch.py").read_text()
    assert 'retries={"total_max_attempts": 1}' in source
