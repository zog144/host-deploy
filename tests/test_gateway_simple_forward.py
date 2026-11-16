"""GitHub issue -> FIFO -> fixed SSM mapping, no compiler dossier.

Mock only AWS and the actual installed workspace/SSM remote executor; the
authorization/parser, SQS dedup, durable ledger and recovery are real.
"""
import json
from pathlib import Path

import pytest

from zog.host_deploy import image_build_lanes
from zog.host_deploy.gateway import (
    github_dispatch, simple_forward, image_build_dispatch,
    image_build_execution,
)
from zog.host_deploy.gateway.consumer import GatewayConsumer
from zog.host_deploy.gateway.ledger import (
    accept, prepare_dispatch, load_dispatch, load_request,
    reconcile_request, reconcile_dispatch,
)
from zog.host_deploy.gateway.protocol import canonical_bytes, validate_request

from test_gateway_consumer import FakeSQS, PRIMARY_ARN, DLQ_ARN, message


REQUEST_ID = "f" * 32
WORKSPACE = "1" * 32
SELECTION = "a" * 64
SNAPSHOT = "sha256:" + "b" * 64
SOURCE = {
    "repository": "zog144/image-build",
    "revision": image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
}
TARGET = {"instance_id": "i-0123456789abcdef0",
          "region": "us-east-1", "account_id": "123456789012"}


def issue(*, parameters=None, actor="zog144"):
    value = {
        "schema": 1, "workspace_id": WORKSPACE, "operation": "build.submit",
        "parameters": parameters or {
            "lane": "gateway-first-fonts-runtime",
            "task": github_dispatch.FIRST_FONTS_TASK,
            "selection": SELECTION, "recipe_snapshot": SNAPSHOT,
        },
    }
    return {"action": "opened",
            "repository": {"full_name": "zog144/host-deploy"},
            "sender": {"login": actor},
            "issue": {"number": 77, "state": "open",
                      "user": {"login": actor},
                      "body": github_dispatch.ISSUE_MARKER + "\n```json\n"
                      + json.dumps(value) + "\n```"}}


def approved():
    return github_dispatch.prepare_event(issue(), frozenset({"zog144"}))


def admit(root, value):
    accept(root, value, message_id="msg-1", receive_count=1)
    # The real trusted workspace admission is source-tested elsewhere. We
    # simulate one *already admitted* owned workspace for the SSM tests.
    from zog.host_deploy.gateway import ledger
    from zog.host_deploy.gateway.protocol import transition
    from zog.host_deploy.workspace import save
    with ledger.request_lock(root, value["request_id"]) as directory:
        state = ledger._load_state(directory)
        state = transition(state, "admission", "admitted", ledger.utc_now())
        save(directory / "state.json", state)


def direct_binding(value):
    return {
        "schema": 3, "direct_forward": True,
        "request_id": value["request_id"],
        "workspace_id": WORKSPACE, "lane": "gateway-first-fonts-runtime",
        "target": TARGET, "source": SOURCE,
        "remote_request": {
            "schema": "image-build-remote-operation-v1",
            "operation_id": value["request_id"],
            "operation": "pipeline.submit",
            "source": SOURCE,
            "arguments": {
                "mode": "image", "selection": SELECTION,
                "recipe_snapshot": SNAPSHOT,
                "targets": ["libpng-final", "freetype-final", "fontconfig-final"],
            },
        },
        "remote_request_sha256": "0" * 64,
    }


@pytest.fixture
def forwarding(tmp_path, monkeypatch):
    root = tmp_path / "gateway"
    value = approved()
    admit(root, value)
    binding = direct_binding(value)
    counters = {"send": [], "inspect": [], "new_host": []}
    def prepared(gateway, request_id, *, direct_forward):
        assert gateway == root and request_id == value["request_id"]
        assert direct_forward is True
        return prepare_dispatch(root, request_id, binding)
    monkeypatch.setattr(simple_forward, "prepare_image_build_dispatch", prepared)
    monkeypatch.setattr(simple_forward, "_binding",
                        lambda record: record["binding"])
    monkeypatch.setattr(simple_forward, "verify_current_target",
                        lambda gateway, selected: TARGET)
    monkeypatch.setattr(simple_forward, "remote_script",
                        lambda selected: "fixed-reviewed-remote-script")
    class Host:
        def __init__(self, config):
            assert config == TARGET
            counters["new_host"].append(config)
        def submit_command(self, script, seconds):
            assert script == "fixed-reviewed-remote-script"
            assert seconds == simple_forward.CONTROL_TIMEOUT_SECONDS
            counters["send"].append(script)
            return "command-123"
        def inspect_command(self, command_id):
            counters["inspect"].append(command_id)
            return {"CommandId": command_id,
                    "InstanceId": TARGET["instance_id"],
                    "Status": "Success",
                    "StandardOutputContent": json.dumps({
                        "schema": image_build_execution.RECEIPT_SCHEMA,
                        "request_id": REQUEST_ID,
                        "remote_request_sha256": "0" * 64,
                        "result": {"status": "pending",
                                   "pipeline_id": "c" * 32},
                    })}
    return root, value, binding, Host, counters


def test_authorized_issue_fifo_to_configured_ssm_and_recovered_result(forwarding):
    root, value, binding, Host, counters = forwarding
    first = simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    assert first["phase"] == "prepared"
    assert load_dispatch(root, REQUEST_ID)["binding"]["direct_forward"] is True
    second = simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    assert second == {"request_id": REQUEST_ID, "phase": "submitted",
                      "command_id": "command-123"}
    assert len(counters["send"]) == 1
    assert load_dispatch(root, REQUEST_ID)["command_id"] == "command-123"
    # Simulate a restart/lost result, preserving the original CommandId.
    reconcile_dispatch(root, REQUEST_ID)
    finished = simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    assert finished["phase"] == "completed"
    assert finished["command_id"] == "command-123"
    assert counters["inspect"] == ["command-123"]
    assert len(counters["send"]) == 1
    saved = json.loads((root / "requests" / REQUEST_ID /
                        "remote-result.json").read_text())
    assert saved["command_id"] == "command-123"
    assert saved["result"]["result"]["pipeline_id"] == "c" * 32
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "completed"


def test_acknowledgement_loss_is_never_automatically_resent(forwarding, monkeypatch):
    root, value, binding, Host, counters = forwarding
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    class Lost(Host):
        def submit_command(self, script, seconds):
            counters["send"].append(script)
            raise TimeoutError("lost SSM reply")
    with pytest.raises(TimeoutError):
        simple_forward.advance(root, REQUEST_ID, host_factory=Lost)
    assert load_dispatch(root, REQUEST_ID)["phase"] == "submission_uncertain"
    assert simple_forward.advance(root, REQUEST_ID, host_factory=Host)["phase"] == "submission_uncertain"
    assert len(counters["send"]) == 1


def test_restart_with_submitting_intent_remains_uncertain(forwarding):
    root, value, binding, Host, counters = forwarding
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    from zog.host_deploy.gateway.ledger import mark_dispatch_submitting
    mark_dispatch_submitting(root, REQUEST_ID)
    reconcile_dispatch(root, REQUEST_ID)
    assert simple_forward.advance(root, REQUEST_ID, host_factory=Host)["phase"] == "submission_uncertain"
    assert counters["send"] == []


def test_duplicate_delivery_and_conflicting_request_rejected(forwarding):
    root, value, binding, Host, counters = forwarding
    _, duplicate = accept(root, value, message_id="msg-2", receive_count=2)
    assert duplicate
    conflicting = json.loads(json.dumps(value))
    conflicting["parameters"]["selection"] = "c" * 64
    from zog.host_deploy.gateway.ledger import LedgerConflict
    with pytest.raises(LedgerConflict):
        accept(root, conflicting, message_id="msg-3", receive_count=3)
    assert counters["send"] == []


@pytest.mark.parametrize("mutation", (
    lambda e: e["sender"].update(login="intruder"),
    lambda e: e["repository"].update(full_name="zog144/another"),
    lambda e: e["issue"].update(state="closed"),
    lambda e: e.update(action="edited"),
))
def test_unauthorized_github_issue_does_not_become_ssm_request(mutation):
    event = issue()
    mutation(event)
    with pytest.raises(ValueError):
        github_dispatch.prepare_event(event, frozenset({"zog144"}))


@pytest.mark.parametrize("field,value", (
    ("selection", "a" * 40),
    ("selection", "/bin/sh"),
    ("recipe_snapshot", "main"),
    ("recipe_snapshot", "sha256:" + "z" * 64),
))
def test_invalid_producer_arguments_rejected_before_sqs(field, value):
    event = issue()
    marker = event["issue"]["body"]
    raw = json.loads(marker.split("```json\n", 1)[1].split("\n```", 1)[0])
    raw["parameters"][field] = value
    event["issue"]["body"] = github_dispatch.ISSUE_MARKER + "\n```json\n" + json.dumps(raw) + "\n```"
    with pytest.raises(ValueError):
        github_dispatch.prepare_event(event, frozenset({"zog144"}))


def test_unknown_or_old_incomplete_font_request_denied_by_direct_route(tmp_path):
    root = tmp_path / "gateway"
    value = approved()
    value["parameters"] = {"lane": "gateway-first-fonts-runtime",
                           "task": github_dispatch.FIRST_FONTS_TASK}
    admit(root, value)
    with pytest.raises(simple_forward.ForwardingDenied):
        simple_forward.advance(root, value["request_id"])


def test_source_owned_finite_mapping_uses_producer_request_not_catalogue():
    value = approved()
    lane = {
        "source_repository": "zog144/image-build",
        "source_revision": image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
        "monthly_pin_repository_path": image_build_lanes.FIRST_FONTS_ORIGINAL_PIN_PATH,
        "monthly_pin_identity": image_build_lanes.FIRST_FONTS_ORIGINAL_PIN_IDENTITY,
    }
    request, task = image_build_dispatch._remote_request(value, lane, direct_forward=True)
    assert task is None
    assert request["operation"] == "pipeline.submit"
    assert request["arguments"]["selection"] == SELECTION
    assert request["arguments"]["recipe_snapshot"] == SNAPSHOT
    assert request["arguments"]["targets"] == [
        "libpng-final", "freetype-final", "fontconfig-final"]
    for unsupported in ("shell.execute", "toolchain.submit"):
        bad = dict(value, operation=unsupported)
        with pytest.raises((RuntimeError, KeyError)):
            image_build_dispatch._remote_request(bad, lane, direct_forward=True)


def test_no_catalogue_or_compiler_dossier_required_in_simple_forward():
    import inspect
    source = inspect.getsource(simple_forward)
    for forbidden in (
        "compiler-selection.json", "compiler_provenance",
        "origin_lane", "issuer_policy", "producer_binding",
        "read_compiler_base_receipt", "load_task_catalogue",
        "AWS-RunShellScript",
    ):
        assert forbidden not in source
