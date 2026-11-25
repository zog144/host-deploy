"""GitHub issue -> FIFO -> fixed SSM mapping, no compiler dossier.

Mock only AWS and the actual installed workspace/SSM remote executor; the
authorization/parser, SQS dedup, durable ledger and recovery are real.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from zog.host_deploy import image_build_lanes
from zog.host_deploy.gateway import (
    github_dispatch, simple_forward, image_build_dispatch, fonts_owner_sender,
    image_build_execution,
)
from zog.host_deploy.gateway.consumer import GatewayConsumer
from zog.host_deploy.gateway.ledger import (
    accept, prepare_dispatch, load_dispatch, load_request,
    reconcile_request, reconcile_dispatch,
)
from zog.host_deploy.gateway.protocol import canonical_bytes, validate_request

from test_gateway_consumer import FakeSQS, PRIMARY_ARN, DLQ_ARN, message


REQUEST_ID = github_dispatch.first_fonts_request_id(77)
WORKSPACE = "1" * 32
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
        "schema": 4, "direct_forward": True,
        "request_id": value["request_id"],
        "workspace_id": WORKSPACE, "lane": "gateway-first-fonts-runtime",
        "project_root": "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime",
        "python_executable": sys.executable,
        "target": TARGET, "source": SOURCE,
        "remote_request": {
            "schema": "image-build-remote-operation-v1",
            "operation_id": value["request_id"],
            "operation": "pipeline.submit",
            "source": SOURCE,
            "arguments": {
                "mode": "image",
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
    # The synthetic compiler Project is only inspected through FakeHost SSM.
    binding["project_root"] = str(tmp_path / "remote-compiler-project")
    monkeypatch.setattr(simple_forward, "FIRST_FONTS_COMPILER_PROJECT_UID",
                        os.geteuid())
    counters = {"send": [], "inspect": [], "new_host": [],
                "read_only_probes": [], "probe_results": {}}
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
    # Historical transport unit fixtures fake the protected owner itself.
    # The dedicated root-control contract tests below exercise its real
    # authorization checks and journal interface.
    monkeypatch.setattr(fonts_owner_sender, "ready",
                        lambda *args, **kwargs: None)
    monkeypatch.setattr(fonts_owner_sender, "submit_once",
                        lambda root, operation_id, **kwargs:
                        kwargs["host"].submit_command(
                            kwargs["script"], seconds=kwargs["seconds"]))
    class Host:
        def __init__(self, config):
            assert config == TARGET
            counters["new_host"].append(config)
        def submit_command(self, script, seconds):
            if seconds == 120:
                # Simulated read-only SSM execution on a different Host.
                assert script.startswith(sys.executable + " -I -B -c ")
                assert "gateway-requests" in script
                assert "subprocess" not in script
                assert "pipeline.resume" not in script
                assert "send_command" not in script
                observed = subprocess.run(script, shell=True,
                                          capture_output=True, text=True, timeout=10)
                identity = "inspection-" + str(
                    len(counters["read_only_probes"]) + 1)
                counters["read_only_probes"].append((identity, script))
                counters["probe_results"][identity] = {
                    "CommandId": identity, "InstanceId": TARGET["instance_id"],
                    "Status": "Success" if observed.returncode == 0 else "Failed",
                    "StandardOutputContent": observed.stdout,
                    "StandardErrorContent": observed.stderr,
                }
                return identity
            assert script == "fixed-reviewed-remote-script"
            assert seconds == simple_forward.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS
            counters["send"].append(script)
            return "command-123"
        def inspect_command(self, command_id):
            counters["inspect"].append(command_id)
            if command_id in counters["probe_results"]:
                return counters["probe_results"][command_id]
            return {"CommandId": command_id,
                    "InstanceId": TARGET["instance_id"],
                    "Status": "Success",
                    "StandardOutputContent": json.dumps({
                        "schema": image_build_execution.RECEIPT_SCHEMA,
                        "request_id": REQUEST_ID,
                        "remote_request_sha256": "0" * 64,
                        "result": {"status": "pending", "uncertainty": False,
                                   "source_revision": SOURCE["revision"],
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
    assert finished["phase"] == "running"
    assert finished["command_id"] == "command-123"
    assert counters["inspect"] == ["command-123"]
    assert len(counters["send"]) == 1
    saved = json.loads((root / "requests" / REQUEST_ID /
                        "dispatch-observation.json").read_text())
    assert saved["command_id"] == "command-123"
    assert saved["observation"]["producer"]["pipeline_id"] == "c" * 32
    assert not (root / "requests" / REQUEST_ID / "remote-result.json").exists()
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "running"


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
    conflicting["parameters"]["lane"] = "another-managed-lane"
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
    ("selection", "a" * 64),
    ("recipe_snapshot", "sha256:" + "b" * 64),
    ("shell", "rm -rf /"),
))
def test_compiler_state_arguments_are_not_accepted_from_github(field, value):
    event = issue()
    marker = event["issue"]["body"]
    raw = json.loads(marker.split("```json\n", 1)[1].split("\n```", 1)[0])
    raw["parameters"][field] = value
    event["issue"]["body"] = github_dispatch.ISSUE_MARKER + "\n```json\n" + json.dumps(raw) + "\n```"
    with pytest.raises(ValueError):
        github_dispatch.prepare_event(event, frozenset({"zog144"}))


def test_wrong_lane_is_not_direct_forwardable():
    value = approved()
    value["parameters"]["lane"] = "unreviewed-lane"
    lane = {
        "source_repository": SOURCE["repository"],
        "source_revision": SOURCE["revision"],
    }
    with pytest.raises(RuntimeError, match="not supported"):
        image_build_dispatch._remote_request(value, lane, direct_forward=True)


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
    assert set(request["arguments"]) == {"mode", "targets"}
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


def test_real_sqs_delivery_is_acked_then_forwarded_once(forwarding, monkeypatch):
    """SQS consumer admission, immutable request, one SSM send and readback."""
    from zog.host_deploy.gateway import consumer as consumer_module
    from zog.host_deploy.gateway import ledger
    from zog.host_deploy.gateway.protocol import transition
    from zog.host_deploy.workspace import save
    root, value, binding, Host, counters = forwarding
    # The fixture created the same admitted request already; simulate duplicate
    # SQS delivery from the original authorized GitHub issue.
    sqs = FakeSQS([message(value, message_id="msg-2", receive_count=2)])
    service = GatewayConsumer(root, PRIMARY_ARN, DLQ_ARN, client=sqs,
                              direct_forward=True)

    original = simple_forward.advance_one
    monkeypatch.setattr(simple_forward, "advance_one",
                        lambda selected: original(selected, host_factory=Host))
    result = service.poll_once(wait_seconds=0)
    assert result["accepted"] is True and result["duplicate"] is True
    assert result["acknowledgement"] == "acked"
    assert len(sqs.deleted) == 1
    assert load_dispatch(root, value["request_id"])["phase"] == "prepared"
    assert counters["send"] == []

    service.poll_once(wait_seconds=0)
    assert len(counters["send"]) == 1
    assert load_dispatch(root, value["request_id"])["command_id"] == "command-123"

    service.poll_once(wait_seconds=0)
    assert load_request(root, value["request_id"])["states"]["completion"] == "running"
    assert counters["inspect"] == ["command-123"]
    assert len(counters["send"]) == 1


def test_ssm_wrong_command_identity_or_forged_success_never_completes(forwarding, monkeypatch):
    root, value, binding, Host, counters = forwarding
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)

    class WrongCommand(Host):
        def inspect_command(self, identifier):
            return {"CommandId": "different", "InstanceId": TARGET["instance_id"],
                    "Status": "Success"}
    with pytest.raises(simple_forward.ForwardingDenied, match="identity"):
        simple_forward.advance(root, REQUEST_ID, host_factory=WrongCommand)
    assert load_request(root, REQUEST_ID)["states"]["completion"] != "completed"

    class WrongReceipt(Host):
        def inspect_command(self, identifier):
            return {"CommandId": identifier, "InstanceId": TARGET["instance_id"],
                    "Status": "Success",
                    "StandardOutputContent": json.dumps({
                        "schema": image_build_execution.RECEIPT_SCHEMA,
                        "request_id": REQUEST_ID,
                        "remote_request_sha256": "9" * 64,
                        "result": {"status": "completed"}})}
    with pytest.raises(simple_forward.ForwardingDenied, match="differs"):
        simple_forward.advance(root, REQUEST_ID, host_factory=WrongReceipt)
    assert len(counters["send"]) == 1


def test_direct_mode_rejects_legacy_catalogue_supervisor_configuration(tmp_path):
    client = FakeSQS()
    with pytest.raises(ValueError, match="cannot be mixed"):
        GatewayConsumer(
            tmp_path / "gateway", PRIMARY_ARN, DLQ_ARN, client=client,
            direct_forward=True,
            approved_generic_catalogue={"schema": 2, "tasks": {}},
            approved_catalogue_identity="sha256:" + "a" * 64,
        )


@pytest.mark.parametrize("producer_revision", (
    image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
    image_build_lanes.FIRST_FONTS_PROJECT_DEFAULT_PRODUCER_REVISION,
))
def test_real_lane_binding_and_remote_script_need_no_compiler_catalogue(
        tmp_path, monkeypatch, producer_revision):
    """Compile the actual frozen SSM wrapper from a schema-5 Fonts lane.

    No synthetic signed compiler receipt, Project-origin lane or injected
    task catalogue is present; no SSM call leaves this test.
    """
    from contextlib import nullcontext

    value = approved()
    root = tmp_path / "gateway"
    admit(root, value)
    project = "/var/lib/zog/image-build-lanes/gateway-first-fonts-runtime"
    spec = image_build_lanes.specification(
        "gateway-first-fonts-runtime", mode="managed",
        source_repository="zog144/image-build",
        source_revision=producer_revision,
        monthly_pin_repository_path=image_build_lanes.FIRST_FONTS_ORIGINAL_PIN_PATH,
        monthly_pin_identity=image_build_lanes.FIRST_FONTS_ORIGINAL_PIN_IDENTITY,
        provenance_host_id="compiler-test-host",
        provenance_project_id="fonts-execution",
        project_root=project, memory_maximum_bytes=2**30,
        thread_count_maximum=8, cpu_weight=100, disk_reservation_bytes=2**30,
        python_executable="/usr/bin/python3",
    )
    record = {
        "schema": image_build_lanes.INHERITED_SCHEMA,
        "state": "active",
        "lane": spec["lane"],
        "specification": spec,
        "source_root": project + "/source",
        "package_dir": project + "/source/project/package",
        "state_dir": project + "/state",
        "controller_config": project + "/controller.json",
        "runtime_companion": {
            "schema": image_build_lanes.RUNTIME_COMPANION_SCHEMA,
            "repository": image_build_lanes.BUILD_RECORD_REPOSITORY,
            "revision": image_build_lanes.FIRST_FONTS_BUILD_RECORD_COMPATIBILITY,
            "source_root": project + "/companions/build-record",
            "producer_revision": spec["source_revision"],
        },
    }
    host = {**TARGET, "workspace_id": WORKSPACE}
    from zog.host_deploy.gateway import project_current
    monkeypatch.setattr(project_current, "verify_approved_lane",
                        lambda *_: {"execution_authorized": False})
    monkeypatch.setattr(image_build_dispatch, "owned_workspace",
                        lambda directory, workspace: "selected-workspace")
    monkeypatch.setattr(image_build_dispatch, "locked_workspace",
                        lambda directory: nullcontext(directory))
    monkeypatch.setattr(image_build_dispatch, "configuration",
                        lambda directory: ({}, host))
    monkeypatch.setattr(image_build_dispatch, "_load_lane_locked",
                        lambda directory, lane: (record, spec))
    assert simple_forward.advance(root, value["request_id"])["phase"] == "prepared"
    frozen = load_dispatch(root, value["request_id"])["binding"]
    assert frozen["direct_forward"] is True
    assert set(frozen["remote_request"]["arguments"]) == {"mode", "targets"}
    assert "selection" not in value["parameters"]
    assert "recipe_snapshot" not in value["parameters"]
    assert "task" not in frozen and "task_catalogue_identity" not in frozen
    # These are the real existing producer/SMM-wrapper validators, NOT mocks.
    image_build_execution._binding({"phase": "prepared", "binding": frozen})
    script = image_build_execution.remote_script(frozen)
    assert "zog.image_build.remote_operations" in script
    assert "compiler-selection.json" not in script
    assert "compiler_provenance" not in script
    assert "issuer_policy" not in script

    sent = []
    class Host:
        def __init__(self, configuration):
            assert configuration == host
        def submit_command(self, script, seconds):
            sent.append((script, seconds))
            return "fixed-command-1"
    class OwnerJournal:
        def inspect(self, operation_id):
            assert operation_id == value["request_id"]
            return (None, None, None)
        def submit_once(self, **kwargs):
            assert kwargs["operation_id"] == value["request_id"]
            assert kwargs["target"] == TARGET
            return kwargs["sender"].submit_command(
                kwargs["script"], seconds=kwargs["seconds"])
        def close(self):
            pass
    result = simple_forward.advance(
        root, value["request_id"], host_factory=Host, owner_factory=OwnerJournal)
    assert result["phase"] == "submitted"
    assert sent == [(script, simple_forward.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS)]
    assert load_dispatch(root, value["request_id"])["command_id"] == "fixed-command-1"


def test_source_successor_has_same_approved_runtime_companion_and_original_pin():
    old = image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION
    successor = image_build_lanes.FIRST_FONTS_PROJECT_DEFAULT_PRODUCER_REVISION
    assert successor == "6b344aad3d3389d3f444bd69b63214a4a5903ad5"
    assert old != successor
    assert image_build_lanes.expected_build_record_revision(old) == (
        image_build_lanes.expected_build_record_revision(successor))
    assert image_build_lanes.expected_controller_revision(old) == (
        image_build_lanes.expected_controller_revision(successor))


def test_issue_body_has_no_compiler_selection_or_snapshot():
    event = issue()
    selected = github_dispatch.prepare_event(event, frozenset({"zog144"}))
    assert selected["parameters"] == {
        "lane": "gateway-first-fonts-runtime",
        "task": github_dispatch.FIRST_FONTS_TASK,
    }
    assert set(selected["parameters"]) == {"lane", "task"}
    assert "selection" not in json.dumps(event)
    assert "recipe_snapshot" not in json.dumps(event)


def test_project_current_ssm_timeout_is_recovery_blocked_not_pipeline_terminal(
        forwarding):
    root, value, binding, Host, counters = forwarding
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    class LongSSM(Host):
        def inspect_command(self, command_id):
            counters["inspect"].append(command_id)
            return {"CommandId": command_id,
                    "InstanceId": TARGET["instance_id"],
                    "Status": "TimedOut"}
    blocked = simple_forward.advance(root, REQUEST_ID, host_factory=LongSSM)
    assert blocked == {
        "request_id": REQUEST_ID, "phase": "recovery_blocked",
        "command_id": "command-123", "ssm_status": "TimedOut",
        "observation_required": True,
    }
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "recovery_blocked"
    assert not (root / "requests" / REQUEST_ID / "remote-result.json").exists()
    assert simple_forward.advance(root, REQUEST_ID, host_factory=LongSSM)["phase"] == "recovery_blocked"
    assert len(counters["send"]) == 1


def _owned_project_files(binding):
    """Actual local Project evidence; NOT a supplied Gateway status object."""
    project = Path(binding["project_root"])
    operation_id = binding["request_id"]
    request = binding["remote_request"]
    request_dir = project / "gateway-requests" / operation_id
    request_dir.mkdir(parents=True, exist_ok=True)
    (request_dir / "request.json").write_text(json.dumps(request))
    operation_dir = project / "state/image-build/remote-operations" / operation_id
    operation_dir.mkdir(parents=True, exist_ok=True)
    (operation_dir / "request.json").write_text(json.dumps(request))
    (operation_dir / "binding.json").write_text(
        json.dumps({"pipeline_id": "c" * 32}))
    pipeline_path = (project / "state/image-build/pipelines" /
                     ("c" * 32) / "pipeline.json")
    pipeline_path.parent.mkdir(parents=True, exist_ok=True)
    pipeline = {
        "schema": 1,
        "pipeline_id": "c" * 32,
        "status": "running",
        "operation": "image",
        "arguments": {"targets": [
            "libpng-final", "freetype-final", "fontconfig-final",
        ]},
        "attempts": {
            "fontconfig-final": "image-63dcd6a137f040bc9224dce166a916ed",
        },
        "owner": {
            "contract": "image-build-remote-operation-v1",
            "operation_id": operation_id,
            "source_repository": "zog144/image-build",
            "source_revision": SOURCE["revision"],
        },
    }
    pipeline_path.write_text(json.dumps(pipeline))
    return project, operation_dir, pipeline_path


def _complete_owned_pipeline(project, pipeline_path):
    pipeline = json.loads(pipeline_path.read_text())
    generation = "a" * 64
    for attempt_id in pipeline["attempts"].values():
        path = (project / "state/image-build/attempts" /
                attempt_id / "status.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "status": "complete", "generation": generation,
        }))
    pipeline["generation"] = generation
    pipeline["status"] = "complete"
    pipeline_path.write_text(json.dumps(pipeline))


def test_project_current_observation_is_same_pipeline_and_never_resubmits(forwarding):
    root, value, binding, Host, counters = forwarding
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    assert simple_forward.advance(root, REQUEST_ID, host_factory=Host)["phase"] == "running"
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "running"
    project, operation_dir, pipeline_path = _owned_project_files(binding)
    # A hostile caller can no longer inject terminal status as a JSON dict.
    with pytest.raises(TypeError):
        simple_forward.reconcile_project_observation(root, REQUEST_ID, {
            "terminal_confirmed": True, "producer_status": "completed",
        })
    assert simple_forward.reconcile_project_observation(
        root, REQUEST_ID, host_factory=Host)["phase"] == "running"
    assert len(counters["send"]) == 1

    for mutation in ("foreign-owner", "changed-source", "foreign-pipeline"):
        path = (pipeline_path if mutation != "foreign-pipeline"
                else operation_dir / "binding.json")
        original = path.read_bytes()
        altered = json.loads(original)
        if mutation == "foreign-owner":
            altered["owner"]["operation_id"] = "e" * 32
        elif mutation == "changed-source":
            altered["owner"]["source_revision"] = "f" * 40
        else:
            altered["pipeline_id"] = "f" * 32
        path.write_text(json.dumps(altered))
        with pytest.raises(simple_forward.ForwardingDenied):
            simple_forward.reconcile_project_observation(root, REQUEST_ID, host_factory=Host)
        path.write_bytes(original)
    # Forged terminal producer output cannot replace the *running*
    # pipeline evidence, even when the original request/result IDs match.
    (operation_dir / "result.json").write_text(json.dumps({
        "schema": "image-build-remote-result-v1",
        "operation_id": REQUEST_ID, "operation_type": "pipeline.submit",
        "source_repository": "zog144/image-build",
        "source_revision": SOURCE["revision"],
        "pipeline_id": "c" * 32,
        "status": "completed", "terminal_outcome": "success",
        "uncertainty": False,
    }))
    assert simple_forward.reconcile_project_observation(
        root, REQUEST_ID, host_factory=Host)["phase"] == "running"
    (operation_dir / "result.json").unlink()

    # Only actual completion in image-build's pipeline and attempt records
    # can create the terminal Gateway receipt; original SSM output and
    # original submit result are not modified or replayed.
    _complete_owned_pipeline(project, pipeline_path)
    complete = simple_forward.reconcile_project_observation(root, REQUEST_ID, host_factory=Host)
    assert complete["phase"] == "completed"
    assert len(counters["send"]) == 1
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "completed"
    receipt = json.loads((root / "requests" / REQUEST_ID /
                          "remote-result.json").read_text())
    assert receipt["result"]["pipeline_status"] == "complete"
    assert receipt["result"]["evidence"]["attempt_statuses"]
    assert receipt["result"]["terminal_confirmed"] is True


def test_legacy_schema_timeout_still_uses_original_control_window(forwarding):
    # The schema-4 tests prove 14,700 seconds is selected. Legacy policy is
    # not widened merely because the first Fonts Project can run longer.
    assert simple_forward.CONTROL_TIMEOUT_SECONDS == 300
    assert simple_forward.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS == 14700


def test_ssm_outer_timeout_then_read_only_reconcile_recovers_same_pipeline_without_send(
        forwarding):
    root, value, binding, Host, counters = forwarding
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    simple_forward.advance(root, REQUEST_ID, host_factory=Host)
    class TimedOut(Host):
        def inspect_command(self, command_id):
            counters["inspect"].append(command_id)
            return {"CommandId": command_id, "InstanceId": TARGET["instance_id"],
                    "Status": "TimedOut"}
    assert simple_forward.advance(root, REQUEST_ID, host_factory=TimedOut)[
        "phase"] == "recovery_blocked"
    from zog.host_deploy.gateway.ledger import reconcile_dispatch
    reconcile_dispatch(root, REQUEST_ID)
    _owned_project_files(binding)
    resumed = simple_forward.reconcile_project_observation(
        root, REQUEST_ID, host_factory=Host)
    assert resumed["phase"] == "running"
    assert resumed["pipeline_id"] == "c" * 32
    assert load_dispatch(root, REQUEST_ID)["command_id"] == "command-123"
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "running"
    assert not (root / "requests" / REQUEST_ID / "remote-result.json").exists()
    assert len(counters["send"]) == 1
    # Gateway's next poll must prefer the newer trusted Project result
    # over the original SSM's permanently TimedOut control-window status.
    again = simple_forward.advance(root, REQUEST_ID, host_factory=TimedOut)
    assert again["phase"] == "running"
    assert again["pipeline_id"] == "c" * 32
    assert load_request(root, REQUEST_ID)["states"]["completion"] == "running"
    assert len(counters["send"]) == 1
