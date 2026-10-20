from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from zog.host_deploy import checkpoint, image_build_lanes
from zog.host_deploy.gateway import image_build_execution
from zog.host_deploy.gateway.image_build_dispatch import (
    binding_for_request,
    prepare_image_build_dispatch,
    verify_current_target,
)
from zog.host_deploy.gateway.image_build_execution import (
    completion_for_receipt,
    observe_submitted,
    remote_script,
    submit_prepared,
)
from zog.host_deploy.gateway.task_catalogue import load as load_task_catalogue
from zog.host_deploy.gateway.ledger import (
    LedgerConflict,
    accept,
    claim_handoff,
    load_dispatch,
    load_request,
    mark_dispatch_submitted,
    mark_dispatch_submitting,
    record_dispatch_runtime_preflight,
    prepare_dispatch,
    reconcile_dispatch,
    reconcile_request,
)
from zog.host_deploy.workspace import initialize, save

REAL_RUNTIME_PREFLIGHT = image_build_lanes.runtime_preflight
REAL_PRODUCER_PREFLIGHT = image_build_execution.producer_runtime_preflight


WORKSPACE_ID = "not-used"
PIPELINE_ID = "c" * 32
REQUEST_ID = "d" * 32
SOURCE_REVISION = "a" * 40
MONTHLY_PIN_PATH = "project/pins/2026-10-01/commit-pin.py"
PIN = "sha256:" + "b" * 64


def gateway_request(workspace_id, operation="build.status", request_id=REQUEST_ID):
    value = {
        "schema": 1,
        "request_id": request_id,
        "workspace_id": workspace_id,
        "operation": operation,
        "origin": {
            "repository": "zog144/host-deploy",
            "issue_number": 20,
            "trigger_actor": "zog144",
        },
        "parameters": {
            "lane": "lane-a",
            "pipeline_id": PIPELINE_ID,
        },
    }
    if operation == "build.submit":
        value["source"] = {
            "repository": "zog144/image-build",
            "commit": SOURCE_REVISION,
        }
        value["parameters"] = {"lane": "lane-a", "task": "xcb-support-image-v1"}
    return value


@pytest.fixture(autouse=True)
def stub_runtime_preflight(monkeypatch):
    """Gateway protocol tests avoid running a real SSM interpreter probe."""
    monkeypatch.setattr(
        image_build_execution, "producer_runtime_preflight",
        lambda host, binding: {
            "contract": "image-build-runtime-preflight-v1",
            "ready": True,
            "mutation": False,
        },
    )
    monkeypatch.setattr(
        image_build_lanes, "runtime_preflight",
        lambda host, python_executable, source_root=None, **kwargs: {
            "python_executable": python_executable,
            "python_version": [3, 12, 0],
        },
    )


def prepared_gateway(tmp_path, observed_state=None):
    source = tmp_path / "source-workspace"
    identity = initialize(source, "image-build", "development", "us-east-1")
    save(
        source / "host.json",
        {
            "region": "us-east-1",
            "profile": "development",
            "instance_id": "i-0123456789abcdef0",
            "workspace_id": identity["workspace_id"],
            "account_id": "123456789012",
            "lifetime": "persistent",
        },
    )
    save(
        source / "launch.json",
        {
            "schema": 1,
            "account_id": "123456789012",
            "specification": {},
            "request": {},
            "phase": "created",
            "instance_id": "i-0123456789abcdef0",
        },
    )
    spec = image_build_lanes.specification(
        "lane-a",
        source_repository="zog144/image-build",
        source_revision=SOURCE_REVISION,
        monthly_pin_repository_path=MONTHLY_PIN_PATH,
        monthly_pin_identity=PIN,
        provenance_host_id="host-a",
        provenance_project_id="project-a",
        memory_maximum_bytes=1024,
        thread_count_maximum=1,
        cpu_weight=100,
        disk_reservation_bytes=1024,
        execution_user_id=1000,
        execution_group_id=1000,
        project_root="/var/lib/zog/image-build-lanes/lane-a",
        observed_state_dir=observed_state,
        python_executable=sys.executable,
    )
    save(
        source / "image-build-lanes/lane-a.json",
        {
            "schema": 1,
            "lane": "lane-a",
            "specification": spec,
            "state": "active",
            "source_root": "/var/lib/zog/image-build-lanes/lane-a/source",
            "package_dir": "/var/lib/zog/image-build-lanes/lane-a/source/project/package",
            "state_dir": "/var/lib/zog/image-build-lanes/lane-a/state",
            "controller_config": "/var/lib/zog/image-build-lanes/lane-a/controller.json",
            "runtime_companion": {
                "schema": 1,
                "repository": "zog144/build-record",
                "revision": image_build_lanes.BUILD_RECORD_COMPATIBILITY,
                "source_root": "/var/lib/zog/image-build-lanes/lane-a/companions/build-record",
                "producer_revision": SOURCE_REVISION,
            },
        },
    )
    archive = tmp_path / "handoff.zip"
    checkpoint.export(source, archive, handoff=True)
    gateway = tmp_path / "gateway"
    claim_handoff(gateway, archive)
    return gateway, identity["workspace_id"]


def admit(gateway, value):
    accept(
        gateway,
        value,
        message_id="message-1",
        receive_count=1,
        at="2026-10-09T12:00:00Z",
    )
    state = reconcile_request(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:01Z",
    )
    assert state["states"]["admission"] == "admitted"
    return state


@pytest.mark.parametrize(
    ("operation", "remote_operation"),
    [
        ("build.status", "pipeline.inspect"),
        ("build.resume", "pipeline.resume"),
        ("build.cancel", "pipeline.cancel"),
    ],
)
def test_prepare_image_build_dispatch_freezes_lane_host_and_remote_request(
    tmp_path, operation, remote_operation
):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id, operation=operation)
    admit(gateway, value)

    state, record = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )

    assert state["states"]["dispatch"] == "prepared"
    assert record["phase"] == "prepared"
    binding = record["binding"]
    assert binding["request_id"] == value["request_id"]
    assert binding["workspace_id"] == workspace_id
    assert binding["lane"] == "lane-a"
    assert binding["target"] == {
        "region": "us-east-1",
        "account_id": "123456789012",
        "instance_id": "i-0123456789abcdef0",
    }
    assert binding["source"] == {
        "repository": "zog144/image-build",
        "revision": SOURCE_REVISION,
    }
    assert binding["monthly_pin_repository_path"] == MONTHLY_PIN_PATH
    assert binding["monthly_pin_identity"] == PIN
    assert binding["remote_request"]["operation_id"] == value["request_id"]
    assert binding["remote_request"]["operation"] == remote_operation
    assert binding["remote_request"]["arguments"] == {"pipeline_id": PIPELINE_ID}
    assert binding["remote_request_path"].endswith(
        "/gateway-requests/" + value["request_id"] + "/request.json"
    )
    assert binding["remote_result_path"].endswith(
        "/gateway-requests/" + value["request_id"] + "/result.json"
    )
    assert binding["argv"][-1] == binding["remote_request_path"]
    assert len(binding["remote_request_sha256"]) == 64

    again_state, again = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:03Z",
    )
    assert again == record
    assert again_state["history"] == state["history"]


def _reviewed_generic_catalogue(tmp_path):
    value = {
        "schema": 2,
        "tasks": {
            "xcb-support-image-v1": {
                "source_repository": "zog144/image-build",
                "source_revision": SOURCE_REVISION,
                "lane": "lane-a",
                "lane_owner": "host-a",
                "monthly_pin_repository_path": MONTHLY_PIN_PATH,
                "monthly_pin_identity": PIN,
                "pin_date": "2026-10-01",
                "entries": [
                    {"id": name, "project": name.removesuffix("-final"),
                     "recipe": name.removesuffix("-final") + "/stages/final"}
                    for name in (
                        "xcb-util-final", "xcb-util-image-final",
                        "xcb-util-keysyms-final", "xcb-util-wm-final",
                        "xcb-util-xrm-final",
                    )
                ],
                "arguments": {
                    "mode": "image",
                    "selection": "e" * 64,
                    "targets": [
                        "xcb-util-final", "xcb-util-image-final",
                        "xcb-util-keysyms-final", "xcb-util-wm-final",
                        "xcb-util-xrm-final",
                    ],
                },
            }
        },
    }
    path = tmp_path / "tasks.json"
    path.write_text(json.dumps(value))
    return load_task_catalogue(path)


def test_generic_submit_requires_reviewed_task_catalogue(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id, operation="build.submit")
    admit(gateway, value)
    with pytest.raises(RuntimeError, match="reviewed task catalogue"):
        binding_for_request(gateway, value["request_id"])
    assert load_dispatch(gateway, value["request_id"]) is None


def test_generic_submit_freezes_capability_first_and_bound_task(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id, operation="build.submit")
    admit(gateway, value)
    catalogue, identity = _reviewed_generic_catalogue(tmp_path)
    state, record = prepare_image_build_dispatch(
        gateway, value["request_id"],
        task_catalogue=catalogue, task_catalogue_identity=identity)
    binding = record["binding"]
    assert state["states"]["dispatch"] == "prepared"
    assert binding["remote_request"]["operation"] == "capabilities.inspect"
    assert binding["remote_request"]["arguments"] == {}
    assert binding["task"]["arguments"]["targets"] == [
        "xcb-util-final", "xcb-util-image-final",
        "xcb-util-keysyms-final", "xcb-util-wm-final", "xcb-util-xrm-final",
    ]
    assert binding["task_catalogue_identity"] == identity
    same_state, again = prepare_image_build_dispatch(
        gateway, value["request_id"],
        task_catalogue=catalogue, task_catalogue_identity=identity)
    assert again == record
    assert same_state["states"] == state["states"]
    changed = json.loads(json.dumps(catalogue))
    changed["tasks"]["xcb-support-image-v1"]["arguments"]["selection"] = "f"*64
    with pytest.raises(LedgerConflict, match="different inputs"):
        prepare_image_build_dispatch(
            gateway, value["request_id"], task_catalogue=changed,
            task_catalogue_identity="sha256:"+"f"*64)

def test_prepared_dispatch_refuses_lane_or_host_substitution(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id)
    admit(gateway, value)
    _, record = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )

    workspace = gateway / "workspaces" / workspace_id
    host = json.loads((workspace / "host.json").read_text())
    host["instance_id"] = "i-fedcba98765432109"
    save(workspace / "host.json", host)

    with pytest.raises(RuntimeError, match="prepared dispatch target"):
        verify_current_target(gateway, record["binding"])


def test_durable_submitting_marker_recovers_as_uncertain_without_replay(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id)
    admit(gateway, value)
    prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )
    record_dispatch_runtime_preflight(
        gateway, value["request_id"],
        {"contract": "image-build-runtime-preflight-v1", "ready": True, "mutation": False},
        at="2026-10-09T12:00:02Z",
    )
    attempted = mark_dispatch_submitting(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:03Z",
    )
    assert attempted["phase"] == "submitting"

    state = reconcile_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:04Z",
    )
    record = load_dispatch(gateway, value["request_id"])
    assert state["states"]["dispatch"] == "submission_uncertain"
    assert state["states"]["completion"] == "not_started"
    assert record["phase"] == "submission_uncertain"
    assert "without a recorded command identity" in record["error"]


def test_late_known_command_identity_resolves_uncertainty_without_new_binding(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id)
    admit(gateway, value)
    _, prepared = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )
    record_dispatch_runtime_preflight(
        gateway, value["request_id"],
        {"contract": "image-build-runtime-preflight-v1", "ready": True, "mutation": False},
        at="2026-10-09T12:00:02Z",
    )
    mark_dispatch_submitting(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:03Z",
    )
    reconcile_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:04Z",
    )

    state, submitted = mark_dispatch_submitted(
        gateway,
        value["request_id"],
        "command-123",
        at="2026-10-09T12:00:05Z",
    )
    assert state["states"]["dispatch"] == "submitted"
    assert state["states"]["completion"] == "pending"
    assert submitted["phase"] == "submitted"
    assert submitted["command_id"] == "command-123"
    assert submitted["binding"] == prepared["binding"]

    same_state, same = mark_dispatch_submitted(
        gateway,
        value["request_id"],
        "command-123",
        at="2026-10-09T12:00:06Z",
    )
    assert same["command_id"] == "command-123"
    assert same_state["states"] == state["states"]
    with pytest.raises(LedgerConflict, match="different SSM command"):
        mark_dispatch_submitted(
            gateway,
            value["request_id"],
            "command-other",
            at="2026-10-09T12:00:07Z",
        )


def test_dispatch_binding_is_immutable_after_preparation(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(workspace_id)
    admit(gateway, value)
    _, record = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )
    changed = json.loads(json.dumps(record["binding"]))
    changed["target"]["instance_id"] = "i-fedcba98765432109"

    with pytest.raises(LedgerConflict, match="different inputs"):
        prepare_dispatch(
            gateway,
            value["request_id"],
            changed,
            at="2026-10-09T12:00:03Z",
        )


def _prepare_status_dispatch(tmp_path, request_id=REQUEST_ID):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(
        workspace_id,
        operation="build.status",
        request_id=request_id,
    )
    admit(gateway, value)
    prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )
    return gateway, value


def test_submit_persists_submitting_before_ssm_and_never_replays_submitted(tmp_path):
    gateway, value = _prepare_status_dispatch(tmp_path)
    calls = []

    class FakeHost:
        def __init__(self, configuration):
            calls.append(("init", configuration["instance_id"]))

        def submit_command(self, script, seconds):
            record = load_dispatch(gateway, value["request_id"])
            assert record["phase"] == "submitting"
            calls.append(("submit", seconds, script))
            return "command-123"

    state, record = submit_prepared(
        gateway,
        value["request_id"],
        host_factory=FakeHost,
        at="2026-10-09T12:00:03Z",
    )
    assert state["states"]["dispatch"] == "submitted"
    assert state["states"]["completion"] == "pending"
    assert record["command_id"] == "command-123"
    assert len([item for item in calls if item[0] == "submit"]) == 1

    again_state, again = submit_prepared(
        gateway,
        value["request_id"],
        host_factory=lambda config: (_ for _ in ()).throw(
            AssertionError("submitted dispatch must not construct another host")
        ),
        at="2026-10-09T12:00:04Z",
    )
    assert again["command_id"] == "command-123"
    assert again_state["states"] == state["states"]


def test_lost_send_command_reply_becomes_uncertain_and_blocks_replay(tmp_path):
    gateway, value = _prepare_status_dispatch(tmp_path)
    calls = []

    class LostReplyHost:
        def __init__(self, configuration):
            pass

        def submit_command(self, script, seconds):
            calls.append(script)
            raise TimeoutError("reply lost after possible SSM acceptance")

    with pytest.raises(TimeoutError, match="reply lost"):
        submit_prepared(
            gateway,
            value["request_id"],
            host_factory=LostReplyHost,
            at="2026-10-09T12:00:03Z",
        )

    record = load_dispatch(gateway, value["request_id"])
    state = load_request(gateway, value["request_id"])
    assert record["phase"] == "submission_uncertain"
    assert state["states"]["dispatch"] == "submission_uncertain"
    assert len(calls) == 1

    with pytest.raises(RuntimeError, match="not safely submit-able"):
        submit_prepared(
            gateway,
            value["request_id"],
            host_factory=LostReplyHost,
            at="2026-10-09T12:00:04Z",
        )
    assert len(calls) == 1


def _local_execution_binding(tmp_path):
    project = tmp_path / "lane-a"
    source = project / "source"
    pin = source / MONTHLY_PIN_PATH
    pin.parent.mkdir(parents=True)
    pin.write_text("{'schema': 1, 'packages': {}}\\n")
    (source / "src").mkdir()
    (source / "src/source.py").write_text("VALUE = 1\\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "config", "user.name", "Gateway Test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    request_id = "1" * 32
    request_path = project / "gateway-requests" / request_id / "request.json"
    result_path = project / "gateway-requests" / request_id / "result.json"
    remote_request = {
        "schema": "image-build-remote-operation-v1",
        "operation_id": request_id,
        "operation": "pipeline.inspect",
        "source": {
            "repository": "zog144/image-build",
            "revision": revision,
        },
        "arguments": {"pipeline_id": "2" * 32},
    }
    result = {
        "schema": "image-build-remote-result-v1",
        "operation_id": request_id,
        "operation_type": "pipeline.inspect",
        "source_repository": "zog144/image-build",
        "source_revision": revision,
        "pipeline_id": "2" * 32,
        "status": "completed",
        "terminal_outcome": "success",
        "failure": None,
        "uncertainty": False,
        "allowed_next_operations": [],
        "missing_evidence": [],
    }
    script = (
        "import json; print(json.dumps(" + repr(result) + ", sort_keys=True))"
    )
    payload = json.dumps(
        remote_request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    binding = {
        "schema": 1,
        "kind": "image-build-remote-operation-v1",
        "request_id": request_id,
        "workspace_id": "3" * 32,
        "lane": "lane-a",
        "target": {
            "region": "us-east-1",
            "account_id": "123456789012",
            "instance_id": "i-0123456789abcdef0",
        },
        "source": remote_request["source"],
        "monthly_pin_repository_path": MONTHLY_PIN_PATH,
        "monthly_pin_identity": "sha256:" + hashlib.sha256(pin.read_bytes()).hexdigest(),
        "observed_state_dir": None,
        "project_root": str(project),
        "source_root": str(source),
        "remote_request_path": str(request_path),
        "remote_result_path": str(result_path),
        "argv": [sys.executable, "-c", script, str(request_path)],
        "remote_request": remote_request,
        "remote_request_sha256": hashlib.sha256(payload).hexdigest(),
    }
    return binding, source, request_path, result_path


def test_remote_wrapper_verifies_exact_clean_checkout_and_persists_result(tmp_path):
    binding, source, request_path, result_path = _local_execution_binding(tmp_path)

    output = subprocess.check_output(
        remote_script(binding),
        shell=True,
        text=True,
    )
    receipt = json.loads(output)
    assert receipt["schema"] == "host-deploy-image-build-receipt-v1"
    assert receipt["request_id"] == binding["request_id"]
    assert receipt["result"]["status"] == "completed"
    assert request_path.exists()
    assert result_path.exists()

    # A retained result does not bypass source verification.
    (source / "untracked").write_text("changed")
    failed = subprocess.run(
        remote_script(binding),
        shell=True,
        text=True,
        capture_output=True,
    )
    assert failed.returncode != 0
    assert "checkout is not clean" in failed.stderr


def _submitted_status_dispatch(tmp_path, request_id=REQUEST_ID):
    gateway, value = _prepare_status_dispatch(tmp_path, request_id=request_id)

    class SubmitHost:
        def __init__(self, configuration):
            pass

        def submit_command(self, script, seconds):
            return "command-" + request_id[:8]

    submit_prepared(
        gateway,
        value["request_id"],
        host_factory=SubmitHost,
        at="2026-10-09T12:00:03Z",
    )
    return gateway, value


def _receipt_for(gateway, request_id, status="completed", uncertainty=False):
    record = load_dispatch(gateway, request_id)
    binding = record["binding"]
    result = {
        "schema": "image-build-remote-result-v1",
        "operation_id": request_id,
        "operation_type": binding["remote_request"]["operation"],
        "source_repository": binding["source"]["repository"],
        "source_revision": binding["source"]["revision"],
        "pipeline_id": PIPELINE_ID,
        "status": status,
        "terminal_outcome": "success" if status == "completed" else None,
        "failure": None,
        "uncertainty": uncertainty,
        "allowed_next_operations": [],
        "missing_evidence_count": 0,
    }
    return json.dumps(
        {
            "schema": "host-deploy-image-build-receipt-v1",
            "request_id": request_id,
            "remote_request_sha256": binding["remote_request_sha256"],
            "result_sha256": "4" * 64,
            "result_bytes": 100,
            "result": result,
        },
        sort_keys=True,
    )


def test_observe_existing_ssm_command_never_submits_and_records_completion(tmp_path):
    gateway, value = _submitted_status_dispatch(tmp_path)
    calls = []

    class ObserveHost:
        def __init__(self, configuration):
            pass

        def inspect_command(self, command_id):
            calls.append(command_id)
            return {
                "Status": "Success",
                "StatusDetails": "Success",
                "ResponseCode": 0,
                "StandardOutputContent": _receipt_for(
                    gateway,
                    value["request_id"],
                ),
                "StandardErrorContent": "",
            }

    state, observation, retained = observe_submitted(
        gateway,
        value["request_id"],
        host_factory=ObserveHost,
        at="2026-10-09T12:00:04Z",
    )
    assert calls == ["command-" + value["request_id"][:8]]
    assert state["states"]["completion"] == "completed"
    assert observation["observation"]["status"] == "Success"
    assert retained["result"]["result"]["status"] == "completed"


def test_ssm_terminal_failure_without_receipt_is_recovery_blocked(tmp_path):
    gateway, value = _submitted_status_dispatch(
        tmp_path,
        request_id="5" * 32,
    )

    class FailedHost:
        def __init__(self, configuration):
            pass

        def inspect_command(self, command_id):
            return {
                "Status": "Failed",
                "StatusDetails": "Failed",
                "ResponseCode": 1,
                "StandardErrorContent": "preflight failed",
            }

    state, _, retained = observe_submitted(
        gateway,
        value["request_id"],
        host_factory=FailedHost,
        at="2026-10-09T12:00:04Z",
    )
    assert retained is None
    assert state["states"]["completion"] == "recovery_blocked"


def test_pending_pipeline_status_query_completes_with_pending_payload(tmp_path):
    gateway, value = _submitted_status_dispatch(
        tmp_path,
        request_id="6" * 32,
    )

    class PendingHost:
        def __init__(self, configuration):
            pass

        def inspect_command(self, command_id):
            return {
                "Status": "Success",
                "StandardOutputContent": _receipt_for(
                    gateway,
                    value["request_id"],
                    status="pending",
                ),
                "StandardErrorContent": "",
            }

    state, _, retained = observe_submitted(
        gateway,
        value["request_id"],
        host_factory=PendingHost,
        at="2026-10-09T12:00:04Z",
    )
    assert state["states"]["completion"] == "completed"
    assert retained["result"]["result"]["status"] == "pending"


def test_pending_pipeline_resume_maps_to_running(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    value = gateway_request(
        workspace_id,
        operation="build.resume",
        request_id="a" * 32,
    )
    admit(gateway, value)
    prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:02Z",
    )

    class SubmitHost:
        def __init__(self, configuration):
            pass

        def submit_command(self, script, seconds):
            return "command-resume"

    submit_prepared(
        gateway,
        value["request_id"],
        host_factory=SubmitHost,
        at="2026-10-09T12:00:03Z",
    )

    class PendingHost:
        def __init__(self, configuration):
            pass

        def inspect_command(self, command_id):
            return {
                "Status": "Success",
                "StandardOutputContent": _receipt_for(
                    gateway,
                    value["request_id"],
                    status="pending",
                ),
                "StandardErrorContent": "",
            }

    state, _, _ = observe_submitted(
        gateway,
        value["request_id"],
        host_factory=PendingHost,
        at="2026-10-09T12:00:04Z",
    )
    assert state["states"]["completion"] == "running"


def test_uncertain_remote_result_maps_to_recovery_blocked(tmp_path):
    gateway, value = _submitted_status_dispatch(
        tmp_path,
        request_id="7" * 32,
    )

    class UncertainHost:
        def __init__(self, configuration):
            pass

        def inspect_command(self, command_id):
            return {
                "Status": "Success",
                "StandardOutputContent": _receipt_for(
                    gateway,
                    value["request_id"],
                    status="pending",
                    uncertainty=True,
                ),
                "StandardErrorContent": "",
            }

    state, _, _ = observe_submitted(
        gateway,
        value["request_id"],
        host_factory=UncertainHost,
        at="2026-10-09T12:00:04Z",
    )
    assert state["states"]["completion"] == "recovery_blocked"


def test_concurrent_submitters_cross_ssm_boundary_only_once(tmp_path):
    gateway, value = _prepare_status_dispatch(
        tmp_path,
        request_id="8" * 32,
    )
    entered = threading.Event()
    release = threading.Event()
    calls = []

    class BlockingHost:
        def __init__(self, configuration):
            pass

        def submit_command(self, script, seconds):
            calls.append(script)
            entered.set()
            assert release.wait(timeout=5)
            return "command-concurrent"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            submit_prepared,
            gateway,
            value["request_id"],
            host_factory=BlockingHost,
            at="2026-10-09T12:00:03Z",
        )
        assert entered.wait(timeout=5)
        second = pool.submit(
            submit_prepared,
            gateway,
            value["request_id"],
            host_factory=BlockingHost,
            at="2026-10-09T12:00:04Z",
        )
        with pytest.raises(RuntimeError, match="not safely submit-able|already in progress"):
            second.result(timeout=5)
        assert len(calls) == 1
        release.set()
        state, record = first.result(timeout=5)

    assert len(calls) == 1
    assert record["command_id"] == "command-concurrent"
    assert state["states"]["dispatch"] == "submitted"


def test_reconcile_recovers_completion_from_fsynced_remote_result(tmp_path):
    gateway, value = _submitted_status_dispatch(
        tmp_path,
        request_id="9" * 32,
    )
    record = load_dispatch(gateway, value["request_id"])
    receipt = json.loads(_receipt_for(gateway, value["request_id"]))
    encoded = json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    save(
        gateway / "requests" / value["request_id"] / "remote-result.json",
        {
            "schema": 1,
            "request_id": value["request_id"],
            "command_id": record["command_id"],
            "result_sha256": hashlib.sha256(encoded).hexdigest(),
            "completion": "completed",
            "recorded_at": "2026-10-09T12:00:04Z",
            "result": receipt,
        },
    )
    before = load_request(gateway, value["request_id"])
    assert before["states"]["completion"] == "pending"

    after = reconcile_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-09T12:00:05Z",
    )
    assert after["states"]["completion"] == "completed"


def test_authoritative_remote_timeout_uses_timed_out_completion():
    receipt = {
        "result": {
            "operation_type": "pipeline.submit",
            "status": "failed",
            "terminal_outcome": "timeout",
            "uncertainty": False,
        }
    }
    assert completion_for_receipt(receipt) == "timed_out"


def test_observed_state_lane_prepares_only_status_and_freezes_path(tmp_path):
    observed = "/var/lib/station-access/zog-compiler-view/state"
    gateway, workspace_id = prepared_gateway(tmp_path, observed_state=observed)
    value = gateway_request(workspace_id, operation="build.status", request_id="b" * 32)
    admit(gateway, value)

    state, record = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-10T12:00:00Z",
    )
    binding = record["binding"]
    assert state["states"]["dispatch"] == "prepared"
    assert binding["observed_state_dir"] == observed
    assert "--observed-state-dir" in binding["argv"]
    assert binding["argv"][binding["argv"].index("--observed-state-dir") + 1] == observed
    assert "--controller-config" not in binding["argv"]
    assert binding["remote_request"]["operation"] == "pipeline.inspect"


@pytest.mark.parametrize("operation", ["build.resume", "build.cancel"])
def test_observed_state_lane_rejects_mutating_pipeline_operations(tmp_path, operation):
    gateway, workspace_id = prepared_gateway(
        tmp_path,
        observed_state="/var/lib/station-access/zog-compiler-view/state",
    )
    value = gateway_request(workspace_id, operation=operation, request_id="e" * 32)
    admit(gateway, value)
    with pytest.raises(RuntimeError, match="only build.status"):
        prepare_image_build_dispatch(
            gateway,
            value["request_id"],
            at="2026-10-10T12:00:00Z",
        )
    assert load_dispatch(gateway, value["request_id"]) is None


def test_observed_state_path_change_after_preparation_is_rejected(tmp_path):
    gateway, workspace_id = prepared_gateway(
        tmp_path,
        observed_state="/var/lib/station-access/zog-compiler-view/state",
    )
    value = gateway_request(workspace_id, operation="build.status", request_id="f" * 32)
    admit(gateway, value)
    _, record = prepare_image_build_dispatch(
        gateway,
        value["request_id"],
        at="2026-10-10T12:00:00Z",
    )

    lane_path = gateway / "workspaces" / workspace_id / "image-build-lanes/lane-a.json"
    lane_record = json.loads(lane_path.read_text())
    lane_record["specification"]["observed_state_dir"] = "/var/lib/other/state"
    save(lane_path, lane_record)

    with pytest.raises(RuntimeError, match="observed state differs"):
        verify_current_target(gateway, record["binding"])

def test_dispatch_freezes_selected_interpreter_and_rejects_lane_substitution(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    request = gateway_request(workspace_id)
    admit(gateway, request)
    _, record = prepare_image_build_dispatch(gateway, request["request_id"])
    binding = record["binding"]
    assert binding["schema"] == 3
    assert binding["python_executable"] == sys.executable
    assert binding["argv"][2] == sys.executable
    assert remote_script(binding).startswith(sys.executable)
    workspace = gateway / "workspaces" / workspace_id
    lane_path = workspace / "image-build-lanes" / "lane-a.json"
    lane_record = json.loads(lane_path.read_text())
    lane_record["specification"]["python_executable"] = "/usr/bin/python3.12"
    save(lane_path, lane_record)
    with pytest.raises(RuntimeError, match="Python runtime differs"):
        verify_current_target(gateway, binding)


def test_gateway_refuses_legacy_lane_for_new_preparation(tmp_path):
    gateway, workspace_id = prepared_gateway(tmp_path)
    workspace = gateway / "workspaces" / workspace_id
    path = workspace / "image-build-lanes" / "lane-a.json"
    record = json.loads(path.read_text())
    record["specification"]["schema"] = 3
    del record["specification"]["python_executable"]
    save(path, record)
    value = gateway_request(workspace_id)
    admit(gateway, value)
    with pytest.raises(RuntimeError, match="requires lane schema 4"):
        prepare_image_build_dispatch(gateway, value["request_id"])
    assert load_dispatch(gateway, value["request_id"]) is None


def test_prepared_legacy_binding_is_not_reinterpreted_or_submitted(tmp_path):
    gateway, value = _prepare_status_dispatch(tmp_path)
    path = gateway / "requests" / value["request_id"] / "dispatch.json"
    record = json.loads(path.read_text())
    legacy = record["binding"]
    legacy["schema"] = 1
    legacy.pop("python_executable")
    legacy.pop("runtime_companion")
    legacy.pop("runtime_profile")
    legacy["argv"][1] = "PYTHONPATH=" + legacy["source_root"] + "/src"
    legacy["argv"][2] = "python3"
    serialized = json.dumps(legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    record["binding_sha256"] = hashlib.sha256(serialized).hexdigest()
    save(path, record)
    with pytest.raises(RuntimeError, match="legacy dependency-unbound"):
        submit_prepared(gateway, value["request_id"], host_factory=lambda _: None)
    assert load_dispatch(gateway, value["request_id"])["phase"] == "prepared"


def test_prepared_dispatch_missing_provenance_dependency_stops_before_ssm(
    tmp_path, monkeypatch
):
    """Producer preflight failure records a bounded refusal without producer submission."""
    gateway, request = _prepare_status_dispatch(tmp_path)
    attempts = []

    class MissingDependencyHost:
        def __init__(self, configuration):
            attempts.append(("host", configuration["instance_id"]))

        def command(self, script, seconds=120):
            attempts.append(("preflight", script))
            assert "zog.image_build.runtime_preflight" in script
            assert "build-record=" in script
            raise RuntimeError("missing pinned build-record")

        def submit_command(self, script, seconds=300):
            raise AssertionError("missing build-record must block producer submission")

    monkeypatch.setattr(
        image_build_execution,
        "producer_runtime_preflight",
        REAL_PRODUCER_PREFLIGHT,
    )
    with pytest.raises(RuntimeError, match="missing pinned build-record"):
        submit_prepared(
            gateway, request["request_id"],
            host_factory=MissingDependencyHost,
            at="2026-10-11T17:40:00Z",
        )
    retained = load_dispatch(gateway, request["request_id"])
    assert retained["phase"] == "prepared"
    state = load_request(gateway, request["request_id"])
    assert state["states"]["dispatch"] == "prepared"
    assert state["states"]["completion"] == "not_started"
    assert len([x for x in attempts if x[0] == "preflight"]) == 1
    report_path = gateway / "requests" / request["request_id"] / "runtime-preflight.json"
    report = json.loads(report_path.read_text())
    assert report["binding_sha256"] == retained["binding_sha256"]
    assert report["observations"][-1]["report"]["ready"] is False


def test_producer_preflight_profile_and_exact_checkout_pins(tmp_path, monkeypatch):
    gateway, request = _prepare_status_dispatch(tmp_path)
    binding = load_dispatch(gateway, request["request_id"])["binding"]
    seen = []

    class FakeHost:
        def command(self, script, seconds):
            seen.append(script)
            profile = binding["runtime_profile"]
            source = binding["source_root"]
            companion = binding["runtime_companion"]
            checks = [
                {
                    "component": "build-record", "status": "ready",
                    "validated_revision": companion["revision"],
                    "source": companion["source_root"] + "/src/zog/build_record/__init__.py",
                }
            ]
            if profile["controller"]:
                checks.append({
                    "component": "box-control", "status": "ready",
                    "validated_revision": profile["controller_revision"],
                    "source": profile["controller_source_root"] +
                    "/box-control/src/zog/box_control/__init__.py",
                })
            return json.dumps({
                "contract": "image-build-runtime-preflight-v1",
                "ready": True, "mutation": False,
                "python": {"executable": binding["python_executable"]},
                "image_build": {"repository_root": source},
                "requirements": {
                    "operation": profile["operation"],
                    "bindings": {
                        "provenance": profile["provenance"],
                        "controller": profile["controller"],
                        "external_observed_state": profile["external_observed_state"],
                    },
                },
                "checks": checks,
            })

    result = REAL_PRODUCER_PREFLIGHT(FakeHost(), binding)
    assert result["ready"] is True
    assert "zog.image_build.runtime_preflight" in seen[0]
    assert binding["source"]["revision"] in seen[0]
    assert binding["runtime_companion"]["revision"] in seen[0]
    assert binding["runtime_profile"]["controller_revision"] in seen[0]


def test_readonly_inspect_preflight_skips_controller_dependency(tmp_path):
    gateway, workspace_id = prepared_gateway(
        tmp_path, observed_state="/var/lib/observation/state"
    )
    request = gateway_request(workspace_id)
    admit(gateway, request)
    _, prepared = prepare_image_build_dispatch(gateway, request["request_id"])
    binding = prepared["binding"]
    assert binding["runtime_profile"]["controller"] is False
    assert binding["runtime_profile"]["external_observed_state"] is True
    assert binding["runtime_profile"]["controller_revision"] is None
    assert binding["runtime_profile"]["controller_source_root"] is None
    assert "--controller-config" not in binding["argv"]


def test_companion_changes_after_dispatch_preparation_are_refused(tmp_path):
    gateway, value = _prepare_status_dispatch(tmp_path)
    bound = load_dispatch(gateway, value["request_id"])["binding"]
    lane_path = (
        gateway / "workspaces" / value["workspace_id"]
        / "image-build-lanes/lane-a.json"
    )
    record = json.loads(lane_path.read_text())
    record["runtime_companion"]["revision"] = "f" * 40
    save(lane_path, record)
    with pytest.raises(RuntimeError, match="runtime companion differs"):
        verify_current_target(gateway, bound)


def _pinned_toolchain_workspace(tmp_path):
    """Prepared fixture emulates the exact pinned producer's compatibility inputs."""
    from zog.host_deploy.gateway.toolchain_task import (
        PRODUCER_REVISION, CONTRACT, TASK_NAME,
    )
    gateway, workspace_id = prepared_gateway(tmp_path)
    lane_path = (gateway / "workspaces" / workspace_id
                 / "image-build-lanes/lane-a.json")
    record = json.loads(lane_path.read_text())
    record["schema"] = image_build_lanes.SCHEMA
    record["specification"]["source_revision"] = PRODUCER_REVISION
    record["runtime_companion"]["producer_revision"] = PRODUCER_REVISION
    record["runtime_companion"]["revision"] = (
        image_build_lanes.TOOLCHAIN_BUILD_RECORD_COMPATIBILITY)
    save(lane_path, record)
    task = {
        "contract": CONTRACT,
        "task": {
            "name": TASK_NAME, "source_repository": "zog144/image-build",
            "source_revision": PRODUCER_REVISION,
            "lane": "lane-a", "lane_owner": "host-a",
            "seed_generation": "a" * 64,
            "monthly_pin_repository_path": MONTHLY_PIN_PATH,
            "monthly_pin_identity": PIN,
            "pin_date": "2026-10-01",
            "specification_identity":
                "sha256:ba8986219065627c939adf49ee0bf200bfc94f85b0bbe280aecdaff8349ffc1c",
        },
    }
    request = gateway_request(workspace_id, "build.submit")
    request["operation"] = "toolchain.submit"
    request["source"]["commit"] = PRODUCER_REVISION
    request["parameters"] = {
        "lane": "lane-a", "task": TASK_NAME,
    }
    admit(gateway, request)
    return gateway, request, task, lane_path, record


def test_reviewed_toolchain_companion_must_be_bound_explicitly(tmp_path):
    from zog.host_deploy.gateway.image_build_execution import _binding
    from zog.host_deploy.gateway.toolchain_task import PRODUCER_REVISION
    gateway, request, task, lane_path, record = _pinned_toolchain_workspace(tmp_path)
    approval = "sha256:" + "e" * 64
    with pytest.raises(RuntimeError, match="explicit reviewed controller"):
        binding_for_request(
            gateway, request["request_id"],
            task_catalogue=task, task_catalogue_identity=approval)
    workspace = lane_path.parent.parent
    spec = record["specification"]
    expected_digest = image_build_lanes.specification_sha256(spec)
    args = dict(
        producer_revision=PRODUCER_REVISION,
        repository="zog144/box-control",
        revision=image_build_lanes.TOOLCHAIN_BOX_CONTROL_COMPATIBILITY,
        source_root=spec["project_root"] + "/companions/box-control",
        expected_specification_sha256=expected_digest,
    )
    bound_lane = image_build_lanes.bind_controller_companion(
        workspace, "lane-a", **args)
    assert image_build_lanes.bind_controller_companion(
        workspace, "lane-a", **args) == bound_lane
    _, prepared = prepare_image_build_dispatch(
        gateway, request["request_id"],
        task_catalogue=task, task_catalogue_identity=approval)
    binding = _binding(prepared)
    assert binding["controller_companion"] == bound_lane["controller_companion"]
    assert binding["runtime_profile"]["controller_revision"] == (
        image_build_lanes.TOOLCHAIN_BOX_CONTROL_COMPATIBILITY)
    assert binding["runtime_companion"]["revision"] == (
        image_build_lanes.TOOLCHAIN_BUILD_RECORD_COMPATIBILITY)
    assert binding["runtime_profile"]["controller_revision"] != (
        image_build_lanes.BOX_CONTROL_COMPATIBILITY)
    assert verify_current_target(gateway, binding)["workspace_id"] == (
        request["workspace_id"])
    with pytest.raises(ValueError, match="already bound differently|unreviewed"):
        image_build_lanes.bind_controller_companion(
            workspace, "lane-a", **{
                **args, "revision": image_build_lanes.BOX_CONTROL_COMPATIBILITY,
            })
    current = json.loads(lane_path.read_text())
    current["controller_companion"]["revision"] = (
        image_build_lanes.BOX_CONTROL_COMPATIBILITY)
    save(lane_path, current)
    with pytest.raises(ValueError, match="unreviewed"):
        _binding({**prepared, "binding": {
            **binding, "controller_companion": current["controller_companion"]}})
    with pytest.raises(RuntimeError, match="controller companion differs"):
        verify_current_target(gateway, binding)


def test_real_preflight_accepts_reviewed_source_bound_controller(tmp_path):
    from zog.host_deploy.gateway.image_build_execution import _binding
    from zog.host_deploy.gateway.toolchain_task import PRODUCER_REVISION
    requirements_path = (Path(__file__).parent / "fixtures" /
        "image-build-toolchain-runtime-requirements-857bb454.json")
    pinned = json.loads(requirements_path.read_text())
    assert pinned["source"] == {
        "repository": "zog144/image-build", "revision": PRODUCER_REVISION
    }
    assert pinned["box_control"]["validated_revision"] == (
        image_build_lanes.TOOLCHAIN_BOX_CONTROL_COMPATIBILITY)
    assert pinned["build_record"]["validated_revision"] == (
        image_build_lanes.TOOLCHAIN_BUILD_RECORD_COMPATIBILITY)
    gateway, request, task, lane_path, record = _pinned_toolchain_workspace(tmp_path)
    spec = record["specification"]
    image_build_lanes.bind_controller_companion(
        lane_path.parent.parent, "lane-a",
        producer_revision=PRODUCER_REVISION,
        repository="zog144/box-control",
        revision=pinned["box_control"]["validated_revision"],
        source_root=spec["project_root"] + "/companions/box-control",
        expected_specification_sha256=image_build_lanes.specification_sha256(spec),
    )
    prepared = binding_for_request(
        gateway, request["request_id"], task_catalogue=task,
        task_catalogue_identity="sha256:" + "d" * 64)
    binding = _binding({"phase": "prepared", "binding": prepared})
    scripts = []

    class SourceBoundHost:
        def command(self, script, seconds):
            scripts.append(script)
            profile = binding["runtime_profile"]
            assert profile["operation"] == "toolchain.specification.inspect"
            checks = []
            for component, revision, root, module in (
                ("build-record", pinned["build_record"]["validated_revision"],
                 binding["runtime_companion"]["source_root"],
                 "src/zog/build_record/__init__.py"),
                ("box-control", pinned["box_control"]["validated_revision"],
                 profile["controller_source_root"],
                 "box-control/src/zog/box_control/__init__.py"),
            ):
                checks.append({
                    "component": component,
                    "status": "ready", "validated_revision": revision,
                    "source": root + "/" + module,
                })
            return json.dumps({
                "contract": "image-build-runtime-preflight-v1",
                "ready": True, "mutation": False,
                "python": {"executable": binding["python_executable"]},
                "image_build": {"repository_root": binding["source_root"]},
                "requirements": {"operation": profile["operation"],
                                 "bindings": {
                                     "provenance": profile["provenance"],
                                     "controller": profile["controller"],
                                     "external_observed_state":
                                         profile["external_observed_state"],
                                 }},
                "checks": checks,
            })

    report = REAL_PRODUCER_PREFLIGHT(SourceBoundHost(), binding)
    assert report["ready"] is True
    assert len(scripts) == 1
    assert PRODUCER_REVISION in scripts[0]
    assert image_build_lanes.TOOLCHAIN_BOX_CONTROL_COMPATIBILITY in scripts[0]
    assert image_build_lanes.TOOLCHAIN_BUILD_RECORD_COMPATIBILITY in scripts[0]
    assert image_build_lanes.BOX_CONTROL_COMPATIBILITY not in scripts[0]
    assert image_build_lanes.BUILD_RECORD_COMPATIBILITY not in scripts[0]

    class WrongControllerHost(SourceBoundHost):
        def command(self, script, seconds):
            response = json.loads(super().command(script, seconds))
            for item in response["checks"]:
                if item["component"] == "box-control":
                    item["validated_revision"] = (
                        image_build_lanes.BOX_CONTROL_COMPATIBILITY)
            return json.dumps(response)

    with pytest.raises(RuntimeError, match="did not verify bound box-control"):
        REAL_PRODUCER_PREFLIGHT(WrongControllerHost(), binding)


def test_historical_controller_profile_unmodified_by_new_producer(tmp_path):
    from zog.host_deploy.gateway.image_build_execution import _binding
    gateway, request = _prepare_status_dispatch(tmp_path)
    prepared = load_dispatch(gateway, request["request_id"])
    binding = _binding(prepared)
    assert "controller_companion" not in binding
    assert binding["runtime_profile"]["controller_revision"] == (
        image_build_lanes.BOX_CONTROL_COMPATIBILITY)
    assert binding["runtime_companion"]["revision"] == (
        image_build_lanes.BUILD_RECORD_COMPATIBILITY)
    assert verify_current_target(gateway, binding)["workspace_id"] == (
        request["workspace_id"])
