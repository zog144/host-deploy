"""Source-only admission of the new isolated, cross-bootstrap-only lane.

These tests never prepare a live GitHub message, contact SSM, install a
controller, or modify the original retained compiler operation.
"""
import copy

import pytest

from zog.host_deploy import image_build_lanes
from zog.host_deploy.gateway import compiler_execution_identity as identity
from zog.host_deploy.gateway import toolchain_supervisor as supervisor
from zog.host_deploy.gateway import toolchain_journal as journal
from zog.host_deploy.gateway import toolchain_task


NEW = identity.FRESH_PRODUCER_REVISION
PROJECT = "/home/zog-fresh-control/isolated-new-lane"
SOCKET = "/run/zog/root-control-fresh-cross-bootstrap.sock"
PIN = toolchain_task.RESTORED_MONTHLY_PIN_IDENTITY
TASK_ID = "sha256:" + "c" * 64


def fresh_identity():
    return {
        "schema": identity.FRESH_SCHEMA,
        "controller_uid": 17301, "controller_gid": 17302,
        "controller_home": "/home/zog-fresh-control",
        "project_root": PROJECT,
        "build_uid": 17401, "build_gid": 17402,
        "socket_path": SOCKET,
        "source_revision": NEW,
        "build_record_revision": identity.FRESH_BUILD_RECORD_REVISION,
        "box_control_revision": identity.FRESH_BOX_CONTROL_REVISION,
        "root_control_revision": identity.FRESH_ROOT_CONTROL_REVISION,
        "python_executable": "/usr/bin/python3",
        "task_catalogue_identity": TASK_ID,
        "fresh_scope": {
            "schema": identity.FRESH_SCOPE,
            "phase": "cross-bootstrap",
            "execution_limit_seconds": 21600,
            "additional_disk_bytes": 34359738368,
            "existing_host_only": True,
            "automatic_later_phases": False,
        },
    }


def checked(value):
    return identity.validate(
        value, project_root=PROJECT, python_executable="/usr/bin/python3",
        source_revision=NEW,
        box_control_revision=identity.FRESH_BOX_CONTROL_REVISION,
        build_record_revision=identity.FRESH_BUILD_RECORD_REVISION,
        task_identity=TASK_ID,
    )


def task():
    return {
        "contract": toolchain_task.CONTRACT, "task": {
            "name": toolchain_task.TASK_NAME,
            "source_repository": "zog144/image-build",
            "source_revision": NEW, "lane": "isolated-new-lane",
            "lane_owner": "approved-new-host",
            "seed_generation": "a"*64,
            "monthly_pin_repository_path": toolchain_task.RESTORED_MONTHLY_PIN_PATH,
            "monthly_pin_identity": PIN, "pin_date": "2026-10-01",
            "specification_identity": "sha256:" + "b"*64,
        },
    }


def test_new_tuple_and_scope_are_exact_and_separate_from_historical():
    assert checked(fresh_identity()) == fresh_identity()
    assert image_build_lanes.expected_controller_revision(NEW) == (
        "b7934882cfacd2fbfd60c7964713ed3dde7f9460")
    assert image_build_lanes.expected_build_record_revision(NEW) == (
        "a866c9c4b0dd385045f00ce2de7d809f5b67c104")
    assert image_build_lanes.expected_controller_revision(
        image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION
    ) == "644170fc441863307092f329bf7e23cb64eb33e2"
    assert identity.ROOT_CONTROL_REVISION == (
        "e4f25110c854c000bdde5ec564c8119370da9a52")
    assert toolchain_task.select(
        task(), name=toolchain_task.TASK_NAME, repository="zog144/image-build",
        revision=NEW, lane="isolated-new-lane", lane_owner="approved-new-host",
        monthly_pin_repository_path=toolchain_task.RESTORED_MONTHLY_PIN_PATH,
        monthly_pin_identity=PIN,
    ) == task()["task"]


@pytest.mark.parametrize("key,bad", [
    ("root_control_revision", identity.ROOT_CONTROL_REVISION),
    ("box_control_revision", "644170fc441863307092f329bf7e23cb64eb33e2"),
    ("source_revision", toolchain_task.RESTORED_PRODUCER_REVISION),
    ("build_record_revision", "771af9429e83da40fd503625a6b4ba8329acee35"),
    ("socket_path", "/run/zog/root-control.sock"),
    ("socket_path", "/tmp/root-control-new.sock"),
    ("socket_path", "/run/zog/root-control-fresh/../root-control.sock"),
])
def test_no_old_controller_pin_or_shared_socket_for_fresh_lane(key,bad):
    value = fresh_identity()
    value[key] = bad
    with pytest.raises(ValueError):
        checked(value)


@pytest.mark.parametrize("key,bad", [
    ("phase", "temporary-userspace"),
    ("execution_limit_seconds", 21601),
    ("additional_disk_bytes", 34359738369),
    ("existing_host_only", False),
    ("automatic_later_phases", True),
])
def test_no_extra_phase_budget_or_new_host(key,bad):
    value = fresh_identity()
    value["fresh_scope"][key] = bad
    with pytest.raises(ValueError):
        checked(value)


def test_missing_fresh_binding_or_relabelled_v2_never_authorizes_new_source():
    v = fresh_identity()
    v["schema"] = identity.SCHEMA
    del v["fresh_scope"]
    with pytest.raises(ValueError):
        checked(v)
    v = fresh_identity()
    v["unexpected_user_command"] = "make install"
    with pytest.raises(ValueError):
        checked(v)


def test_new_scope_supervisor_does_not_advance_past_cross_bootstrap():
    bound = {
        "compiler_execution_identity": fresh_identity(),
        "request_id": "f"*32,
        "source": {"repository": "zog144/image-build", "revision": NEW},
        "task": task()["task"], "task_catalogue_identity": TASK_ID,
    }
    original = journal.initial("f"*32, bound)
    current = journal.event(bound, original, "submit", "cross-bootstrap")
    assert current["request"]["arguments"] == {
        "phase": "cross-bootstrap", "seed_generation": "a"*64}
    original["specification"] = "sha256:" + "b"*64
    original["phases"] = [{
        "name": "cross-bootstrap", "operation_id": current["operation_id"],
        "predecessor": None, "status": "completed",
        "inspect_count": 0, "resume_count": 0, "resume_authorized": False,
        "evidence": {"controller_jobs": []},
    }]
    assert supervisor._next(bound, original) is None
    assert original["status"] == "completed"
    assert original["artifact_receipt"] is None
    # Old historical bindings retain their separate multiphase semantics.
    previous = copy.deepcopy(original)
    previous["status"] = "active"
    bound.pop("compiler_execution_identity")
    next_event = supervisor._next(bound, previous)
    assert next_event["request"]["arguments"] == {"phase": "temporary-userspace"}


def test_exact_scope_is_in_fixed_root_transport_launcher():
    runtime = identity.IDENTITY_RUNTIME
    assert identity.FRESH_ROOT_CONTROL_REVISION in runtime
    assert 'extra_groups=()' in runtime
    assert 'value.get("fresh_scope")' in runtime
    assert 'root-control-[a-z0-9]' in runtime


def test_fresh_dispatch_requires_dedicated_controller_and_preserves_frozen_lane(tmp_path):
    import json
    from pathlib import Path
    from test_gateway_dispatch import prepared_gateway, gateway_request, admit
    from zog.host_deploy.gateway.image_build_dispatch import (
        binding_for_request, verify_current_target,
    )
    from zog.host_deploy.gateway.image_build_execution import _binding
    from zog.host_deploy.workspace import save

    gateway, workspace_id = prepared_gateway(tmp_path)
    lane_path = (gateway / "workspaces" / workspace_id /
                 "image-build-lanes/lane-a.json")
    rec = json.loads(lane_path.read_text())
    rec["schema"] = image_build_lanes.SCHEMA
    project = PROJECT.replace("isolated-new-lane", "lane-a")
    rec["specification"]["source_revision"] = NEW
    rec["specification"]["project_root"] = project
    rec["specification"]["monthly_pin_identity"] = PIN
    rec["specification"]["controller"]["socket_path"] = SOCKET
    rec["specification"]["controller"]["execution_user_id"] = 17401
    rec["specification"]["controller"]["execution_group_id"] = 17402
    rec["specification"]["controller"]["execution_timeout_seconds"] = 21600
    rec["specification"]["resource_policy"]["disk_reservation_bytes"] = (
        32 * 1024**3)
    rec["runtime_companion"].update(
        producer_revision=NEW,
        revision=identity.FRESH_BUILD_RECORD_REVISION,
        source_root=project + "/companions/build-record",
    )
    rec["controller_companion"] = {
        "schema": 1, "repository": "zog144/box-control",
        "revision": identity.FRESH_BOX_CONTROL_REVISION,
        "source_root": project + "/companions/box-control",
        "producer_revision": NEW,
    }
    rec.update(
        source_root=project + "/source",
        package_dir=project + "/source/project/package",
        state_dir=project + "/state",
        controller_config=project + "/controller.json",
    )
    approved = fresh_identity()
    approved["project_root"] = project
    approved["task_catalogue_identity"] = TASK_ID
    rec["compiler_execution_identity"] = approved
    save(lane_path, rec)
    protected = task()
    protected["task"].update(
        lane="lane-a", lane_owner="host-a", seed_generation="d"*64,
    )
    request = gateway_request(workspace_id, "build.submit")
    request["operation"] = "toolchain.submit"
    request["source"]["commit"] = NEW
    request["parameters"] = {
        "lane": "lane-a", "task": toolchain_task.TASK_NAME,
    }
    admit(gateway, request)
    frozen = binding_for_request(
        gateway, request["request_id"],
        task_catalogue=protected, task_catalogue_identity=TASK_ID,
    )
    assert frozen["compiler_execution_identity"]["socket_path"] == SOCKET
    assert frozen["source"]["revision"] == NEW
    assert frozen["runtime_profile"]["controller_revision"] == (
        identity.FRESH_BOX_CONTROL_REVISION)
    assert frozen["task"]["seed_generation"] == "d"*64
    assert frozen["remote_request_path"].startswith(
        "/var/lib/host-deploy/typed-toolchain-requests/")
    _binding({"phase": "prepared", "binding": frozen})
    assert verify_current_target(gateway, frozen)["workspace_id"] == workspace_id
    mismatched = json.loads(lane_path.read_text())
    mismatched["specification"]["controller"]["socket_path"] = (
        "/run/zog/root-control.sock")
    save(lane_path, mismatched)
    with pytest.raises(RuntimeError, match="controller/socket/budget drift"):
        verify_current_target(gateway, frozen)
    save(lane_path, rec)
    mismatched = json.loads(lane_path.read_text())
    mismatched["runtime_companion"]["revision"] = "0"*40
    save(lane_path, mismatched)
    with pytest.raises(RuntimeError, match="runtime companion differs"):
        verify_current_target(gateway, frozen)
