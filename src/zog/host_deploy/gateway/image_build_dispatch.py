"""Prepare exact image-build remote-operation bindings for the gateway.

This module is intentionally preparation-only.  It does not submit SSM commands.
"""

import hashlib
import json
from pathlib import Path
import re

from .. import image_build_lanes
from ..provision import configuration
from ..workspace import locked as locked_workspace
from .ledger import (
    load_request,
    owned_workspace,
    prepare_dispatch,
)


REMOTE_SCHEMA = "image-build-remote-operation-v1"
_BINDING_SCHEMA = 3
_ACCOUNT = re.compile(r"[0-9]{12}")
_INSTANCE = re.compile(r"i-[0-9a-f]{8,32}")


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _load_lane_locked(workspace, lane):
    path = Path(workspace) / "image-build-lanes" / (lane + ".json")
    record = json.loads(path.read_text())
    if (
        record.get("schema") not in {1, 2, 3, 4}
        or record.get("lane") != lane
        or record.get("state") != "active"
    ):
        raise RuntimeError("gateway image-build lane is not active")
    spec = image_build_lanes.validate(record.get("specification"))
    if spec["mode"] != "managed":
        raise RuntimeError("gateway image-build lane must be managed")
    required = {"source_root", "package_dir", "state_dir", "controller_config"}
    if any(
        not isinstance(record.get(name), str)
        or not Path(record[name]).is_absolute()
        for name in required
    ):
        raise RuntimeError("active image-build lane is missing execution paths")
    return record, spec


def _remote_request(
    gateway_request,
    lane_spec,
    *,
    task_catalogue=None,
    task_catalogue_identity=None,
):
    operation = gateway_request["operation"]
    parameters = gateway_request["parameters"]
    source = {
        "repository": lane_spec["source_repository"],
        "revision": lane_spec["source_revision"],
    }
    observed_state = (
        lane_spec.get("observed_state_dir")
        if lane_spec.get("schema") in {image_build_lanes.EXTERNAL_STATE_SCHEMA, image_build_lanes.SCHEMA}
        else None
    )
    if observed_state is not None and operation != "build.status":
        raise RuntimeError(
            "external observed state permits only build.status"
        )
    if operation == "build.submit":
        from .task_catalogue import select
        if task_catalogue is None or task_catalogue_identity is None:
            raise RuntimeError("generic pipeline submit requires reviewed task catalogue")
        task = select(
            task_catalogue, parameters["task"],
            repository=source["repository"], revision=source["revision"],
            lane=parameters["lane"],
            monthly_pin_repository_path=lane_spec["monthly_pin_repository_path"],
            monthly_pin_identity=lane_spec["monthly_pin_identity"],
        )
        if task["lane_owner"] != lane_spec["provenance_host_id"]:
            raise RuntimeError("generic pipeline task is not owned by managed lane")
        if gateway_request["source"] != {
            "repository": source["repository"], "commit": source["revision"]
        }:
            raise RuntimeError("generic task source differs from approved request")
        return ({
            "schema": REMOTE_SCHEMA,
            "operation_id": gateway_request["request_id"],
            "operation": "capabilities.inspect",
            "source": source, "arguments": {},
        }, {"task": task, "task_catalogue_identity": task_catalogue_identity})


    if operation == "toolchain.submit":
        from .toolchain_task import select
        if task_catalogue is None or task_catalogue_identity is None:
            raise RuntimeError("toolchain submission requires a protected task definition")
        task = select(
            task_catalogue, name=parameters["task"],
            repository=source["repository"], revision=source["revision"],
            lane=parameters["lane"],
            lane_owner=lane_spec["provenance_host_id"],
            monthly_pin_repository_path=lane_spec["monthly_pin_repository_path"],
            monthly_pin_identity=lane_spec["monthly_pin_identity"],
        )
        if gateway_request["source"] != {
            "repository": source["repository"], "commit": source["revision"]
        }:
            raise RuntimeError("toolchain source differs from approved request")
        if observed_state is not None:
            raise RuntimeError("toolchain execution requires managed controller state")
        return ({
            "schema": REMOTE_SCHEMA,
            "operation_id": gateway_request["request_id"],
            "operation": "toolchain.specification.inspect",
            "source": source, "arguments": {},
        }, {"task": task, "task_catalogue_identity": task_catalogue_identity})

    if operation in {"toolchain.inspect", "toolchain.resume"}:
        if observed_state is not None:
            raise RuntimeError("typed toolchain inspection requires managed controller state")
        # A separate trusted request may inspect an existing submission.
        # Resume is deliberately not enabled as a one-shot dispatch: its
        # authority requires the retained stage journal and controller evidence.
        if operation == "toolchain.resume":
            raise RuntimeError("toolchain resume requires reviewed durable phase recovery")
        return ({
            "schema": REMOTE_SCHEMA,
            "operation_id": gateway_request["request_id"],
            "operation": "toolchain.inspect",
            "source": source,
            "arguments": {"operation_id": parameters["operation_id"]},
        }, None)

    mapping = {
        "build.status": "pipeline.inspect",
        "build.resume": "pipeline.resume",
        "build.cancel": "pipeline.cancel",
    }
    remote_operation = mapping.get(operation)
    if remote_operation is None:
        raise RuntimeError(
            "gateway operation is not enabled by the pass-4 execution adapter"
        )
    return (
        {
            "schema": REMOTE_SCHEMA,
            "operation_id": gateway_request["request_id"],
            "operation": remote_operation,
            "source": source,
            "arguments": {"pipeline_id": parameters["pipeline_id"]},
        },
        None,
    )


def _target(host):
    required = {"region", "account_id", "instance_id", "workspace_id"}
    if not isinstance(host, dict) or not required.issubset(host):
        raise RuntimeError("workspace host configuration is incomplete")
    if (
        not isinstance(host["region"], str)
        or not host["region"]
        or not isinstance(host["account_id"], str)
        or not _ACCOUNT.fullmatch(host["account_id"])
        or not isinstance(host["instance_id"], str)
        or not _INSTANCE.fullmatch(host["instance_id"])
    ):
        raise RuntimeError("workspace host identity is invalid")
    return {
        "region": host["region"],
        "account_id": host["account_id"],
        "instance_id": host["instance_id"],
    }


def binding_for_request(
    gateway_root,
    request_id,
    *,
    task_catalogue=None,
    task_catalogue_identity=None,
):
    """Build an immutable server-owned binding without performing remote mutation."""
    state = load_request(gateway_root, request_id)
    if state["states"]["admission"] != "admitted":
        raise RuntimeError("image-build dispatch requires admitted request")
    request = state["request"]
    parameters = request["parameters"]
    lane = parameters.get("lane")
    if not isinstance(lane, str):
        raise RuntimeError("gateway request has no image-build lane")

    workspace = owned_workspace(gateway_root, request["workspace_id"])
    if workspace is None:
        raise RuntimeError("gateway does not own the request workspace")

    with locked_workspace(workspace) as locked:
        _, host = configuration(locked)
        if host["workspace_id"] != request["workspace_id"]:
            raise RuntimeError("workspace host identity changed before dispatch")
        lane_record, lane_spec = _load_lane_locked(locked, lane)
        if lane_spec["schema"] != image_build_lanes.SCHEMA:
            raise RuntimeError(
                "gateway dispatch requires lane schema 4 with a bound Python interpreter; "
                "legacy prepared operations must not be silently rewritten"
            )
        companion = lane_record.get("runtime_companion")
        if companion is None:
            raise RuntimeError(
                "gateway dispatch requires explicit lane runtime companion binding"
            )
        companion = image_build_lanes.validate_runtime_companion(
            companion, project_root=lane_spec["project_root"]
        )
        if (companion["producer_revision"] != lane_spec["source_revision"]
                or companion["revision"] != image_build_lanes.expected_build_record_revision(
                    lane_spec["source_revision"])):
            raise RuntimeError("runtime companion is not the source-bound producer checkpoint")
        remote_request, task_binding = _remote_request(
            request,
            lane_spec,
            task_catalogue=task_catalogue,
            task_catalogue_identity=task_catalogue_identity,
        )
        project_root = Path(lane_spec["project_root"])
        controller_companion = lane_record.get("controller_companion")
        if controller_companion is not None:
            controller_companion = image_build_lanes.validate_controller_companion(
                controller_companion, project_root=lane_spec["project_root"])
            if (controller_companion["producer_revision"]
                    != lane_spec["source_revision"]):
                raise RuntimeError("controller companion belongs to different producer")
        if (lane_spec["source_revision"] in (
                    image_build_lanes.TOOLCHAIN_PRODUCER_REVISION,
                    image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION)
                and lane_spec["observed_state_dir"] is None
                and controller_companion is None):
            raise RuntimeError("new producer requires explicit reviewed controller companion")

        remote_root = (
            Path("/var/lib/host-deploy/typed-toolchain-requests")
            / request["workspace_id"] / request_id
            if request["operation"] == "toolchain.submit"
            else project_root / "gateway-requests" / request_id
        )
        request_path = remote_root / "request.json"
        result_path = remote_root / "result.json"
        argv = image_build_lanes.remote_operation_argv(
            lane_record,
            request_path,
        )
        argv[1] += ":" + companion["source_root"] + "/src"
        if "--controller-config" in argv:
            argv[1] += ":" + str(project_root / "companions/box-control/box-control/src")

    request_bytes = _canonical(remote_request)
    binding = {
        "schema": _BINDING_SCHEMA,
        "kind": REMOTE_SCHEMA,
        "request_id": request_id,
        "workspace_id": request["workspace_id"],
        "lane": lane,
        "python_executable": lane_spec["python_executable"],
        "runtime_companion": companion,
        "runtime_profile": {
            "schema": 1,
            "operation": remote_request["operation"],
            "provenance": "--provenance-pin" in argv,
            "controller": "--controller-config" in argv,
            "external_observed_state": "--observed-state-dir" in argv,
            "controller_revision": (
                (controller_companion["revision"] if controller_companion is not None
                 else image_build_lanes.BOX_CONTROL_COMPATIBILITY)
                if "--controller-config" in argv else None
            ),
            "controller_source_root": (
                str(project_root / "companions/box-control")
                if "--controller-config" in argv else None
            ),
        },
        "target": _target(host),
        "source": {
            "repository": lane_spec["source_repository"],
            "revision": lane_spec["source_revision"],
        },
        "monthly_pin_repository_path": lane_spec["monthly_pin_repository_path"],
        "monthly_pin_identity": lane_spec["monthly_pin_identity"],
        "observed_state_dir": (
            lane_spec["observed_state_dir"]
            if lane_spec.get("schema") in {image_build_lanes.EXTERNAL_STATE_SCHEMA, image_build_lanes.SCHEMA}
            else None
        ),
        "project_root": lane_spec["project_root"],
        "source_root": lane_record["source_root"],
        "remote_request_path": str(request_path),
        "remote_result_path": str(result_path),
        "argv": argv,
        "remote_request": remote_request,
        "remote_request_sha256": hashlib.sha256(request_bytes).hexdigest(),
    }
    if controller_companion is not None and "--controller-config" in argv:
        binding["controller_companion"] = controller_companion
    if request["operation"] == "toolchain.submit":
        from .compiler_execution_identity import validate as validate_execution
        if task_binding is None:
            raise RuntimeError("nonroot toolchain requires reviewed protected task")
        approved_identity = lane_record.get("compiler_execution_identity")
        if approved_identity is None:
            raise RuntimeError("nonroot toolchain execution identity not installed")
        binding["compiler_execution_identity"] = validate_execution(
            approved_identity, project_root=lane_spec["project_root"],
            python_executable=lane_spec["python_executable"],
            source_revision=lane_spec["source_revision"],
            build_record_revision=companion["revision"],
            box_control_revision=controller_companion["revision"],
            task_identity=task_catalogue_identity,
        )
    if task_binding is not None:
        binding["task"] = task_binding["task"]
        binding["task_catalogue_identity"] = task_binding[
            "task_catalogue_identity"
        ]
    return binding


def prepare_image_build_dispatch(
    gateway_root,
    request_id,
    *,
    task_catalogue=None,
    task_catalogue_identity=None,
    at=None,
):
    binding = binding_for_request(
        gateway_root,
        request_id,
        task_catalogue=task_catalogue,
        task_catalogue_identity=task_catalogue_identity,
    )
    return prepare_dispatch(
        gateway_root,
        request_id,
        binding,
        at=at,
    )


def verify_current_target(gateway_root, binding):
    """Return current host config only when it still matches the frozen target."""
    workspace = owned_workspace(gateway_root, binding["workspace_id"])
    if workspace is None:
        raise RuntimeError("gateway no longer owns the bound workspace")
    with locked_workspace(workspace) as locked:
        _, host = configuration(locked)
        lane_record, lane_spec = _load_lane_locked(locked, binding["lane"])
    if _target(host) != binding["target"]:
        raise RuntimeError("workspace host differs from prepared dispatch target")
    if {
        "repository": lane_spec["source_repository"],
        "revision": lane_spec["source_revision"],
    } != binding["source"]:
        raise RuntimeError("image-build lane source differs from prepared dispatch")
    if lane_spec["monthly_pin_repository_path"] != binding["monthly_pin_repository_path"]:
        raise RuntimeError("image-build lane monthly pin path differs from prepared dispatch")
    if lane_spec["monthly_pin_identity"] != binding["monthly_pin_identity"]:
        raise RuntimeError("image-build lane monthly pin differs from prepared dispatch")
    current_observed_state = (
        lane_spec["observed_state_dir"]
        if lane_spec.get("schema") == image_build_lanes.SCHEMA
        else None
    )
    if current_observed_state != binding["observed_state_dir"]:
        raise RuntimeError("image-build observed state differs from prepared dispatch")
    if binding.get("schema") in {2, 3}:
        if (
            lane_spec["schema"] != image_build_lanes.SCHEMA
            or lane_spec["python_executable"] != binding.get("python_executable")
        ):
            raise RuntimeError("image-build Python runtime differs from prepared dispatch")
    if binding.get("schema") == 3:
        current = lane_record.get("runtime_companion")
        if current != binding.get("runtime_companion"):
            raise RuntimeError("runtime companion differs from frozen dispatch")
        if "controller_companion" in binding:
            selected = image_build_lanes.validate_controller_companion(
                binding["controller_companion"], project_root=binding["project_root"])
            if (lane_record.get("controller_companion") != selected
                    or selected["producer_revision"] != binding["source"]["revision"]):
                raise RuntimeError("controller companion differs from frozen dispatch")
        elif (binding["source"]["revision"] in (
                  image_build_lanes.TOOLCHAIN_PRODUCER_REVISION,
                  image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION)
              and binding["runtime_profile"]["controller"]):
            raise RuntimeError("new producer dispatch lacks reviewed controller binding")
    if "compiler_execution_identity" in binding:
        from .compiler_execution_identity import validate as validate_execution
        checked = validate_execution(
            binding["compiler_execution_identity"],
            project_root=binding["project_root"],
            python_executable=binding["python_executable"],
            source_revision=binding["source"]["revision"],
            build_record_revision=binding["runtime_companion"]["revision"],
            box_control_revision=binding["controller_companion"]["revision"],
            task_identity=binding["task_catalogue_identity"],
            allow_historical=True,
        )
        if lane_record.get("compiler_execution_identity") != checked:
            raise RuntimeError("compiler UID/GID/home/socket identity changed after preparation")
    elif binding.get("task") and binding["source"]["revision"] == (
            image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION):
        raise RuntimeError("restored compiler dispatch missing nonroot binding")
    if lane_record["source_root"] != binding["source_root"]:
        raise RuntimeError("image-build lane source path differs from prepared dispatch")
    expected_argv = image_build_lanes.remote_operation_argv(
        lane_record,
        Path(binding["remote_request_path"]),
    )
    if binding.get("schema") == 3:
        expected_argv[1] += ":" + binding["runtime_companion"]["source_root"] + "/src"
        if binding["runtime_profile"]["controller"]:
            expected_argv[1] += ":" + binding["runtime_profile"]["controller_source_root"] + "/box-control/src"
    if expected_argv != binding["argv"]:
        raise RuntimeError("image-build lane execution argv differs from prepared dispatch")
    return host
