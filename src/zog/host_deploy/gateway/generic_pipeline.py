"""Supervised, finite generic image-build pipeline over the existing SSM gateway.

Each stage owns its own immutable operation and SSM command identity.  A lost
SendCommand reply is terminally uncertain; no automatic replacement is possible.
This module does not run in the SQS consumer and has no arbitrary task input.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from ..runner import Host
from ..workspace import save
from .image_build_dispatch import verify_current_target
from .image_build_execution import (
    CONTROL_TIMEOUT_SECONDS, _canonical, _binding, parse_receipt,
    producer_runtime_preflight, remote_script,
)
from .ledger import load_dispatch, load_request, request_lock, utc_now
from . import graphics_operation_send_intent as send_intent

SCHEMA = "host-deploy-generic-pipeline-v1"
FILE = "generic-pipeline.json"
STAGES = ("capabilities", "snapshot", "submit", "inspect")
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")

def _selected_protected_owner_preflight(root, binding, step, stage_binding):
    """Installed-only independent preflight operation; never Host.command."""
    from .graphics_native_owner_client import selected_preflight
    return selected_preflight(root,binding,step,stage_binding)


def _selected_protected_owner_sender(root, binding, step):
    """Installed-only root sender over pinned authenticated Unix IPC."""
    from .graphics_native_owner_client import selected_sender
    return selected_sender(root,binding,step)


def _operation_id(gateway_id, name, ordinal=0):
    return hashlib.sha256(
        ("zog-generic-pipeline-v1:" + gateway_id + ":" + name +
         ":" + str(ordinal)).encode("ascii")
    ).hexdigest()[:32]

def _base(root, request_id):
    state = load_request(root, request_id)
    if (state["request"]["operation"] != "build.submit"
            or state["states"]["admission"] != "admitted"):
        raise RuntimeError("generic pipeline requires an admitted build.submit")
    dispatch = load_dispatch(root, request_id)
    if dispatch is None or dispatch["phase"] != "prepared":
        raise RuntimeError("generic pipeline requires an unsubmitted frozen dispatch")
    binding = _binding(dispatch)
    if binding["remote_request"]["operation"] != "capabilities.inspect":
        raise RuntimeError("generic pipeline has no source-bound capability gate")
    if (binding.get("task") is None or
            binding.get("task_catalogue_identity") is None):
        raise RuntimeError("generic pipeline task is not frozen")
    # Historical operator CLI cannot bypass the durable one-stage-per-lane
    # claim. This is read-only: never fabricate a stage-once receipt at run.
    from .graphics_stage_once import require_record
    require_record(root, request_id, binding)
    return state, binding

def _read(directory, binding, gateway_id):
    path = directory / FILE
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise RuntimeError("unsafe retained generic pipeline record")
    value = json.loads(path.read_text())
    if (type(value) is not dict
            or set(value) != {"schema", "request_id", "binding_sha256",
                              "phase", "stages", "recipe_identity", "pipeline_id"}
            or value["schema"] != SCHEMA or value["request_id"] != gateway_id
            or value["binding_sha256"] != hashlib.sha256(_canonical(binding)).hexdigest()
            or value["phase"] not in ("active", "uncertain", "failed", "completed", "running")
            or type(value["stages"]) is not list
            or len(value["stages"]) > 64
            or (value["recipe_identity"] is not None and
                (type(value["recipe_identity"]) is not str
                 or not SHA.fullmatch(value["recipe_identity"])))
            or (value["pipeline_id"] is not None and
                (type(value["pipeline_id"]) is not str
                 or not IDENTITY.fullmatch(value["pipeline_id"])))):
        raise RuntimeError("generic pipeline journal integrity mismatch")
    for i, step in enumerate(value["stages"]):
        if (type(step) is not dict or set(step) != {
                "name", "operation_id", "ordinal", "phase",
                "request", "request_sha256", "command_id", "result"}
                or step["name"] not in STAGES
                or type(step["ordinal"]) is not int or step["ordinal"] < 0
                or step["ordinal"] != sum(
                    old["name"] == step["name"] for old in value["stages"][:i])
                or step["operation_id"] != _operation_id(
                    gateway_id, step["name"], step["ordinal"])
                or step["phase"] not in ("prepared", "submitting",
                                         "submitted", "completed", "uncertain")
                or type(step["request"]) is not dict
                or hashlib.sha256(_canonical(step["request"])).hexdigest()
                    != step["request_sha256"]
                or step["request"].get("operation_id") != step["operation_id"]
                or step["request"].get("source") != binding["source"]
                or (step["command_id"] is not None and
                    (type(step["command_id"]) is not str
                     or not 1 <= len(step["command_id"]) <= 128))):
            raise RuntimeError("generic pipeline stage identity mismatch")
        # A locally recomputed unkeyed request digest is NOT authority to
        # substitute mode, base generation, XCB/X11 predecessor, targets,
        # recipe snapshot, or even the remote operation. Reconstruct all
        # fields from the original frozen server-selected task on each read.
        try:
            original = _request(binding, step["name"], step["operation_id"], value)
        except (KeyError, ValueError, TypeError, RuntimeError) as error:
            raise RuntimeError("generic pipeline frozen request unavailable") from error
        if step["request"] != original:
            raise RuntimeError("generic pipeline request differs from frozen task binding")
        # Once a remote operation was sent, every durable history read must
        # find its separate exclusive intent. The same unkeyed JSON receipt
        # cannot manufacture or erase an SSM send.
        if step["phase"] in ("submitted", "completed"):
            send_intent.require_command(directory.parents[1], gateway_id, binding, step)
        if i == 0:
            if step["name"] != "capabilities":
                raise RuntimeError("generic pipeline stage order mismatch")
        else:
            previous = value["stages"][i-1]
            next_stage = {
                "capabilities": "snapshot",
                "snapshot": "submit",
                "submit": "inspect",
                "inspect": "inspect",
            }[previous["name"]]
            if previous["phase"] != "completed" or step["name"] != next_stage:
                raise RuntimeError("generic pipeline stage order mismatch")
        # A changed local recipe/pipeline identity must not reselect an older
        # generation. These values can only originate from the recorded
        # completed authenticated remote observation, not an arbitrary
        # request-journal edit with a recomputed checksum.
        if step["phase"] == "completed" and step["name"] in ("snapshot", "submit"):
            receipt = step["result"]
            if (type(receipt) is not dict or
                    type(receipt.get("result")) is not dict):
                raise RuntimeError("generic pipeline completed receipt missing")
            observed = receipt["result"]
            if step["name"] == "snapshot":
                snapshot = observed.get("recipe_identity")
                if (not isinstance(snapshot, str) or not SHA.fullmatch(snapshot)
                        or snapshot != value["recipe_identity"]
                        or observed.get("artifacts", {}).get("recipe_snapshot") != snapshot):
                    raise RuntimeError("generic pipeline snapshot identity mismatch")
            else:
                pipeline = observed.get("pipeline_id")
                if (not isinstance(pipeline, str) or not IDENTITY.fullmatch(pipeline)
                        or pipeline != value["pipeline_id"]):
                    raise RuntimeError("generic pipeline submission identity mismatch")
    return value

def _save(directory, value):
    save(directory / FILE, value)
    return json.loads(json.dumps(value))

def _request(binding, name, operation_id, record):
    source = binding["source"]
    task = binding["task"]
    if name == "capabilities":
        operation, arguments = "capabilities.inspect", {}
    elif name == "snapshot":
        operation = "recipes.snapshot"
        arguments = {"entries": task["entries"], "pin_date": task["pin_date"]}
    elif name == "submit":
        operation = "pipeline.submit"
        arguments = {**task["arguments"],
                     "recipe_snapshot": record["recipe_identity"]}
    elif name == "inspect":
        operation = "pipeline.inspect"
        arguments = {"pipeline_id": record["pipeline_id"]}
    else:
        raise RuntimeError("unknown generic stage")
    if name == "submit" and not SHA.fullmatch(record["recipe_identity"] or ""):
        raise RuntimeError("immutable recipe snapshot is not verified")
    if name == "inspect" and not IDENTITY.fullmatch(record["pipeline_id"] or ""):
        raise RuntimeError("pipeline identity is not verified")
    result = {"schema": "image-build-remote-operation-v1",
              "operation_id": operation_id, "operation": operation,
              "source": source, "arguments": arguments}
    if name == "submit":
        result["predecessor"] = _operation_id(record["request_id"], "snapshot")
    return result

def _stage_binding(base, step):
    result = copy.deepcopy(base)
    request = step["request"]
    operation_id = step["operation_id"]
    root = Path(result["project_root"]) / "gateway-requests" / operation_id
    result["request_id"] = operation_id
    result["remote_request"] = request
    result["remote_request_sha256"] = step["request_sha256"]
    result["remote_request_path"] = str(root / "request.json")
    result["remote_result_path"] = str(root / "result.json")
    result["argv"][-1] = result["remote_request_path"]
    result["runtime_profile"]["operation"] = request["operation"]
    return _binding({"phase": "prepared", "binding": result})

def _new_step(binding, record, name):
    ordinal = sum(s["name"] == name for s in record["stages"])
    operation_id = _operation_id(record["request_id"], name, ordinal)
    request = _request(binding, name, operation_id, record)
    return {"name": name, "operation_id": operation_id, "ordinal": ordinal,
            "phase": "prepared", "request": request,
            "request_sha256": hashlib.sha256(_canonical(request)).hexdigest(),
            "command_id": None, "result": None}

def _capabilities(result, binding):
    if result.get("status") != "completed" or result.get("uncertainty") is not False:
        raise RuntimeError("generic pipeline capability operation not completed")
    info = result.get("artifacts", {}).get("remote_capabilities")
    if type(info) is not dict or info.get("contract") != "image-build-remote-capabilities-v1":
        raise RuntimeError("missing authenticated producer capability contract")
    if (info.get("source") != binding["source"]
            or info.get("request_contract") != "image-build-remote-operation-v1"
            or info.get("result_contract") != "image-build-remote-result-v1"):
        raise RuntimeError("producer capability is not bound to deployed source")
    gp = info.get("generic_pipeline")
    if type(gp) is not dict or gp.get("supported") is not True:
        raise RuntimeError("generic pipeline not supported by source")
    snapshot, submit, recovery = (
        gp.get("recipe_snapshot"), gp.get("submit"), gp.get("recovery"))
    mode = binding["task"]["arguments"]["mode"]
    if (type(snapshot) is not dict
            or snapshot.get("operation") != "recipes.snapshot"
            or snapshot.get("contract") != "image-build-recipe-snapshot-v1"
            or not {"pipeline.submit", "pipeline.retry"}.issubset(
                set(snapshot.get("required_for") or []))
            or type(submit) is not dict
            or submit.get("operation") != "pipeline.submit"
            or submit.get("requires_recipe_snapshot") is not True
            or mode not in (submit.get("modes") or [])
            or type(recovery) is not dict
            or recovery.get("inspect") != "pipeline.inspect"
            or recovery.get("resume") != "pipeline.resume"
            or recovery.get("cancel") != "pipeline.cancel"
            or recovery.get("retry") != "pipeline.retry"
            or recovery.get("automatic_retry") is not False):
        raise RuntimeError("producer does not advertise required generic operations")
    worker = info.get("maintained_workers")
    if (type(worker) is not dict
            or worker.get("generic_pipeline_submit_equivalent") is not False
            or worker.get("remote_execution_operation") is not None):
        raise RuntimeError("maintained workers cannot substitute generic pipeline")
    if "capabilities.inspect" not in (info.get("operations") or []):
        raise RuntimeError("producer does not support source-bound capability inspection")

def _validate_result(step, receipt, binding, record):
    result = receipt["result"]
    if result["uncertainty"]:
        raise RuntimeError("image-build producer returned uncertain state")
    if step["name"] == "capabilities":
        _capabilities(result, binding)
    elif step["name"] == "snapshot":
        snap = result.get("recipe_identity")
        artifacts = result.get("artifacts") or {}
        if (result["status"] != "completed"
                or type(snap) is not str or not SHA.fullmatch(snap)
                or artifacts.get("recipe_snapshot") != snap
                or artifacts.get("contract") != "image-build-recipe-snapshot-v1"
                or artifacts.get("pin_date") != binding["task"]["pin_date"]):
            raise RuntimeError("producer snapshot result incomplete or mismatched")
        record["recipe_identity"] = snap
    elif step["name"] == "submit":
        pipeline = result.get("pipeline_id")
        if (result["status"] not in ("pending", "completed", "failed")
                or type(pipeline) is not str or not IDENTITY.fullmatch(pipeline)):
            raise RuntimeError("producer submitted pipeline without durable identity")
        record["pipeline_id"] = pipeline
    elif step["name"] == "inspect":
        if result.get("pipeline_id") != record["pipeline_id"]:
            raise RuntimeError("pipeline observation differs from submitted pipeline")
    return result

def _authenticate_snapshot_before_submit(root, request_id, host, binding, record):
    """Live readback of *original* SSM snapshot, not local receipt agreement.

    A recomputed mutable record can select any internally consistent
    recipe_identity. This check instead requires the original snapshot
    CommandId to return a completed source/request-bound image-build receipt
    from SSM, under the same frozen source, task and operation binding.
    The live readback is mandatory for EACH pipeline.submit attempt.
    """
    snapshots = [stage for stage in record["stages"]
                 if stage["name"] == "snapshot"]
    if len(snapshots) != 1:
        raise RuntimeError("missing unique original recipe snapshot")
    snapshot = snapshots[0]
    if (snapshot["phase"] != "completed" or
            type(snapshot["command_id"]) is not str
            or not snapshot["command_id"] or
            type(snapshot["result"]) is not dict):
        raise RuntimeError("original snapshot has no completed command identity")
    send_intent.require_command(root, request_id, binding, snapshot)
    original_binding = _stage_binding(binding, snapshot)
    observed = host.inspect_command(snapshot["command_id"])
    if (type(observed) is not dict or observed.get("Status") != "Success"
            or observed.get("CommandId") != snapshot["command_id"]):
        raise RuntimeError("original SSM snapshot observation unavailable")
    receipt = parse_receipt(observed.get("StandardOutputContent", ""),
                            original_binding)
    if (type(receipt) is not dict or
            type(receipt.get("result")) is not dict
            or receipt != snapshot["result"]):
        raise RuntimeError("original snapshot receipt differs from authenticated SSM history")
    confirmed = copy.deepcopy(record)
    _validate_result(snapshot, receipt, binding, confirmed)
    if confirmed["recipe_identity"] != record["recipe_identity"]:
        raise RuntimeError("selected recipe snapshot changed since authenticated producer result")
    return receipt


def status(root, request_id):
    _, binding = _base(root, request_id)
    with request_lock(root, request_id) as directory:
        value = _read(directory, binding, request_id)
        return value or {"schema": SCHEMA, "phase": "not_started",
                         "request_id": request_id, "stages": []}

def advance(root, request_id, *, host_factory=Host):
    """One supervised action per invocation; never auto-replay uncertain SSM."""
    state, binding = _base(root, request_id)
    with request_lock(root, request_id) as directory:
        value = _read(directory, binding, request_id)
        if value is None:
            value = {"schema": SCHEMA, "request_id": request_id,
                     "binding_sha256": hashlib.sha256(_canonical(binding)).hexdigest(),
                     "phase": "active", "stages": [],
                     "recipe_identity": None, "pipeline_id": None}
        if value["phase"] in ("uncertain", "failed", "completed"):
            return json.loads(json.dumps(value))
        steps = value["stages"]
        if not steps or steps[-1]["phase"] == "completed":
            previous = steps[-1] if steps else None
            if previous is None:
                name = "capabilities"
            elif previous["name"] == "capabilities":
                name = "snapshot"
            elif previous["name"] == "snapshot":
                name = "submit"
            elif previous["name"] == "submit":
                result = previous["result"]["result"]
                if result["status"] == "failed":
                    value["phase"] = "failed"
                    return _save(directory, value)
                if result["status"] == "completed":
                    value["phase"] = "completed"
                    return _save(directory, value)
                name = "inspect"
            else:
                result = previous["result"]["result"]
                if result["status"] in ("completed", "failed", "released"):
                    value["phase"] = ("completed" if result["status"] == "completed"
                                      else "failed")
                    return _save(directory, value)
                if len(steps) >= 64:
                    value["phase"] = "failed"
                    return _save(directory, value)
                name = "inspect"
            steps.append(_new_step(binding, value, name))
            return _save(directory, value)  # durably freeze before SSM action

        step = steps[-1]
        if step["phase"] == "prepared":
            # Any prior intent (including after a journal-only rollback) is
            # terminally uncertain, never a second authorization to send.
            send_intent.refuse_if_claimed(root, request_id, binding, step)
        if step["phase"] in ("submitting", "uncertain"):
            value["phase"] = "uncertain"
            step["phase"] = "uncertain"
            return _save(directory, value)  # cannot infer lost SendCommand ID
        stage_binding = _stage_binding(binding, step)
        if step["phase"] == "prepared":
            # This must precede *all* Host and preflight activity: the old
            # producer_runtime_preflight(host, ...) invoked Host.command(),
            # which itself performed an unfenced AWS SSM SendCommand.
            protected_sender = _selected_protected_owner_sender(root, binding, step)
            protected_preflight = _selected_protected_owner_preflight(
                root, binding, step, stage_binding)
            if not callable(protected_sender) or not callable(protected_preflight):
                raise RuntimeError("protected graphical owner transport unavailable")
            # An independently preapproved preflight has its OWN irrevocable
            # root-owned send claim and must not be reconstructed from local
            # journal state. No native implementation exists in this branch.
            preflight = protected_preflight()
            if (type(preflight) is not dict or
                    preflight.get("contract") !=
                    "zog-protected-graphical-preflight-observation-v1" or
                    preflight.get("ready") is not True or
                    preflight.get("mutation") is not False or
                    preflight.get("authenticated") is not True):
                raise RuntimeError("protected graphical preflight evidence unavailable")
            configuration = verify_current_target(root, binding)
            host = host_factory(configuration)
            if step["name"] == "submit":
                _authenticate_snapshot_before_submit(
                    root, request_id, host, binding, value)
            # Original script is only a local provenance witness; a native
            # privileged sender must independently select command bytes.
            script = remote_script(stage_binding)
            step["phase"] = "submitting"
            _save(directory, value)  # fsync before AWS mutation
            # This separate exclusive fsynced identity is committed AFTER
            # read-only preflight and BEFORE the first external SendCommand.
            # A restored older prepared journal cannot erase it; no send
            # occurs if claim exists, is partial or has a changed identity.
            send_intent.claim(root, request_id, binding, step)
            try:
                # No gateway-owned direct SendCommand fallback. The selected
                # owner transport must independently authenticate the immutable
                # original request, commit the protected claim, send once, and
                # provide its original authenticated CommandId.
                command_id = protected_sender(
                    script, seconds=CONTROL_TIMEOUT_SECONDS)
            except BaseException:
                value["phase"] = "uncertain"
                step["phase"] = "uncertain"
                _save(directory, value)
                raise
            if (type(command_id) is not str or not 1 <= len(command_id) <= 128):
                value["phase"] = "uncertain"
                step["phase"] = "uncertain"
                _save(directory, value)
                raise RuntimeError("SSM submission returned no durable command ID")
            try:
                # The original returned CommandId is itself bound to this
                # exact send intent in a no-replacement fsynced sidecar.
                # A missing receipt after a crash is HOLD, never permission
                # to invent or submit a replacement operation.
                send_intent.record_command(root, request_id, binding, step,
                                           command_id)
            except BaseException:
                value["phase"] = "uncertain"
                step["phase"] = "uncertain"
                _save(directory, value)
                raise
            step["command_id"] = command_id
            step["phase"] = "submitted"
            return _save(directory, value)
        if step["phase"] != "submitted" or not step["command_id"]:
            raise RuntimeError("invalid generic stage completion authority")
        configuration = verify_current_target(root, binding)
        host = host_factory(configuration)
        observed = host.inspect_command(step["command_id"])
        if observed is None or observed.get("Status") in (
                "Pending", "InProgress", "Delayed", "Cancelling"):
            return json.loads(json.dumps(value))
        if observed.get("Status") != "Success":
            value["phase"] = "uncertain"
            step["phase"] = "uncertain"
            return _save(directory, value)
        try:
            receipt = parse_receipt(observed.get("StandardOutputContent", ""),
                                    stage_binding)
            _validate_result(step, receipt, binding, value)
        except Exception:
            value["phase"] = "uncertain"
            step["phase"] = "uncertain"
            _save(directory, value)
            raise
        step["result"] = receipt
        step["phase"] = "completed"
        value["phase"] = "running" if step["name"] in ("submit", "inspect") else "active"
        return _save(directory, value)
