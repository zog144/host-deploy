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

SCHEMA = "host-deploy-generic-pipeline-v1"
FILE = "generic-pipeline.json"
STAGES = ("capabilities", "snapshot", "submit", "inspect")
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")

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
                or step["operation_id"] != _operation_id(
                    gateway_id, step["name"], step["ordinal"])
                or step["phase"] not in ("prepared", "submitting",
                                         "submitted", "completed", "uncertain")
                or hashlib.sha256(_canonical(step["request"])).hexdigest()
                    != step["request_sha256"]
                or step["request"].get("operation_id") != step["operation_id"]
                or step["request"].get("source") != binding["source"]
                or (step["command_id"] is not None and
                    (type(step["command_id"]) is not str
                     or not 1 <= len(step["command_id"]) <= 128))):
            raise RuntimeError("generic pipeline stage identity mismatch")
        if i and value["stages"][i-1]["phase"] != "completed":
            raise RuntimeError("generic pipeline advanced past incomplete stage")
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
        if step["phase"] in ("submitting", "uncertain"):
            value["phase"] = "uncertain"
            step["phase"] = "uncertain"
            return _save(directory, value)  # cannot infer lost SendCommand ID
        stage_binding = _stage_binding(binding, step)
        if step["phase"] == "prepared":
            configuration = verify_current_target(root, binding)
            host = host_factory(configuration)
            producer_runtime_preflight(host, stage_binding)
            script = remote_script(stage_binding)
            step["phase"] = "submitting"
            _save(directory, value)  # fsync before AWS mutation
            try:
                command_id = host.submit_command(
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
