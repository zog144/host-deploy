"""Bounded read-only progress projection from the durable generic gateway ledger.

This is a local administrative view, not a GitHub reporter or an SSM probe.
It never returns raw remote stdout, arbitrary artifact values, credentials,
executor scripts, or full controller/private-state paths.
"""
import hashlib
import json
import re

from .generic_pipeline import status as generic_status
from .image_build_execution import _canonical
from .ledger import load_dispatch, load_request

SCHEMA = "host-deploy-generic-progress-v1"
_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")
_PHASES = {"not_started", "active", "running", "completed", "failed", "uncertain"}
_STATUSES = {"pending", "completed", "failed", "released"}


def _producer_summary(step):
    """Only allowlisted facts from the *retained authenticated SSM receipt*."""
    receipt = step.get("result")
    if receipt is None:
        return None
    if type(receipt) is not dict or type(receipt.get("result")) is not dict:
        raise RuntimeError("invalid retained generic producer result")
    result = receipt["result"]
    if (result.get("operation_id") != step["operation_id"]
            or result.get("operation_type") != step["request"]["operation"]
            or result.get("status") not in _STATUSES
            or type(result.get("uncertainty")) is not bool
            or type(result.get("missing_evidence_count")) is not int
            or not 0 <= result["missing_evidence_count"] <= 1_000_000):
        raise RuntimeError("retained producer result differs from selected invocation")
    pid = result.get("pipeline_id")
    if pid is not None and (type(pid) is not str or not _ID.fullmatch(pid)):
        raise RuntimeError("invalid retained pipeline identity")
    snap = result.get("recipe_identity")
    if snap is not None and (type(snap) is not str or not _SHA.fullmatch(snap)):
        raise RuntimeError("invalid retained recipe identity")
    artifacts = result.get("artifacts", {})
    if type(artifacts) is not dict or len(artifacts) > 64:
        raise RuntimeError("unbounded retained artifact names")
    names = sorted(artifacts)
    if any(type(name) is not str or not _SAFE_NAME.fullmatch(name) for name in names):
        raise RuntimeError("invalid retained artifact label")
    # Do not include potentially sensitive values or raw failure text.
    result_id = "sha256:" + hashlib.sha256(_canonical(result)).hexdigest()
    return {
        "operation": step["request"]["operation"],
        "operation_id": step["operation_id"],
        "status": result["status"],
        "uncertainty": result["uncertainty"],
        "missing_evidence_count": result["missing_evidence_count"],
        "pipeline_id": pid,
        "recipe_snapshot_id": snap,
        "artifact_names": names,
        "failure_present": result.get("failure") is not None,
        "result_sha256": result_id,
    }


def progress(root, request_id):
    """Return bounded durable progress for a single original GitHub request ID.

    No SSM calls, new controller operations, receipt publication or mutation.
    The returned stage may be stale until the next supervised inspect poll.
    """
    if type(request_id) is not str or not _ID.fullmatch(request_id):
        raise ValueError("generic progress requires an exact request ID")
    state = load_request(root, request_id)
    request = state["request"]
    if request["operation"] != "build.submit":
        raise ValueError("generic progress is supported for build.submit only")
    admission = state["states"]["admission"]
    view = {
        "schema": SCHEMA,
        "request_id": request_id,
        "task": request["parameters"]["task"],
        "lane": request["parameters"]["lane"],
        "source_revision": request["source"]["commit"],
        "admission": admission,
        "dispatch": state["states"]["dispatch"],
        "phase": "not_started",
        "task_catalogue_sha256": None,
        "recipe_snapshot_id": None,
        "pipeline_id": None,
        "stages": [],
        "current_operation": None,
        "result": None,
        "terminal": False,
        "uncertain": False,
    }
    dispatch = load_dispatch(root, request_id)
    if dispatch is None:
        return view
    binding = dispatch["binding"]
    if (type(binding) is not dict or binding.get("request_id") != request_id
            or binding.get("source") != {
                "repository": request["source"]["repository"],
                "revision": request["source"]["commit"],
            }
            or binding.get("lane") != request["parameters"]["lane"]
            or binding.get("task_catalogue_identity") is None):
        raise RuntimeError("retained generic binding differs from original request")
    view["task_catalogue_sha256"] = binding["task_catalogue_identity"]
    if dispatch["phase"] != "prepared":
        view["phase"] = ("uncertain" if dispatch["phase"] in (
            "submitting", "submission_uncertain") else "not_started")
        view["uncertain"] = view["phase"] == "uncertain"
        return view

    record = generic_status(root, request_id)
    if record["phase"] not in _PHASES or len(record["stages"]) > 64:
        raise RuntimeError("invalid retained generic progress")
    view["phase"] = record["phase"]
    view["recipe_snapshot_id"] = record.get("recipe_identity")
    view["pipeline_id"] = record.get("pipeline_id")
    view["terminal"] = record["phase"] in ("completed", "failed", "uncertain")
    view["uncertain"] = record["phase"] == "uncertain"
    for step in record["stages"]:
        result = _producer_summary(step)
        stage = {
            "name": step["name"],
            "phase": step["phase"],
            "operation_id": step["operation_id"],
            "ssm_command_id": step["command_id"],
            "result_sha256": result["result_sha256"] if result else None,
        }
        view["stages"].append(stage)
        view["current_operation"] = {
            "name": stage["name"], "phase": stage["phase"],
            "operation_id": stage["operation_id"],
            "ssm_command_id": stage["ssm_command_id"],
        }
        if result is not None:
            view["result"] = result
    # The stage journal is a *retained* point-in-time snapshot, not a live
    # assertion of process activity or a certificate of published artifacts.
    return json.loads(json.dumps(view))
