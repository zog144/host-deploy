"""Supervise typed image-build toolchains with durable SSM fencing.

One call performs at most one journal transition or SSM observation/submission.
No API failure authorizes replacing a previously attempted submission.
"""
import json
from pathlib import Path

from ..runner import Host
from ..workspace import save
from .image_build_dispatch import verify_current_target
from .image_build_execution import (
    CONTROL_TIMEOUT_SECONDS, parse_receipt, producer_runtime_preflight,
    remote_script,
)
from .ledger import request_lock
from .toolchain_journal import (
    COMPLETE, PHASES, RECOVERY, binding, event, initial, persist, read,
    stage_binding,
)
from .toolchain_receipt import validate_final_result

OBSERVATION_DIR = "typed-toolchain-observations"
EXECUTION_CONTRACT = "image-build-toolchain-remote-execution-v1"


def _next(bound, journal):
    if journal["specification"] is None:
        return event(bound, journal, "specification", "specification")
    if not journal["phases"]:
        return event(bound, journal, "submit", PHASES[0])
    last = journal["phases"][-1]
    if last["status"] == "pending":
        if last["resume_authorized"]:
            return event(bound, journal, "resume", last["name"], last["resume_count"])
        return event(bound, journal, "inspect", last["name"], last["inspect_count"])
    if last["status"] == "failed":
        if last["name"] == "final-libc-publish" and not journal["recovery_authorized"]:
            journal["status"] = "awaiting_recovery"
            return None
        if (last["name"] == "final-libc-publish"
                and journal["recovery_authorized"]
                and "toolchain.submit" in last["evidence"]["allowed_next_operations"]):
            return event(bound, journal, "submit", RECOVERY)
        journal["status"] = "failed"
        return None
    if last["name"] == "final-compiler":
        journal["status"] = ("completed" if journal["artifact_receipt"] else "uncertain")
        return None
    if last["name"] == RECOVERY:
        successor = "final-math"
    else:
        successor = PHASES[PHASES.index(last["name"]) + 1]
    return event(bound, journal, "submit", successor)


def _validate_observation(bound, journal, current, receipt):
    result = receipt["result"]
    kind, phase_name = current["kind"], current["phase"]
    if result["uncertainty"] is not False:
        raise RuntimeError("producer toolchain observation is uncertain")
    if kind == "specification":
        spec = result.get("artifacts", {}).get("toolchain_specification")
        if (result["status"] != "completed"
                or type(spec) is not dict
                or spec.get("contract") != "image-build-toolchain-specification-v1"
                or spec.get("identity") != bound["task"]["specification_identity"]
                or spec.get("bootstrap_pipeline", {}).get("remote_execution", {}).get(
                    "phases") != list(PHASES[:6]) + [RECOVERY] + list(PHASES[6:])
                or spec.get("bootstrap_pipeline", {}).get(
                    "remote_execution_status") != "available"):
            raise RuntimeError("producer toolchain specification differs from reviewed pin")
        journal["specification"] = spec["identity"]
        return

    execution = result.get("artifacts", {}).get("toolchain_execution")
    submit_id = (current["operation_id"] if kind == "submit"
                 else journal["phases"][-1]["operation_id"])
    if (type(execution) is not dict
            or execution.get("contract") != EXECUTION_CONTRACT
            or execution.get("phase") != phase_name
            or execution.get("operation_id") != submit_id
            or execution.get("specification", {}).get("identity")
               != journal["specification"]
            or result["status"] not in ("pending", "completed", "failed")
            or type(execution.get("pipelines")) is not list
            or type(execution.get("controller_jobs")) is not list
            or type(result.get("attempt_ids")) is not list):
        raise RuntimeError("typed toolchain execution receipt incomplete")
    if kind == "submit":
        predecessor = (journal["phases"][-1]["operation_id"]
                       if journal["phases"] else None)
        if execution.get("predecessor") != predecessor:
            raise RuntimeError("toolchain predecessor differs from frozen phase")
        journal["phases"].append({
            "name": phase_name, "operation_id": submit_id,
            "predecessor": predecessor, "status": "pending",
            "inspect_count": 0, "resume_count": 0, "resume_authorized": False,
            "evidence": {},
        })
    last = journal["phases"][-1]
    if (last["name"] != phase_name
            or execution.get("predecessor") != last["predecessor"]):
        raise RuntimeError("toolchain inspection returned different phase lineage")
    last["status"] = result["status"]
    last["evidence"] = {
        "receipt_sha256": receipt["result_sha256"],
        "observation_id": current["operation_id"],
        "command_id": current["command_id"],
        "selected_generation": result.get("selected_generation"),
        "controller_jobs": execution["controller_jobs"],
        "pipelines": execution["pipelines"],
        "attempt_ids": result["attempt_ids"],
        "allowed_next_operations": result["allowed_next_operations"],
    }
    if kind == "inspect":
        last["inspect_count"] += 1
    if kind == "resume":
        last["resume_count"] += 1
        last["resume_authorized"] = False
    if phase_name == "final-compiler" and result["status"] == "completed":
        journal["artifact_receipt"] = validate_final_result(
            result, journal["specification"]
        )


def _archive(directory, current, receipt):
    path = directory / OBSERVATION_DIR / (current["operation_id"] + ".json")
    record = {
        "schema": 1, "operation_id": current["operation_id"],
        "command_id": current["command_id"],
        "request_sha256": current["request_sha256"], "receipt": receipt,
    }
    if path.is_symlink():
        raise RuntimeError("unsafe typed toolchain observation path")
    if path.exists():
        if path.stat().st_size > 128 * 1024 or json.loads(path.read_text()) != record:
            raise RuntimeError("typed toolchain observation changed")
    else:
        save(path, record)


def status(root, request_id):
    bound = binding(root, request_id)
    with request_lock(root, request_id) as directory:
        return read(directory, request_id, bound) or initial(request_id, bound)


def authorize_resume(root, request_id, phase_name):
    """Operator authority only after an authenticated pending observation."""
    bound = binding(root, request_id)
    with request_lock(root, request_id) as directory:
        journal = read(directory, request_id, bound)
        if (journal is None or journal["status"] != "active"
                or journal["current"] is not None or not journal["phases"]
                or journal["phases"][-1]["name"] != phase_name
                or journal["phases"][-1]["status"] != "pending"
                or "toolchain.resume" not in journal["phases"][-1]["evidence"].get(
                    "allowed_next_operations", [])):
            raise RuntimeError("toolchain resume lacks pending inspected authority")
        journal["phases"][-1]["resume_authorized"] = True
        return persist(directory, journal)


def authorize_recovery(root, request_id):
    """Explicitly permit final-libc publish recovery, never general retry."""
    bound = binding(root, request_id)
    with request_lock(root, request_id) as directory:
        journal = read(directory, request_id, bound)
        if (journal is None or journal["status"] != "awaiting_recovery"
                or journal["current"] is not None or not journal["phases"]
                or journal["phases"][-1]["name"] != "final-libc-publish"
                or journal["phases"][-1]["status"] != "failed"
                or "toolchain.submit" not in journal["phases"][-1]["evidence"].get(
                    "allowed_next_operations", [])):
            raise RuntimeError("final-libc recovery lacks failed publisher evidence")
        journal["status"] = "active"
        journal["recovery_authorized"] = True
        return persist(directory, journal)


def advance(root, request_id, *, host_factory=Host):
    bound = binding(root, request_id)
    with request_lock(root, request_id) as directory:
        journal = read(directory, request_id, bound)
        if journal is None:
            return persist(directory, initial(request_id, bound))
        if journal["status"] in (*COMPLETE, "awaiting_recovery"):
            return journal
        current = journal["current"]
        if current is None:
            journal["current"] = _next(bound, journal)
            return persist(directory, journal)
        if current["state"] in ("submitting", "uncertain"):
            current["state"] = "uncertain"
            journal["status"] = "uncertain"
            return persist(directory, journal)
        stage = stage_binding(bound, current)
        if current["state"] == "prepared":
            host = host_factory(verify_current_target(root, bound))
            producer_runtime_preflight(host, stage)
            script = remote_script(stage)
            current["state"] = "submitting"
            persist(directory, journal)
            try:
                command_id = host.submit_command(
                    script, seconds=CONTROL_TIMEOUT_SECONDS)
            except BaseException:
                current["state"] = "uncertain"
                journal["status"] = "uncertain"
                persist(directory, journal)
                raise
            if type(command_id) is not str or not 1 <= len(command_id) <= 128:
                current["state"] = "uncertain"
                journal["status"] = "uncertain"
                persist(directory, journal)
                raise RuntimeError("SSM toolchain submission lacks CommandId")
            current["command_id"] = command_id
            current["state"] = "submitted"
            return persist(directory, journal)
        if current["state"] != "submitted" or not current["command_id"]:
            raise RuntimeError("toolchain dispatch journal missing submitted identity")
        host = host_factory(verify_current_target(root, bound))
        observation = host.inspect_command(current["command_id"])
        if observation is None or observation.get("Status") in (
                "Pending", "InProgress", "Delayed", "Cancelling"):
            return journal
        if observation.get("Status") != "Success":
            current["state"] = "uncertain"
            journal["status"] = "uncertain"
            return persist(directory, journal)
        try:
            receipt = parse_receipt(observation.get("StandardOutputContent", ""), stage)
            _archive(directory, current, receipt)
            _validate_observation(bound, journal, current, receipt)
        except Exception:
            current["state"] = "uncertain"
            journal["status"] = "uncertain"
            persist(directory, journal)
            raise
        journal["observations"] += 1
        journal["current"] = None
        return persist(directory, journal)
