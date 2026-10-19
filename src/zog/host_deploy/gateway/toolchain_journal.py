"""Retained binding and stage identities for unattended typed toolchains."""
import hashlib
import json
from pathlib import Path

from ..workspace import save
from .image_build_execution import _canonical, _binding
from .ledger import load_dispatch, load_request, request_lock
from .toolchain_task import validate as validate_task, CONTRACT as TASK_CONTRACT

SCHEMA = "host-deploy-typed-toolchain-v1"
FILE = "typed-toolchain.json"
PHASES = ("cross-bootstrap", "temporary-userspace", "native-transition",
          "native-environment", "final-libc-build", "final-libc-publish",
          "final-math", "final-compiler")
RECOVERY = "final-libc-recover"
COMPLETE = ("completed", "failed", "uncertain")


def operation_id(gateway_id, phase, kind, ordinal=0):
    return hashlib.sha256(
        ("zog-typed-toolchain-v1:" + gateway_id + ":" + phase + ":"
         + kind + ":" + str(ordinal)).encode("ascii")
    ).hexdigest()[:32]


def binding(root, gateway_id):
    state = load_request(root, gateway_id)
    dispatch = load_dispatch(root, gateway_id)
    if (state["request"]["operation"] != "toolchain.submit"
            or state["states"]["admission"] != "admitted"
            or dispatch is None or dispatch["phase"] != "prepared"):
        raise RuntimeError("typed toolchain requires admitted frozen dispatch")
    bound = _binding(dispatch)
    task = bound.get("task")
    if (bound["remote_request"]["operation"] != "toolchain.specification.inspect"
            or type(task) is not dict
            or not bound.get("task_catalogue_identity")):
        raise RuntimeError("typed toolchain has no approved task binding")
    validate_task({"contract": TASK_CONTRACT, "task": task})
    if (task["source_revision"] != bound["source"]["revision"]
            or task["source_repository"] != bound["source"]["repository"]
            or task["lane"] != bound["lane"]
            or task["monthly_pin_identity"] != bound["monthly_pin_identity"]
            or task["monthly_pin_repository_path"] !=
               bound["monthly_pin_repository_path"]
            or bound["observed_state_dir"] is not None
            or bound["runtime_profile"]["controller"] is not True):
        raise RuntimeError("typed toolchain lane/provenance/controller mismatch")
    return bound


def initial(gateway_id, bound):
    return {
        "schema": SCHEMA, "request_id": gateway_id,
        "binding_sha256": hashlib.sha256(_canonical(bound)).hexdigest(),
        "catalogue_sha256": bound["task_catalogue_identity"],
        "status": "active", "specification": None, "phases": [],
        "current": None, "observations": 0, "recovery_authorized": False,
        "artifact_receipt": None,
    }


def read(directory, gateway_id, bound):
    path = directory / FILE
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise RuntimeError("unsafe typed toolchain journal")
    try:
        data = json.loads(path.read_text())
        expected = initial(gateway_id, bound)
        if (type(data) is not dict or set(data) != set(expected)
                or any(data[k] != expected[k] for k in
                       ("schema", "request_id", "binding_sha256", "catalogue_sha256"))
                or data["status"] not in ("active", "awaiting_recovery", *COMPLETE)
                or type(data["phases"]) is not list or len(data["phases"]) > 9
                or type(data["observations"]) is not int or data["observations"] < 0
                or type(data["recovery_authorized"]) is not bool):
            raise ValueError("header")
        previous = None
        for phase in data["phases"]:
            if (type(phase) is not dict
                    or phase.get("name") not in (*PHASES, RECOVERY)
                    or phase.get("operation_id") != operation_id(
                        gateway_id, phase["name"], "submit")
                    or phase.get("status") not in ("pending", "completed", "failed")
                    or type(phase.get("inspect_count")) is not int
                    or phase["inspect_count"] < 0
                    or type(phase.get("resume_count")) is not int
                    or phase["resume_count"] < 0
                    or type(phase.get("resume_authorized")) is not bool
                    or type(phase.get("evidence")) is not dict
                    or phase.get("predecessor") != (
                        previous["operation_id"] if previous else None)):
                raise ValueError("phase")
            if previous and previous["status"] != "completed" and not (
                    phase["name"] == RECOVERY
                    and previous["name"] == "final-libc-publish"
                    and previous["status"] == "failed"):
                raise ValueError("predecessor")
            previous = phase
        event = data["current"]
        if event is not None:
            if (type(event) is not dict
                    or set(event) != {"kind", "phase", "ordinal", "operation_id",
                                      "request", "request_sha256", "state", "command_id"}
                    or event["kind"] not in ("specification", "submit", "inspect", "resume")
                    or event["state"] not in ("prepared", "submitting",
                                           "submitted", "uncertain")
                    or event["operation_id"] != operation_id(
                        gateway_id, event["phase"], event["kind"], event["ordinal"])
                    or event["request"].get("operation_id") != event["operation_id"]
                    or event["request"].get("source") != bound["source"]
                    or hashlib.sha256(_canonical(event["request"])).hexdigest()
                       != event["request_sha256"]):
                raise ValueError("event")
        return data
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RuntimeError("typed toolchain journal integrity mismatch") from exc


def persist(directory, journal):
    save(directory / FILE, journal)
    return json.loads(json.dumps(journal))


def event(bound, journal, kind, phase, ordinal=0):
    op_id = operation_id(journal["request_id"], phase, kind, ordinal)
    if kind == "specification":
        operation, args = "toolchain.specification.inspect", {}
    elif kind == "submit":
        operation, args = "toolchain.submit", {"phase": phase}
        if phase == "cross-bootstrap":
            args["seed_generation"] = bound["task"]["seed_generation"]
    else:
        operation, args = "toolchain." + kind, {
            "operation_id": journal["phases"][-1]["operation_id"]
        }
    request = {"schema": "image-build-remote-operation-v1",
               "operation_id": op_id, "operation": operation,
               "source": bound["source"], "arguments": args}
    if kind == "submit" and journal["phases"]:
        request["predecessor"] = journal["phases"][-1]["operation_id"]
    return {"kind": kind, "phase": phase, "ordinal": ordinal,
            "operation_id": op_id, "request": request,
            "request_sha256": hashlib.sha256(_canonical(request)).hexdigest(),
            "state": "prepared", "command_id": None}


def stage_binding(bound, event_record):
    from copy import deepcopy
    staged = deepcopy(bound)
    op_id = event_record["operation_id"]
    remote = Path(staged["project_root"]) / "gateway-requests" / op_id
    staged["request_id"] = op_id
    staged["remote_request"] = event_record["request"]
    staged["remote_request_sha256"] = event_record["request_sha256"]
    staged["remote_request_path"] = str(remote / "request.json")
    staged["remote_result_path"] = str(remote / "result.json")
    staged["argv"][-1] = staged["remote_request_path"]
    staged["runtime_profile"]["operation"] = event_record["request"]["operation"]
    return _binding({"phase": "prepared", "binding": staged})
