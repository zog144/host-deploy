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
        permitted_sequence = list(PHASES)
        if any(p.get("name") == RECOVERY for p in data["phases"] if isinstance(p, dict)):
            permitted_sequence.insert(6, RECOVERY)
        if [p.get("name") for p in data["phases"] if isinstance(p, dict)] != (
                permitted_sequence[:len(data["phases"])]):
            raise ValueError("out-of-order or repeated toolchain phase")
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
        active = data["current"]
        if active is not None:
            if (type(active) is not dict
                    or set(active) != {"kind", "phase", "ordinal", "operation_id",
                                      "request", "request_sha256", "state", "command_id"}
                    or active["kind"] not in ("specification", "submit", "inspect", "resume")
                    or active["state"] not in ("prepared", "submitting",
                                           "submitted", "uncertain")
                    or active["operation_id"] != operation_id(
                        gateway_id, active["phase"], active["kind"], active["ordinal"])
                    or active["request"].get("operation_id") != active["operation_id"]
                    or active["request"].get("source") != bound["source"]
                    or hashlib.sha256(_canonical(active["request"])).hexdigest()
                       != active["request_sha256"]):
                raise ValueError("event")
        if active is not None:
            # The stored request digest is unkeyed; an attacker or stale
            # recovery snapshot can recompute it. Reconstruct the exact
            # authorized request from the immutable bound task, generation,
            # source and predecessor and reject any alternate selection.
            original = event(bound, data, active["kind"], active["phase"],
                             active["ordinal"])
            if active["request"] != original["request"]:
                raise ValueError("frozen event differs from typed binding")
            # A currently selected request must also be reachable from the
            # already completed/authorized phase history, not merely name a
            # generally permitted worker phase.
            last = data["phases"][-1] if data["phases"] else None
            if active["kind"] == "specification":
                if data["specification"] is not None or last is not None:
                    raise ValueError("duplicate specification event")
            elif active["kind"] == "submit":
                if data["specification"] is None:
                    raise ValueError("submit before approved specification")
                if last is None:
                    expected_phase = PHASES[0]
                elif last["status"] == "failed":
                    expected_phase = (RECOVERY if
                        last["name"] == "final-libc-publish" and data["recovery_authorized"]
                        and "toolchain.submit" in last["evidence"].get("allowed_next_operations", [])
                        else None)
                elif last["status"] != "completed" or last["name"] == "final-compiler":
                    expected_phase = None
                elif last["name"] == RECOVERY:
                    expected_phase = "final-math"
                else:
                    expected_phase = PHASES[PHASES.index(last["name"]) + 1]
                if active["phase"] != expected_phase:
                    raise ValueError("toolchain submit not next authorized phase")
            elif (last is None or last["status"] != "pending"
                    or active["ordinal"] != last[
                        "inspect_count" if active["kind"] == "inspect" else "resume_count"]
                    or (active["kind"] == "resume" and not last["resume_authorized"])):
                raise ValueError("toolchain observation not authorized by pending phase")
            # A caller cannot authorize a novel worker by regenerating a
            # self-consistent operation_id and SHA for an unreviewed phase.
            if (active["phase"] not in ("specification", *PHASES, RECOVERY)
                    or (active["kind"] == "specification"
                        and (active["phase"] != "specification"
                             or active["ordinal"] != 0))
                    or (active["kind"] == "submit"
                        and (active["phase"] == "specification"
                             or active["ordinal"] != 0))
                    or (active["kind"] in ("inspect", "resume")
                        and (not data["phases"] or active["phase"] !=
                             data["phases"][-1]["name"]))):
                raise ValueError("unreviewed toolchain stage selection")
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
    remote = (
        Path("/var/lib/host-deploy/typed-toolchain-requests")
        / staged["workspace_id"] / op_id
        if "compiler_execution_identity" in staged
        else Path(staged["project_root"]) / "gateway-requests" / op_id
    )
    staged["request_id"] = op_id
    staged["remote_request"] = event_record["request"]
    staged["remote_request_sha256"] = event_record["request_sha256"]
    staged["remote_request_path"] = str(remote / "request.json")
    staged["remote_result_path"] = str(remote / "result.json")
    staged["argv"][-1] = staged["remote_request_path"]
    staged["runtime_profile"]["operation"] = event_record["request"]["operation"]
    return _binding({"phase": "prepared", "binding": staged})
