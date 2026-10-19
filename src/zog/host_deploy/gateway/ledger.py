"""Durable local request ledger and controlled workspace ownership."""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
import zipfile

from .. import checkpoint
from ..workspace import load as load_workspace
from ..workspace import locked as locked_workspace
from ..workspace import save
from .protocol import (
    RequestProtocolError,
    new_state,
    request_digest,
    transition,
    validate_state,
)


_HEX_32 = re.compile(r"[0-9a-f]{32}")
_MESSAGE = re.compile(r"[A-Za-z0-9_-]{1,200}")


class LedgerConflict(RuntimeError):
    """A durable request identity is already bound to different request bytes."""


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _identity(value, name):
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise ValueError(f"invalid {name}")
    if uuid.UUID(value).hex != value:
        raise ValueError(f"invalid {name}")
    return value


def ensure_root(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise ValueError("gateway state directory must not be a symlink")
    return root


@contextmanager
def dispatcher_lock(root):
    root = ensure_root(root)
    path = root / "dispatcher.lock"
    with path.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another gateway dispatcher owns this state directory") from None
        yield root


@contextmanager
def request_lock(root, request_id):
    root = ensure_root(root)
    request_id = _identity(request_id, "request_id")
    directory = root / "requests" / request_id
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "request.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield directory


def _load_state(directory):
    state = json.loads((Path(directory) / "state.json").read_text())
    return validate_state(state)


def load_request(root, request_id):
    with request_lock(root, request_id) as directory:
        return _load_state(directory)


def _delivery_value(message_id, receive_count, at):
    if not isinstance(message_id, str) or not _MESSAGE.fullmatch(message_id):
        raise ValueError("invalid SQS message identity")
    if type(receive_count) is not int or not 1 <= receive_count <= 1_000_000:
        raise ValueError("invalid SQS receive count")
    return {
        "message_id": message_id,
        "receive_count": receive_count,
        "last_seen_at": at,
    }


def accept(root, request, *, message_id, receive_count, at=None):
    at = at or utc_now()
    digest = request_digest(request)
    request_id = request["request_id"]
    delivery = _delivery_value(message_id, receive_count, at)
    with request_lock(root, request_id) as directory:
        state_path = directory / "state.json"
        duplicate = state_path.exists()
        if duplicate:
            state = _load_state(directory)
            if state["request_sha256"] != digest or state["request"] != request:
                raise LedgerConflict(
                    "request_id is already bound to a different validated request"
                )
        else:
            state = new_state(request)
            state = transition(state, "acceptance", "accepted", at)
            state = transition(state, "admission", "pending", at)
            save(state_path, state)

        transport_path = directory / "transport.json"
        if transport_path.exists():
            transport = json.loads(transport_path.read_text())
            if (
                transport.get("schema") != 1
                or transport.get("request_id") != request_id
                or transport.get("request_sha256") != digest
            ):
                raise LedgerConflict("durable SQS transport record does not match request")
            deliveries = transport.get("deliveries")
            if not isinstance(deliveries, list):
                raise LedgerConflict("durable SQS transport history is invalid")
        else:
            transport = {
                "schema": 1,
                "request_id": request_id,
                "request_sha256": digest,
                "first_seen_at": at,
                "deliveries": [],
                "acknowledgement": "pending",
            }
            deliveries = transport["deliveries"]
        deliveries.append(delivery)
        if len(deliveries) > 64:
            transport["deliveries"] = deliveries[-64:]
        transport["acknowledgement"] = "pending"
        save(transport_path, transport)
        return state, duplicate


def record_acknowledgement(root, request_id, state, *, at=None, error=None):
    at = at or utc_now()
    if state not in {"delete_attempting", "acked", "delete_uncertain"}:
        raise ValueError("invalid acknowledgement state")
    with request_lock(root, request_id) as directory:
        transport_path = directory / "transport.json"
        transport = json.loads(transport_path.read_text())
        transport["acknowledgement"] = state
        transport["acknowledgement_at"] = at
        if error is None:
            transport.pop("delete_error", None)
        else:
            transport["delete_error"] = str(error)[:512]
        save(transport_path, transport)


def record_failure(root, *, message_id, receive_count, body, error, at=None):
    root = ensure_root(root)
    at = at or utc_now()
    if not isinstance(body, str):
        body = repr(body)
    digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    safe_message = (
        message_id
        if isinstance(message_id, str) and _MESSAGE.fullmatch(message_id)
        else digest[:32]
    )
    directory = root / "failures" / safe_message
    directory.mkdir(parents=True, exist_ok=True)
    base = f"{receive_count:08d}"
    path = directory / (base + ".json")
    suffix = 0
    while path.exists():
        suffix += 1
        path = directory / (base + f"-{suffix}.json")
    save(
        path,
        {
            "schema": 1,
            "message_id": safe_message,
            "receive_count": receive_count,
            "observed_at": at,
            "body_sha256": digest,
            "error_type": type(error).__name__,
            "error": str(error)[:512],
        },
    )
    return path


def _owner_path(workspace):
    return Path(workspace) / "gateway-owner.json"


def owned_workspace(root, workspace_id):
    root = ensure_root(root)
    workspace_id = _identity(workspace_id, "workspace_id")
    path = root / "workspaces" / workspace_id
    marker = _owner_path(path)
    if not marker.exists():
        return None
    owner = json.loads(marker.read_text())
    if owner == {
        "schema": 1,
        "workspace_id": workspace_id,
        "owner": "released",
    }:
        return None
    if owner != {
        "schema": 1,
        "workspace_id": workspace_id,
        "owner": "host-deploy-gateway",
    }:
        raise RuntimeError("invalid gateway workspace ownership marker")
    workspace = load_workspace(path)
    if workspace["workspace_id"] != workspace_id:
        raise RuntimeError("gateway workspace identity mismatch")
    return path


def reconcile_request(root, request_id, *, at=None):
    at = at or utc_now()
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        if state["states"]["admission"] != "pending":
            return state
        workspace_id = state["request"]["workspace_id"]
        workspace = owned_workspace(root, workspace_id)
        observation = directory / "admission.json"
        if workspace is None:
            save(
                observation,
                {
                    "schema": 1,
                    "state": "pending",
                    "reason": "workspace_not_owned",
                    "observed_at": at,
                },
            )
            return state
        try:
            with locked_workspace(workspace) as locked:
                identity = load_workspace(locked)["workspace_id"]
                if identity != workspace_id:
                    raise RuntimeError("workspace identity changed during admission")
                state = transition(state, "admission", "admitted", at)
                save(directory / "state.json", state)
                save(
                    observation,
                    {
                        "schema": 1,
                        "state": "admitted",
                        "workspace_id": workspace_id,
                        "observed_at": at,
                    },
                )
                return state
        except RuntimeError as error:
            if "workspace lock" not in str(error):
                raise
            save(
                observation,
                {
                    "schema": 1,
                    "state": "pending",
                    "reason": "workspace_busy",
                    "observed_at": at,
                },
            )
            return state


def reconcile_all(root, *, at=None):
    root = ensure_root(root)
    directory = root / "requests"
    if not directory.exists():
        return []
    results = []
    for path in sorted(directory.iterdir()):
        if not path.is_dir() or not _HEX_32.fullmatch(path.name):
            continue
        reconcile_request(root, path.name, at=at)
        results.append(reconcile_dispatch(root, path.name, at=at))
    return results



_DISPATCH_PHASES = {
    "prepared",
    "submitting",
    "submitted",
    "submission_uncertain",
}


def _detached_json(value, label):
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ValueError(label + " must be finite JSON data") from None
    if len(encoded) > 128 * 1024:
        raise ValueError(label + " exceeds durable size limit")
    return json.loads(encoded), hashlib.sha256(encoded).hexdigest()


def _validate_dispatch_record(record, state):
    required = {
        "schema",
        "request_id",
        "request_sha256",
        "binding",
        "binding_sha256",
        "phase",
        "prepared_at",
    }
    phase = record.get("phase") if isinstance(record, dict) else None
    if phase == "submitting":
        required.add("attempt_started_at")
    elif phase == "submitted":
        required.update({"attempt_started_at", "command_id", "submitted_at"})
    elif phase == "submission_uncertain":
        required.update({"attempt_started_at", "uncertainty_at", "error"})
    if (
        not isinstance(record, dict)
        or set(record) != required
        or record.get("schema") != 1
        or phase not in _DISPATCH_PHASES
    ):
        raise LedgerConflict("invalid durable dispatch record")
    if (
        record["request_id"] != state["request_id"]
        or record["request_sha256"] != state["request_sha256"]
    ):
        raise LedgerConflict("dispatch record request binding mismatch")
    binding, digest = _detached_json(record["binding"], "dispatch binding")
    if record["binding_sha256"] != digest:
        raise LedgerConflict("dispatch binding digest mismatch")
    if (
        binding.get("request_id") != state["request_id"]
        or binding.get("workspace_id") != state["request"]["workspace_id"]
    ):
        raise LedgerConflict("dispatch binding identity mismatch")
    if phase == "submitted":
        command_id = record["command_id"]
        if (
            not isinstance(command_id, str)
            or not 1 <= len(command_id) <= 128
            or any(ord(character) < 33 or ord(character) > 126 for character in command_id)
        ):
            raise LedgerConflict("invalid durable SSM command identity")
    if phase == "submission_uncertain":
        if not isinstance(record["error"], str) or len(record["error"]) > 512:
            raise LedgerConflict("invalid dispatch uncertainty evidence")
    return record


def load_dispatch(root, request_id):
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        path = directory / "dispatch.json"
        if not path.exists():
            return None
        return json.loads(json.dumps(_validate_dispatch_record(
            json.loads(path.read_text()), state
        )))


def prepare_dispatch(root, request_id, binding, *, at=None):
    """Bind exact remote inputs before any SSM mutation."""
    at = at or utc_now()
    binding, binding_digest = _detached_json(binding, "dispatch binding")
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        if state["states"]["admission"] != "admitted":
            raise RuntimeError("dispatch preparation requires admitted request")
        if (
            binding.get("request_id") != request_id
            or binding.get("workspace_id") != state["request"]["workspace_id"]
        ):
            raise ValueError("dispatch binding does not match gateway request identity")
        path = directory / "dispatch.json"
        if path.exists():
            record = _validate_dispatch_record(json.loads(path.read_text()), state)
            if record["binding_sha256"] != binding_digest or record["binding"] != binding:
                raise LedgerConflict("dispatch is already bound to different inputs")
        else:
            record = {
                "schema": 1,
                "request_id": request_id,
                "request_sha256": state["request_sha256"],
                "binding": binding,
                "binding_sha256": binding_digest,
                "phase": "prepared",
                "prepared_at": at,
            }
            save(path, record)
        if state["states"]["dispatch"] == "not_started":
            state = transition(state, "dispatch", "prepared", at)
            save(directory / "state.json", state)
        elif state["states"]["dispatch"] not in {
            "prepared",
            "submitted",
            "submission_uncertain",
        }:
            raise LedgerConflict("gateway dispatch state conflicts with durable binding")
        return state, json.loads(json.dumps(record))


def record_dispatch_runtime_preflight(root, request_id, evidence, *, at=None):
    """Retain bounded producer readiness evidence while the request is prepared."""
    at = at or utc_now()
    evidence, _ = _detached_json(evidence, "runtime preflight evidence")
    if (not isinstance(evidence, dict) or evidence.get("contract")
            != "image-build-runtime-preflight-v1"
            or type(evidence.get("ready")) is not bool
            or evidence.get("mutation") is not False):
        raise ValueError("invalid producer runtime preflight report")
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        path = directory / "dispatch.json"
        record = _validate_dispatch_record(json.loads(path.read_text()), state)
        if record["phase"] != "prepared" or record["binding"].get("schema") != 3:
            raise RuntimeError("runtime preflight requires a prepared schema-3 dispatch binding")
        report_path = directory / "runtime-preflight.json"
        if report_path.exists():
            journal = json.loads(report_path.read_text())
            if (journal.get("schema") != 1
                    or journal.get("binding_sha256") != record["binding_sha256"]
                    or not isinstance(journal.get("observations"), list)):
                raise LedgerConflict("runtime preflight journal differs from bound dispatch")
        else:
            journal = {"schema": 1, "binding_sha256": record["binding_sha256"],
                       "observations": []}
        if len(journal["observations"]) >= 16:
            raise LedgerConflict("runtime preflight evidence journal is full")
        journal["observations"].append({"at": at, "report": evidence})
        _detached_json(journal, "runtime preflight journal")
        save(report_path, journal)
        return json.loads(json.dumps(journal))


def mark_dispatch_submitting(root, request_id, *, at=None):
    """Persist mutation intent before calling SSM SendCommand."""
    at = at or utc_now()
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        path = directory / "dispatch.json"
        record = _validate_dispatch_record(json.loads(path.read_text()), state)
        if record["phase"] == "submitting":
            raise RuntimeError("dispatch submission is already in progress")
        if record["phase"] != "prepared":
            raise RuntimeError("dispatch is not eligible for a new SSM submission")
        if state["states"]["dispatch"] != "prepared":
            raise LedgerConflict("dispatch intent requires prepared gateway state")
        if record["binding"].get("schema") == 3:
            evidence_path = directory / "runtime-preflight.json"
            if not evidence_path.is_file() or evidence_path.is_symlink():
                raise RuntimeError("producer preflight evidence is missing")
            evidence = json.loads(evidence_path.read_text())
            if (evidence.get("schema") != 1
                    or evidence.get("binding_sha256") != record["binding_sha256"]
                    or not isinstance(evidence.get("observations"), list)
                    or not evidence["observations"]
                    or evidence["observations"][-1]["report"].get("ready") is not True):
                raise RuntimeError("producer preflight has not passed for bound dispatch")
        record["phase"] = "submitting"
        record["attempt_started_at"] = at
        save(path, record)
        return json.loads(json.dumps(record))


def mark_dispatch_submitted(root, request_id, command_id, *, at=None):
    """Record the returned SSM CommandId before classifying dispatch as submitted."""
    at = at or utc_now()
    if (
        not isinstance(command_id, str)
        or not 1 <= len(command_id) <= 128
        or any(ord(character) < 33 or ord(character) > 126 for character in command_id)
    ):
        raise ValueError("invalid SSM command identity")
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        path = directory / "dispatch.json"
        record = _validate_dispatch_record(json.loads(path.read_text()), state)
        if record["phase"] == "submitted":
            if record["command_id"] != command_id:
                raise LedgerConflict("dispatch is bound to a different SSM command")
        elif record["phase"] in {"submitting", "submission_uncertain"}:
            record["phase"] = "submitted"
            record["command_id"] = command_id
            record["submitted_at"] = at
            record.pop("uncertainty_at", None)
            record.pop("error", None)
            save(path, record)
        else:
            raise RuntimeError("dispatch submission was not durably attempted")

        dispatch_state = state["states"]["dispatch"]
        if dispatch_state == "not_started":
            state = transition(state, "dispatch", "prepared", at)
            dispatch_state = "prepared"
        if dispatch_state in {"prepared", "submission_uncertain"}:
            state = transition(state, "dispatch", "submitted", at)
        if state["states"]["completion"] == "not_started":
            state = transition(state, "completion", "pending", at)
        save(directory / "state.json", state)
        return state, json.loads(json.dumps(record))


def mark_dispatch_uncertain(root, request_id, error, *, at=None):
    """Classify an attempted SSM mutation whose command identity is unavailable."""
    at = at or utc_now()
    message = str(error)[:512]
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        path = directory / "dispatch.json"
        record = _validate_dispatch_record(json.loads(path.read_text()), state)
        if record["phase"] == "submitted":
            return state, json.loads(json.dumps(record))
        if record["phase"] not in {"submitting", "submission_uncertain"}:
            raise RuntimeError("dispatch has no uncertain SSM submission attempt")
        record["phase"] = "submission_uncertain"
        record["uncertainty_at"] = at
        record["error"] = message
        save(path, record)
        dispatch_state = state["states"]["dispatch"]
        if dispatch_state == "not_started":
            state = transition(state, "dispatch", "prepared", at)
            dispatch_state = "prepared"
        if dispatch_state == "prepared":
            state = transition(state, "dispatch", "submission_uncertain", at)
            save(directory / "state.json", state)
        elif dispatch_state != "submission_uncertain":
            raise LedgerConflict("uncertain dispatch conflicts with gateway state")
        return state, json.loads(json.dumps(record))


def reconcile_dispatch(root, request_id, *, at=None):
    """Repair local state from a durable dispatch marker without resubmitting."""
    at = at or utc_now()
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        path = directory / "dispatch.json"
        if not path.exists():
            return state
        record = _validate_dispatch_record(json.loads(path.read_text()), state)
        dispatch_state = state["states"]["dispatch"]

        if record["phase"] == "prepared":
            if dispatch_state == "not_started":
                state = transition(state, "dispatch", "prepared", at)
                save(directory / "state.json", state)
            return state

        if record["phase"] == "submitting":
            record["phase"] = "submission_uncertain"
            record["uncertainty_at"] = at
            record["error"] = (
                "dispatcher recovered after SSM submission intent "
                "without a recorded command identity"
            )
            save(path, record)

        if record["phase"] == "submission_uncertain":
            dispatch_state = state["states"]["dispatch"]
            if dispatch_state == "not_started":
                state = transition(state, "dispatch", "prepared", at)
                dispatch_state = "prepared"
            if dispatch_state == "prepared":
                state = transition(state, "dispatch", "submission_uncertain", at)
                save(directory / "state.json", state)
            elif dispatch_state != "submission_uncertain":
                raise LedgerConflict("uncertain dispatch conflicts with gateway state")
            return state

        if record["phase"] == "submitted":
            dispatch_state = state["states"]["dispatch"]
            if dispatch_state == "not_started":
                state = transition(state, "dispatch", "prepared", at)
                dispatch_state = "prepared"
            if dispatch_state in {"prepared", "submission_uncertain"}:
                state = transition(state, "dispatch", "submitted", at)
            elif dispatch_state != "submitted":
                raise LedgerConflict("submitted dispatch conflicts with gateway state")
            if state["states"]["completion"] == "not_started":
                state = transition(state, "completion", "pending", at)
            result_path = directory / "remote-result.json"
            if result_path.exists():
                result_record = json.loads(result_path.read_text())
                if (
                    not isinstance(result_record, dict)
                    or result_record.get("schema") != 1
                    or result_record.get("request_id") != request_id
                    or result_record.get("command_id") != record["command_id"]
                    or result_record.get("completion") not in _COMPLETION_TARGETS
                ):
                    raise LedgerConflict("invalid retained remote result record")
                retained, digest = _detached_json(
                    result_record.get("result"), "remote result receipt"
                )
                if result_record.get("result_sha256") != digest:
                    raise LedgerConflict("retained remote result digest mismatch")
                state = _apply_completion(
                    state,
                    result_record["completion"],
                    at,
                )
            save(directory / "state.json", state)
            return state

        raise LedgerConflict("unknown durable dispatch phase")



def record_dispatch_observation(root, request_id, observation, *, at=None):
    """Persist a bounded latest SSM observation; this never authorizes resubmission."""
    at = at or utc_now()
    observation, _ = _detached_json(observation, "dispatch observation")
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        dispatch_path = directory / "dispatch.json"
        record = _validate_dispatch_record(
            json.loads(dispatch_path.read_text()), state
        )
        if record["phase"] != "submitted":
            raise RuntimeError("SSM observation requires submitted dispatch")
        value = {
            "schema": 1,
            "request_id": request_id,
            "command_id": record["command_id"],
            "observed_at": at,
            "observation": observation,
        }
        save(directory / "dispatch-observation.json", value)
        return json.loads(json.dumps(value))


_COMPLETION_TARGETS = {
    "running",
    "completed",
    "failed",
    "timed_out",
    "cancelled",
    "recovery_blocked",
}


def _apply_completion(state, target, at):
    if target not in _COMPLETION_TARGETS:
        raise ValueError("invalid gateway completion target")
    if state["states"]["dispatch"] != "submitted":
        raise RuntimeError("completion requires submitted dispatch")
    current = state["states"]["completion"]
    if current == target:
        return state
    if current == "not_started":
        state = transition(state, "completion", "pending", at)
        current = "pending"
    if current in {"completed", "failed", "timed_out", "cancelled"}:
        raise LedgerConflict("terminal gateway completion cannot change")
    return transition(state, "completion", target, at)


def mark_completion(root, request_id, target, *, at=None):
    """Advance gateway completion from submitted evidence without changing dispatch."""
    at = at or utc_now()
    with request_lock(root, request_id) as directory:
        state = _apply_completion(_load_state(directory), target, at)
        save(directory / "state.json", state)
        return state


def record_remote_result(root, request_id, result, completion, *, at=None):
    """Bind one immutable image-build result receipt before terminal classification."""
    at = at or utc_now()
    result, result_digest = _detached_json(result, "remote result receipt")
    with request_lock(root, request_id) as directory:
        state = _load_state(directory)
        dispatch_path = directory / "dispatch.json"
        dispatch = _validate_dispatch_record(
            json.loads(dispatch_path.read_text()), state
        )
        if dispatch["phase"] != "submitted":
            raise RuntimeError("remote result requires submitted dispatch")
        path = directory / "remote-result.json"
        if completion not in _COMPLETION_TARGETS:
            raise ValueError("invalid remote result completion")
        value = {
            "schema": 1,
            "request_id": request_id,
            "command_id": dispatch["command_id"],
            "result_sha256": result_digest,
            "completion": completion,
            "recorded_at": at,
            "result": result,
        }
        if path.exists():
            existing = json.loads(path.read_text())
            comparable = dict(existing)
            comparable["recorded_at"] = at
            if comparable != value:
                raise LedgerConflict("remote result differs from retained evidence")
            value = existing
        else:
            save(path, value)

    state = mark_completion(root, request_id, completion, at=at)
    return state, json.loads(json.dumps(value))


def _checkpoint_handoff_metadata(archive):
    archive = Path(archive)
    with zipfile.ZipFile(archive) as source:
        try:
            info = source.getinfo("checkpoint.json")
        except KeyError:
            raise ValueError("checkpoint metadata is missing") from None
        if info.file_size > 64 * 1024:
            raise ValueError("checkpoint metadata is oversized")
        metadata = json.loads(source.read(info))
    if metadata.get("schema") != 1 or metadata.get("handoff") is not True:
        raise ValueError("dispatcher ownership requires a handoff checkpoint")
    workspace_id = _identity(metadata.get("workspace_id"), "workspace_id")
    return metadata, workspace_id


def _file_sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _verify_restored_checkpoint(target, metadata):
    expected = metadata.get("files")
    if not isinstance(expected, dict):
        raise RuntimeError("handoff checkpoint file manifest is invalid")
    for name, digest in expected.items():
        path = Path(target) / name
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not path.is_file()
            or path.is_symlink()
            or _file_sha256(path) != digest
        ):
            raise RuntimeError("restored workspace differs from bound handoff checkpoint")


def claim_handoff(root, archive):
    root = ensure_root(root)
    archive = Path(archive).resolve()
    metadata, workspace_id = _checkpoint_handoff_metadata(archive)
    digest = _file_sha256(archive)
    ownership_path = root / "ownership" / (workspace_id + ".json")
    target = root / "workspaces" / workspace_id
    prepared = {
        "schema": 1,
        "workspace_id": workspace_id,
        "owner": "host-deploy-gateway",
        "checkpoint_sha256": digest,
        "phase": "prepared",
    }
    if ownership_path.exists():
        existing = json.loads(ownership_path.read_text())
        comparable = dict(existing)
        comparable["phase"] = "prepared"
        comparable.pop("completed_at", None)
        if comparable != prepared:
            raise RuntimeError("workspace ownership is bound to another checkpoint")
    else:
        save(ownership_path, prepared)

    if target.exists():
        workspace = load_workspace(target)
        if workspace["workspace_id"] != workspace_id:
            raise RuntimeError("existing dispatcher workspace identity mismatch")
        _verify_restored_checkpoint(target, metadata)
    else:
        restored = checkpoint.restore(archive, target)
        if restored["workspace_id"] != workspace_id:
            raise RuntimeError("restored dispatcher workspace identity mismatch")

    marker = {
        "schema": 1,
        "workspace_id": workspace_id,
        "owner": "host-deploy-gateway",
    }
    if _owner_path(target).exists():
        if json.loads(_owner_path(target).read_text()) != marker:
            raise RuntimeError("existing dispatcher ownership marker mismatch")
    else:
        save(_owner_path(target), marker)

    completed = dict(prepared)
    completed["phase"] = "owned"
    completed["completed_at"] = utc_now()
    save(ownership_path, completed)
    return {
        "workspace_id": workspace_id,
        "workspace": str(target),
        "checkpoint_sha256": digest,
        "owned": True,
    }


def release_handoff(root, workspace_id, output):
    root = ensure_root(root)
    workspace = owned_workspace(root, workspace_id)
    if workspace is None:
        raise RuntimeError("workspace is not owned by the gateway")
    result = checkpoint.export(workspace, output, handoff=True)
    save(
        _owner_path(workspace),
        {"schema": 1, "workspace_id": workspace_id, "owner": "released"},
    )
    ownership_path = root / "ownership" / (workspace_id + ".json")
    ownership = json.loads(ownership_path.read_text())
    ownership["phase"] = "released"
    ownership["released_at"] = utc_now()
    ownership["checkpoint"] = str(Path(output).absolute())
    save(ownership_path, ownership)
    return result


def summary(root):
    root = ensure_root(root)
    requests = root / "requests"
    failures = root / "failures"
    states = {}
    count = 0
    if requests.exists():
        for path in requests.iterdir():
            if not path.is_dir() or not _HEX_32.fullmatch(path.name):
                continue
            try:
                state = validate_state(json.loads((path / "state.json").read_text()))
            except (OSError, ValueError, RequestProtocolError):
                states["invalid"] = states.get("invalid", 0) + 1
                continue
            count += 1
            key = (
                state["states"]["acceptance"]
                + "/"
                + state["states"]["admission"]
                + "/"
                + state["states"]["dispatch"]
            )
            states[key] = states.get(key, 0) + 1
    failure_count = 0
    if failures.exists():
        failure_count = sum(1 for path in failures.rglob("*.json") if path.is_file())
    return {"requests": count, "states": states, "failure_evidence": failure_count}
