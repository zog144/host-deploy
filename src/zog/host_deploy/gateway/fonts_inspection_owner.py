"""Protected, finite Project-current read-only SSM observation owner.

An inspection is a NEW bounded SSM command, never a replay of the original
build. Both a gateway-local create-only intent and the installed root-control
LocalTaskCJournal's protected send-once intent precede that command. The
gateway's general-purpose Host sender must never be called directly here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .ledger import load_dispatch, load_request, request_lock
from .image_build_execution import _binding
from .project_current import validate as validate_current
from .project_current_observation import read_only_observation_script
from .protocol import request_digest

SCHEMA = "host-deploy-protected-project-observation-intent-v1"
RECEIPT = "host-deploy-protected-project-observation-command-v1"
FINISHED = "host-deploy-protected-project-observation-finished-v1"
TIMEOUT = 120
LIMIT = 64
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_COMMAND = re.compile(r"[A-Za-z0-9-]{1,128}\Z")


class InspectionOwnerUnavailable(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write_once(directory, filename, value):
    raw = _canonical(value) + b"\n"
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        if os.write(fd, raw) != len(raw):
            raise OSError("short protected inspection evidence write")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _read(directory, filename):
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600
                or not 0 < st.st_size < 8192):
            raise InspectionOwnerUnavailable("protected inspection record custody differs")
        raw = os.read(fd, 8192)
        if len(raw) != st.st_size:
            raise InspectionOwnerUnavailable("protected inspection evidence changed")
        value = json.loads(raw)
        if type(value) is not dict or raw != _canonical(value) + b"\n":
            raise InspectionOwnerUnavailable("noncanonical protected inspection record")
        return value
    finally:
        os.close(fd)


def _owner_factory(owner_factory):
    if owner_factory is not None:
        return owner_factory
    try:
        from zog.root_control.task_c_trusted_host import LocalTaskCJournal
    except ImportError as error:
        raise InspectionOwnerUnavailable(
            "protected root-control observation owner is not installed") from error
    return LocalTaskCJournal


def _checked_owner(factory):
    try:
        return _owner_factory(factory)()
    except (OSError, RuntimeError, ValueError) as error:
        raise InspectionOwnerUnavailable(
            "protected root-control observation owner unavailable") from error


def _validation(root, request_id, binding, target, original_command_id,
                pipeline_id, script, host):
    from .project_current import IDENTITY
    if (type(request_id) is not str or not _HEX32.fullmatch(request_id)
            or type(original_command_id) is not str
            or not _COMMAND.fullmatch(original_command_id)
            or (pipeline_id is not None and
                (type(pipeline_id) is not str or not IDENTITY.fullmatch(pipeline_id)))):
        raise InspectionOwnerUnavailable("invalid original observation identity")
    dispatch = load_dispatch(root, request_id)
    state = load_request(root, request_id)
    if (dispatch is None or dispatch.get("phase") != "submitted"
            or _binding(dispatch) != binding
            or dispatch.get("command_id") != original_command_id
            or state["request_sha256"] != request_digest(state["request"])
            or state["states"]["admission"] != "admitted"
            or state["request"]["operation"] != "build.submit"
            or state["request"]["parameters"] != {
                "lane": "gateway-first-fonts-runtime",
                "task": "graphics-fonts-image-v1",
            }):
        raise InspectionOwnerUnavailable("original admitted Project-current operation differs")
    validate_current(binding)
    if (type(target) is not dict or target != binding["target"]
            or getattr(host, "instance", target["instance_id"]) != target["instance_id"]
            or script != read_only_observation_script(
                binding["project_root"], binding["python_executable"], request_id,
                pipeline_id=pipeline_id)):
        raise InspectionOwnerUnavailable("inspection script or frozen compiler target differs")
    return {"schema": SCHEMA, "request_id": request_id,
            "original_command_id": original_command_id,
            "target": {key: target[key] for key in
                       ("instance_id", "region", "account_id")},
            "project_root": binding["project_root"],
            "python_executable": binding["python_executable"],
            "pipeline_id": pipeline_id,
            "frozen_binding_sha256": _sha(binding),
            "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
            "timeout_seconds": TIMEOUT}


def _attempt_names(directory):
    # Fixed names, not supplied paths. A foreign or partial record is a HOLD.
    names = [name for name in os.listdir(directory)
             if name.startswith("project-inspection-")]
    for name in names:
        if not re.fullmatch(r"project-inspection-[0-9]{4}\.(?:intent|command|done)\.json", name):
            raise InspectionOwnerUnavailable("unknown protected inspection record")
    seqs = sorted({int(x.split("-")[-1].split(".")[0]) for x in names})
    if seqs != list(range(1, len(seqs) + 1)) or len(seqs) > LIMIT:
        raise InspectionOwnerUnavailable("invalid protected inspection attempt sequence")
    return seqs


def submit_or_recover(root, request_id, *, binding, target,
                      original_command_id, pipeline_id, script, host,
                      owner_factory=None):
    """Return an authenticated inspection CommandId; never resend a pending one.

    Reconciliation after a lost SSM acknowledgement reads the journal's
    retained CommandId. An intent with no journal CommandId is uncertain and
    cannot be retried. Only an explicitly finished earlier inspection permits
    a NEW separately journaled read-only inspection.
    """
    reviewed = _validation(root, request_id, binding, target,
                           original_command_id, pipeline_id, script, host)
    journal = _checked_owner(owner_factory)
    try:
        with request_lock(root, request_id) as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                seqs = _attempt_names(fd)
                n = seqs[-1] if seqs else 0
                if n and _read(fd, f"project-inspection-{n:04d}.done.json") is None:
                    row = _read(fd, f"project-inspection-{n:04d}.intent.json")
                    if row is None:
                        raise InspectionOwnerUnavailable("protected inspection intent missing")
                    original = {key: row[key] for key in reviewed}
                    if original != reviewed:
                        raise InspectionOwnerUnavailable("pending inspection differs from frozen selection")
                    inspection_operation_id = row.get("inspection_operation_id")
                    if (type(inspection_operation_id) is not str
                            or not _HEX32.fullmatch(inspection_operation_id)):
                        raise InspectionOwnerUnavailable("protected inspection operation ID differs")
                    retained, command, cancelled = journal.inspect(inspection_operation_id)
                    if (retained is None or cancelled is not None or command is None
                            or command.get("command_id") is None):
                        raise InspectionOwnerUnavailable(
                            "inspection SSM acknowledgement uncertain; no replay")
                    expected_intent = {
                        "schema": "zog-task-c-trusted-host-local-intent-v1",
                        "operation_id": inspection_operation_id,
                        "request_sha256": _sha(row),
                        "script_sha256": row["script_sha256"],
                        "target": row["target"], "document": "AWS-RunShellScript",
                        "execution_timeout_seconds": TIMEOUT,
                    }
                    if retained != expected_intent:
                        raise InspectionOwnerUnavailable("protected inspection journal differs")
                    command_id = command["command_id"]
                    if (command != {
                            "schema": "zog-task-c-trusted-host-command-v1",
                            "operation_id": inspection_operation_id,
                            "request_sha256": _sha(row),
                            "command_id": command_id}
                            or not isinstance(command_id, str)
                            or not _COMMAND.fullmatch(command_id)
                            or command_id == original_command_id):
                        raise InspectionOwnerUnavailable("protected inspection CommandId differs")
                    local = _read(fd, f"project-inspection-{n:04d}.command.json")
                    if local is not None and local != {
                            "schema": RECEIPT, "inspection_operation_id": inspection_operation_id,
                            "command_id": command_id}:
                        raise InspectionOwnerUnavailable("inspection acknowledgement differs")
                    if local is None:
                        _write_once(fd, f"project-inspection-{n:04d}.command.json", {
                            "schema": RECEIPT,
                            "inspection_operation_id": inspection_operation_id,
                            "command_id": command_id})
                    return n, command_id
                if n >= LIMIT:
                    raise InspectionOwnerUnavailable("protected inspection history full")
                n += 1
                row = {**reviewed, "inspection_operation_id": uuid.uuid4().hex}
                name = f"project-inspection-{n:04d}.intent.json"
                _write_once(fd, name, row)
                # The root journal writes its own immutable O_EXCL intent BEFORE SSM.
                # Any error now leaves the local attempt incomplete, not retryable.
                command_id = journal.submit_once(
                    operation_id=row["inspection_operation_id"],
                    request_sha256=_sha(row), script=script,
                    target=reviewed["target"], seconds=TIMEOUT, sender=host)
                if (type(command_id) is not str
                        or not _COMMAND.fullmatch(command_id)
                        or command_id == original_command_id):
                    raise InspectionOwnerUnavailable(
                        "inspection CommandId must differ from original protected build")
                _write_once(fd, f"project-inspection-{n:04d}.command.json", {
                    "schema": RECEIPT, "inspection_operation_id": row["inspection_operation_id"],
                    "command_id": command_id})
                return n, command_id
            finally:
                os.close(fd)
    finally:
        journal.close()


def finish(root, request_id, number, command_id, *, status):
    """Only a confirmed terminal SSM invocation can release the next attempt."""
    if status not in ("Success", "Failed", "Cancelled", "TimedOut"):
        raise InspectionOwnerUnavailable("inspection has no terminal SSM status")
    with request_lock(root, request_id) as directory:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            row = _read(fd, f"project-inspection-{number:04d}.command.json")
            if row is None or row.get("command_id") != command_id:
                raise InspectionOwnerUnavailable("protected inspection completion lacks CommandId")
            done = {"schema": FINISHED, "inspection_operation_id": row["inspection_operation_id"],
                    "command_id": command_id, "status": status}
            name = f"project-inspection-{number:04d}.done.json"
            old = _read(fd, name)
            if old is not None:
                if old != done:
                    raise InspectionOwnerUnavailable("protected inspection completion differs")
            else:
                _write_once(fd, name, done)
        finally:
            os.close(fd)
