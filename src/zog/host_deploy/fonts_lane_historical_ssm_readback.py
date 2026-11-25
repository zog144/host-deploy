"""Bounded historical SSM *readback*, never SendCommand or replay.

The original November 14 migration ran before the current protected Gateway
build sender. Nothing here assumes those old commands were in a root-control
journal; if they were not, this contract explicitly HOLDS. Only a separately
approved, existing protected identity record and genuine matching root-control
journal entries permit GetCommandInvocation/ListCommands readback.

All success statuses are historical observations, NEVER proof of the writer
that later selected the active certbot-seed lane or a build admission.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import fonts_lane_supersession_audit as audit

SCHEMA = "host-deploy-first-fonts-nov14-command-evidence-v1"
REPORT = "host-deploy-first-fonts-historical-command-readback-v1"
EVIDENCE = "first-fonts-nov14-historical-commands-v1.json"
JOURNAL_ROOT = "/var/lib/zog-task-c/operations"
ORIGINAL_INTENT = "zog-task-c-trusted-host-local-intent-v1"
ORIGINAL_COMMAND = "zog-task-c-trusted-host-command-v1"
STATES = frozenset(("Success", "Failed", "TimedOut", "Cancelled"))
_COMMAND_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_OP = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA_KEYS = {"schema", "binding", "selected_lane_record_sha256",
                "pending_intent_sha256", "original_specification_sha256",
                "commands"}
_ORDER = ("initial-attempt", "later-attempt")
_WINDOW_START = datetime(2026, 11, 13, tzinfo=timezone.utc)
_WINDOW_END = datetime(2026, 11, 17, tzinfo=timezone.utc)
_MAX = 8192


class HistoricalHold(RuntimeError):
    """Readback denied: original identity or protected evidence is missing."""


def _fail(reason):
    raise HistoricalHold(reason)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate key in retained command evidence")
        result[key] = value
    return result


def _parse(raw, *, newline):
    try:
        obj = json.loads(raw, object_pairs_hook=_unique,
                         parse_constant=lambda _: _fail("nonfinite history evidence"))
    except (ValueError, UnicodeError, TypeError) as error:
        raise HistoricalHold("invalid protected historical command evidence") from error
    if (type(obj) is not dict or
            raw != _canonical(obj) + (b"\n" if newline else b"")):
        _fail("noncanonical protected historical command evidence")
    return obj


def _open_dir(path, *, root_owner=True):
    path = Path(path)
    if (not path.is_absolute() or path == Path("/")
            or os.path.normpath(str(path)) != str(path)):
        _fail("noncanonical historical journal path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                _fail("redirected historical journal ancestor")
            new = os.open(part, os.O_RDONLY | os.O_NOFOLLOW |
                          os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            after = os.fstat(new)
            sticky_root = (after.st_uid == 0 and
                           stat.S_IMODE(after.st_mode) == 0o1777)
            if ((before.st_dev, before.st_ino, before.st_uid,
                 before.st_mode) !=
                (after.st_dev, after.st_ino, after.st_uid,
                 after.st_mode) or
                (after.st_mode & 0o022 and not sticky_root)):
                os.close(new)
                _fail("untrusted journal ancestor owner/mode/inode")
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        if (root_owner and
                (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700)):
            _fail("protected original root journal owner or mode differs")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file(fd, name, *, owner=None, newline=False, optional=False):
    if owner is None:
        owner = os.geteuid()  # Only trusted root may open the native journal.
    if (type(name) is not str or not re.fullmatch(
            r"[a-z0-9][A-Za-z0-9_.-]{0,127}", name)):
        _fail("untrusted historical record basename")
    try:
        first = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        if optional:
            return None, None
        _fail("required original command record missing: " + name)
    if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
            or first.st_uid != owner or stat.S_IMODE(first.st_mode) != 0o600
            or not 0 < first.st_size <= _MAX):
        _fail("foreign original command record: " + name)
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        now = os.fstat(opened)
        attrs = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                 "st_nlink", "st_size")
        if any(getattr(now, a) != getattr(first, a) for a in attrs):
            _fail("historical record replaced before read")
        raw = os.read(opened, _MAX + 1)
        after = os.fstat(opened)
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (len(raw) != first.st_size
                or (now.st_dev, now.st_ino, now.st_mtime_ns,
                    now.st_ctime_ns, now.st_size) !=
                   (after.st_dev, after.st_ino, after.st_mtime_ns,
                    after.st_ctime_ns, after.st_size)
                or any(getattr(named, a) != getattr(first, a) for a in attrs)):
            _fail("original command record changed during readback")
        return _parse(raw, newline=newline), _sha(raw)
    finally:
        os.close(opened)


@contextmanager
def _journal(directory):
    """Acquire EXISTING root-owned lock shared, without creating a file."""
    if os.geteuid() != 0:
        _fail("historical command readback requires trusted root observer")
    fd = _open_dir(directory)
    try:
        before = os.stat(".lock", dir_fd=fd, follow_symlinks=False)
        lock = os.open(".lock", os.O_RDONLY | os.O_NOFOLLOW |
                       os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        try:
            actual = os.fstat(lock)
            if (not stat.S_ISREG(actual.st_mode) or actual.st_uid != 0
                    or actual.st_nlink != 1 or
                    stat.S_IMODE(actual.st_mode) != 0o600 or
                    (before.st_dev, before.st_ino) !=
                    (actual.st_dev, actual.st_ino)):
                _fail("root journal lock is foreign")
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise HistoricalHold("protected root journal busy") from error
            yield fd
            latest = os.stat(".lock", dir_fd=fd, follow_symlinks=False)
            if (latest.st_dev, latest.st_ino) != (actual.st_dev, actual.st_ino):
                _fail("historical root journal lock replaced")
        finally:
            os.close(lock)
    finally:
        os.close(fd)


def _selected_report(workspace, selections):
    return audit.inspect(workspace, **selections)


def _evidence(workspace, selected, expected_evidence_sha256):
    if (type(expected_evidence_sha256) is not str or
            not _SHA.fullmatch(expected_evidence_sha256)):
        _fail("independent approved evidence SHA required")
    with audit._locked_workspace(workspace) as fd:
        # Protected existing bytes only. Never create or import a review record.
        raw = audit._read(fd, EVIDENCE)
        parsed = _parse(raw, newline=True)
        if _sha(raw) != expected_evidence_sha256:
            _fail("review-approved historical command evidence digest differs")
        if (set(parsed) != _SCHEMA_KEYS or parsed["schema"] != SCHEMA
                or parsed["binding"] != selected["compiler_target"]
                or parsed["selected_lane_record_sha256"] !=
                    selected["selected_lane_record_sha256"]
                or parsed["pending_intent_sha256"] !=
                    selected["pending_intent_sha256"]
                or parsed["original_specification_sha256"] !=
                    selected["original_schema4_specification_sha256"]):
            _fail("approved original history does not bind selected Gateway lane")
        commands = parsed["commands"]
        if type(commands) is not list or len(commands) != 2:
            _fail("exactly two original command identities required")
        expected_keys = {"ordinal", "operation_id", "command_id",
                         "request_sha256", "script_sha256",
                         "execution_timeout_seconds"}
        ids = []
        for position, row in enumerate(commands):
            if (type(row) is not dict or set(row) != expected_keys
                    or row["ordinal"] != _ORDER[position]
                    or type(row["operation_id"]) is not str
                    or not _OP.fullmatch(row["operation_id"])
                    or type(row["command_id"]) is not str
                    or not _COMMAND_ID.fullmatch(row["command_id"])
                    or any(type(row[k]) is not str or not _SHA.fullmatch(row[k])
                           for k in ("request_sha256", "script_sha256"))
                    or type(row["execution_timeout_seconds"]) is not int
                    or not 1 <= row["execution_timeout_seconds"] <= 21600):
                _fail("unapproved original SSM operation identity or script")
            ids.extend((row["operation_id"], row["command_id"]))
        if len(set(ids)) != 4:
            _fail("original command identities repeat")
        if audit._read(fd, EVIDENCE) != raw:
            _fail("approved historical witness changed")
    return parsed, expected_evidence_sha256


def _original_journal_rows(directory, evidence):
    with _journal(directory) as fd:
        selected = []
        for row in evidence["commands"]:
            operation = row["operation_id"]
            intent_name = operation + ".intent.json"
            command_name = operation + ".command.json"
            cancel_name = operation + ".cancel.json"
            intent, intent_sha = _file(fd, intent_name)
            result, result_sha = _file(fd, command_name)
            cancel, _ = _file(fd, cancel_name, optional=True)
            target = evidence["binding"]
            expected = {
                "schema": ORIGINAL_INTENT,
                "operation_id": operation,
                "request_sha256": row["request_sha256"],
                "script_sha256": row["script_sha256"],
                "target": {k: target[k] for k in
                           ("instance_id", "region", "account_id")},
                "document": "AWS-RunShellScript",
                "execution_timeout_seconds": row["execution_timeout_seconds"],
            }
            if intent != expected or cancel is not None or result != {
                "schema": ORIGINAL_COMMAND,
                "operation_id": operation,
                "request_sha256": row["request_sha256"],
                "command_id": row["command_id"],
            }:
                _fail("root-controlled original send intent/ack differs or is cancelled")
            selected.append({"operation_id": operation,
                             "intent_sha256": intent_sha,
                             "command_record_sha256": result_sha})
        # Re-read under the same existing lock, rejecting a local swap.
        for row, frozen in zip(evidence["commands"], selected):
            op = row["operation_id"]
            if (_file(fd, op + ".intent.json")[1] != frozen["intent_sha256"]
                    or _file(fd, op + ".command.json")[1] !=
                       frozen["command_record_sha256"]):
                _fail("protected original command records changed")
        return selected


def _date(value):
    if isinstance(value, datetime):
        dt = value
    elif type(value) in (int, float) and not isinstance(value, bool):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        _fail("SSM command time missing or invalid")
    if dt.tzinfo is None:
        _fail("SSM command UTC time has no timezone")
    return dt.astimezone(timezone.utc)


def _ssm_readback(client, row, target):
    """Only ListCommands and GetCommandInvocation; no SendCommand escape."""
    cmd_id = row["command_id"]
    instance = target["instance_id"]
    listed = client.list_commands(CommandId=cmd_id, MaxResults=2)
    if (type(listed) is not dict or listed.get("NextToken") or
            type(listed.get("Commands")) is not list or
            len(listed["Commands"]) != 1):
        _fail("original SSM command metadata absent/ambiguous")
    command = listed["Commands"][0]
    p = command.get("Parameters")
    instances = command.get("InstanceIds")
    targeting = command.get("Targets", [])
    # Explicit instance-only target. No tags, multi-Host targets or wildcard.
    if (command.get("CommandId") != cmd_id
            or command.get("DocumentName") != "AWS-RunShellScript"
            or type(instances) is not list
            or instances != [instance]
            or targeting not in (None, [])
            or type(p) is not dict or set(p) != {"commands", "executionTimeout"}
            or type(p["commands"]) is not list or len(p["commands"]) != 1
            or type(p["commands"][0]) is not str
            or _sha(p["commands"][0].encode("utf-8")) != row["script_sha256"]
            or p["executionTimeout"] != [
                str(row["execution_timeout_seconds"])]):
        _fail("SSM service command script/document/instance differs from root journal")
    requested = _date(command.get("RequestedDateTime"))
    if not _WINDOW_START <= requested < _WINDOW_END:
        _fail("SSM command is outside original November 14 window")
    invocation = client.get_command_invocation(CommandId=cmd_id,
                                                InstanceId=instance)
    if (type(invocation) is not dict
            or invocation.get("CommandId") != cmd_id
            or invocation.get("InstanceId") != instance
            or invocation.get("DocumentName") != "AWS-RunShellScript"
            or invocation.get("Status") not in STATES
            or type(invocation.get("ResponseCode")) is not int):
        _fail("SSM invocation result incomplete, pending or foreign")
    status = invocation["Status"]
    if command.get("Status") != status:
        _fail("SSM command/invocation terminal status differs")
    stdout, stderr = (invocation.get("StandardOutputContent"),
                      invocation.get("StandardErrorContent"))
    if (type(stdout) is not str or type(stderr) is not str
            or len(stdout.encode("utf-8")) > 96000
            or len(stderr.encode("utf-8")) > 96000):
        _fail("SSM bounded output was not returned")
    return {
        "operation_id": row["operation_id"],
        "command_id": cmd_id, "status": status,
        "response_code": invocation["ResponseCode"],
        "requested_at_utc": requested.isoformat(),
        "script_sha256": row["script_sha256"],
        "stdout_prefix_sha256": _sha(stdout.encode("utf-8")),
        "stderr_prefix_sha256": _sha(stderr.encode("utf-8")),
        "stdout_bytes_observed": len(stdout.encode("utf-8")),
        "stderr_bytes_observed": len(stderr.encode("utf-8")),
        "full_stdout_authenticated": False,
        "historical_writer_authenticated": False,
    }


def inspect(workspace, *, approvals, expected_evidence_sha256,
            journal_directory=JOURNAL_ROOT, ssm_client, sts_client,
            aws_region):
    """Observe two already-sent commands, never select an arbitrary ID.

    The exact reviewed witness and matching original root-owned journal
    entries are mandatory *before* any AWS read. No original journal =>
    HOLD and no AWS call. An AWS Success is never a lane selection receipt.
    """
    current = _selected_report(workspace, approvals)
    if (current.get("status") != "supersession-unproven" or
            current.get("execution_authorized") is not False):
        _fail("current protected lane must remain nonauthorizing")
    evidence, digest = _evidence(workspace, current, expected_evidence_sha256)
    original = _original_journal_rows(journal_directory, evidence)
    target = current["compiler_target"]
    identity = sts_client.get_caller_identity()
    if (type(identity) is not dict or
            type(aws_region) is not str or aws_region != target["region"]
            or type(identity.get("Account")) is not str
            or identity["Account"] != target["account_id"]):
        _fail("AWS credential account/region does not match admitted compiler")
    results = []
    for record in evidence["commands"]:
        results.append(_ssm_readback(ssm_client, record, target))
    # Repeat current local selection and root original command identities.
    if _selected_report(workspace, approvals) != current:
        _fail("Gateway lane or original migration intent changed during AWS readback")
    if _original_journal_rows(journal_directory, evidence) != original:
        _fail("protected original command journal changed during AWS readback")
    return {
        "schema": REPORT,
        "status": "supersession-unproven",
        "binding": target,
        "selected_lane_record_sha256": current["selected_lane_record_sha256"],
        "pending_intent_sha256": current["pending_intent_sha256"],
        "reviewed_witness_sha256": digest,
        "original_journal_attested": True,
        "historical_ssm_readback": results,
        "original_migration_to_current_lane_transition_verified": False,
        "superseding_writer": None,
        "mutation": False, "ssm_send_authorized": False,
        "execution_authorized": False, "compilation_authorized": False,
    }
