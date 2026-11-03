"""Exclusive per-operation SSM send intent, separate from mutable pipeline journal.

Source-only local owner fence: protects against replay of *generic-pipeline.json*
while the separate send-intent directory survives. It is not independent
antirollback storage. Protected native installation must bind a separately
authenticated monotonic owner for full disk/reboot/authority rollback.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "host-deploy-generic-operation-send-once-v1"
_DIR = "generic-operation-send-intents"
_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class SendIntentBlocked(RuntimeError):
    pass


def _deny():
    raise SendIntentBlocked("original-ssm-operation-already-claimed-or-uncertain")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _expected(binding, request_id, step):
    if (type(request_id) is not str or _ID.fullmatch(request_id) is None
            or type(step) is not dict
            or type(step.get("operation_id")) is not str
            or _ID.fullmatch(step["operation_id"]) is None
            or type(step.get("request_sha256")) is not str
            or _SHA.fullmatch(step["request_sha256"]) is None
            or type(step.get("ordinal")) is not int
            or not 0 <= step["ordinal"] < 64
            or step.get("name") not in ("capabilities", "snapshot",
                                       "submit", "inspect")
            or type(binding) is not dict
            or type(binding.get("task_catalogue_identity")) is not str):
        _deny()
    return {
        "schema": SCHEMA,
        "request_id": request_id,
        "operation_id": step["operation_id"],
        "stage": step["name"],
        "ordinal": step["ordinal"],
        "remote_request_sha256": step["request_sha256"],
        "binding_sha256": hashlib.sha256(_canonical(binding)).hexdigest(),
        "task_catalogue_sha256": binding["task_catalogue_identity"],
        "source": binding["source"],
        "lane": binding["lane"],
        "target": binding["target"],
        "monthly_pin_identity": binding["monthly_pin_identity"],
        "task": binding["task"],
    }


def _open_base(gateway_root, request_id, *, create):
    if (type(request_id) is not str or _ID.fullmatch(request_id) is None):
        _deny()
    root = Path(gateway_root)
    if root.is_symlink() or not root.is_dir():
        _deny()
    # The fixed directory lives alongside, NOT inside, the mutable request
    # journal; its uid and mode must be independently checked.
    base = root / _DIR
    if create:
        try:
            base.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        _deny()
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        _deny()
    name = request_id + "--"
    return fd, name


def _load(fd, filename):
    try:
        leaf = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    except OSError:
        _deny()
    try:
        st = os.fstat(leaf)
        if (not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.geteuid()
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_nlink != 1 or not 0 < st.st_size <= 8192):
            _deny()
        raw = os.read(leaf, 8193)
        if len(raw) != st.st_size:
            _deny()
    finally:
        os.close(leaf)
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    _deny()
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _deny())
    except (ValueError, UnicodeError, TypeError):
        _deny()
    if type(data) is not dict or _canonical(data) != raw:
        _deny()
    return data


def _open(gateway_root, request_id, step, *, create=False):
    fd, prefix = _open_base(gateway_root, request_id, create=create)
    filename = prefix + step["operation_id"] + ".json"
    return fd, filename


def claim(gateway_root, request_id, binding, step):
    """Write-once, fsync-before-mutation: returning means this caller owns send.

    No callback may override the destination; repeated intent (even same
    bytes), partial write, symlink, or stale identity blocks all second sends.
    Call this under the existing per-request owner lock immediately before
    SendCommand, AFTER read-only preflight and producer receipt verification.
    """
    expected = _expected(binding, request_id, step)
    fd, filename = _open(gateway_root, request_id, step, create=True)
    try:
        try:
            leaf = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        except OSError:
            _deny()
        raw = _canonical(expected)
        try:
            st = os.fstat(leaf)
            if (st.st_uid != os.geteuid()
                    or stat.S_IMODE(st.st_mode) != 0o600
                    or st.st_nlink != 1):
                _deny()
            if os.write(leaf, raw) != len(raw):
                _deny()
            os.fsync(leaf)
        finally:
            os.close(leaf)
        os.fsync(fd)
        if _load(fd, filename) != expected:
            _deny()
        return expected
    finally:
        os.close(fd)


def require_claim(gateway_root, request_id, binding, step):
    """No editable journal receipt can invent a previously sent SSM command."""
    expected = _expected(binding, request_id, step)
    fd, filename = _open(gateway_root, request_id, step)
    try:
        if _load(fd, filename) != expected:
            _deny()
        return expected
    finally:
        os.close(fd)


def refuse_if_claimed(gateway_root, request_id, binding, step):
    """Fail closed if a valid old prepared record reappears after a send."""
    _expected(binding, request_id, step)
    fd, filename = _open(gateway_root, request_id, step, create=True)
    try:
        if _load(fd, filename) is not None:
            _deny()
    finally:
        os.close(fd)
