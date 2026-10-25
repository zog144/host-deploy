"""Host-owned aggregate budget guard for one fresh cross-bootstrap operation.

Not a background monitor by itself. The protected host installer must run
tick() from a separate boot-reactivated watchdog at least once per minute.
Source-only inspection can never stand in for an installed native watchdog.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

SCHEMA = "host-deploy-fresh-cross-bootstrap-budget-v1"
DEADLINE_SECONDS = 21600
ADDITIONAL_DISK_BYTES = 34359738368
MAX_HEARTBEAT_SECONDS = 60
_HEX = re.compile(r"[0-9a-f]{32}\Z")


def _canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(x):
    return hashlib.sha256(_canonical(x)).hexdigest()


def begin(*, request_id, host_id, project_root, boot_id,
          now_seconds, monotonic_seconds, used_bytes, sidecar_plan_sha256,
          monitor_receipt_sha256):
    """Freeze exactly one root-owned budget, generated only after native admission."""
    if type(request_id) is not str or not _HEX.fullmatch(request_id):
        raise ValueError("invalid unique new owner request")
    if (not isinstance(host_id, str) or not host_id
            or type(project_root) is not str or not project_root.startswith("/")
            or type(boot_id) is not str or not boot_id):
        raise ValueError("budget owner/host/Project missing")
    for value in (now_seconds, monotonic_seconds, used_bytes):
        if type(value) is not int or value < 0:
            raise ValueError("budget clock/usage counter invalid")
    for digest in (sidecar_plan_sha256, monitor_receipt_sha256):
        if (type(digest) is not str or len(digest) != 71
                or not digest.startswith("sha256:")
                or any(c not in "0123456789abcdef" for c in digest[7:])):
            raise ValueError("budget host-owned monitor/sidecar receipt absent")
    return {
        "schema": SCHEMA, "request_id": request_id, "host_id": host_id,
        "project_root": project_root, "boot_id": boot_id,
        "started_at_seconds": now_seconds,
        "deadline_seconds": now_seconds + DEADLINE_SECONDS,
        "started_monotonic_seconds": monotonic_seconds,
        "baseline_disk_used_bytes": used_bytes,
        "last_disk_used_bytes": used_bytes,
        "last_tick_seconds": now_seconds,
        "last_monotonic_seconds": monotonic_seconds,
        "sidecar_plan_sha256": sidecar_plan_sha256,
        "monitor_receipt_sha256": monitor_receipt_sha256,
        "status": "active", "stop_receipt": None,
    }


def validate(value):
    if type(value) is not dict or set(value) != set(begin(
            request_id="0"*32, host_id="host", project_root="/project",
            boot_id="boot", now_seconds=0, monotonic_seconds=0,
            used_bytes=0, sidecar_plan_sha256="sha256:"+"0"*64,
            monitor_receipt_sha256="sha256:"+"1"*64)):
        raise ValueError("invalid durable budget schema")
    if (value["schema"] != SCHEMA or not _HEX.fullmatch(value["request_id"])
            or type(value["host_id"]) is not str or not value["host_id"]
            or type(value["project_root"]) is not str
            or not value["project_root"].startswith("/")
            or type(value["boot_id"]) is not str or not value["boot_id"]
            or value["status"] not in ("active", "stopped", "uncertain")
            or value["deadline_seconds"] != value["started_at_seconds"] + DEADLINE_SECONDS):
        raise ValueError("budget owner/deadline mismatch")
    for key in ("started_at_seconds", "deadline_seconds",
                "started_monotonic_seconds", "baseline_disk_used_bytes",
                "last_disk_used_bytes", "last_tick_seconds",
                "last_monotonic_seconds"):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError("negative/invalid budget counter")
    if (value["last_tick_seconds"] < value["started_at_seconds"]
            or value["last_monotonic_seconds"] < value["started_monotonic_seconds"]):
        raise ValueError("non-monotonic retained budget")
    for key in ("sidecar_plan_sha256", "monitor_receipt_sha256"):
        if (type(value[key]) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key])):
            raise ValueError("budget authority is unbound")
    if value["status"] == "active" and value["stop_receipt"] is not None:
        raise ValueError("active budget has stop receipt")
    return json.loads(_canonical(value))


def evaluate(value, *, host_id, project_root, boot_id, now_seconds,
             monotonic_seconds, used_bytes, monitor_receipt_sha256,
             watchdog_active, sidecar_active):
    """Pure fail-closed decision from host-owned clocks/quota/monitor evidence."""
    x = validate(value)
    if x["status"] != "active":
        return "stop"
    if (host_id != x["host_id"] or project_root != x["project_root"]
            or boot_id != x["boot_id"]
            or monitor_receipt_sha256 != x["monitor_receipt_sha256"]
            or watchdog_active is not True or sidecar_active is not True):
        return "uncertain"
    if any(type(k) is not int or k < 0
           for k in (now_seconds, monotonic_seconds, used_bytes)):
        return "uncertain"
    if (now_seconds < x["last_tick_seconds"]
            or monotonic_seconds < x["last_monotonic_seconds"]
            or now_seconds - x["last_tick_seconds"] > MAX_HEARTBEAT_SECONDS
            or monotonic_seconds - x["last_monotonic_seconds"] > MAX_HEARTBEAT_SECONDS):
        return "uncertain"
    if (now_seconds >= x["deadline_seconds"]
            or monotonic_seconds - x["started_monotonic_seconds"] >= DEADLINE_SECONDS
            or max(0, used_bytes - x["baseline_disk_used_bytes"]) >= ADDITIONAL_DISK_BYTES):
        return "stop"
    return "active"


def tick(value, *, telemetry, host_owner):
    """Watchdog tick; cancellation only for the frozen new Project/operation."""
    x = validate(value)
    decision = evaluate(x, **telemetry)
    if decision == "active":
        x["last_tick_seconds"] = telemetry["now_seconds"]
        x["last_monotonic_seconds"] = telemetry["monotonic_seconds"]
        x["last_disk_used_bytes"] = telemetry["used_bytes"]
        return x
    if x["status"] != "active":
        return x
    # Budget breach or uncertainty MUST request a project-bound cancellation.
    # An unsuccessful/unknown stop is permanently uncertain, not retried as
    # a different request or written as completed cleanup.
    try:
        receipt = host_owner.cancel_exact_project(
            x["project_root"], x["request_id"],
            reason="aggregate-budget-" + decision,
        )
        if not isinstance(receipt, dict) or receipt.get("confirmed") is not True:
            raise RuntimeError("cancellation not authenticated")
        x["stop_receipt"] = receipt
        x["status"] = "stopped" if decision == "stop" else "uncertain"
    except Exception:
        x["stop_receipt"] = None
        x["status"] = "uncertain"
    return x


def write_once(directory, value):
    """Install root-owned, non-link 0600 budget checkpoint before first mutation.

    This does not create the watchdog; the protected native owner must ensure
    a separate continuously scheduled/boot-reconciled watchdog is active.
    """
    if os.geteuid() != 0:
        raise PermissionError("budget registry requires privileged host owner")
    x = validate(value)
    root = Path(directory)
    st = root.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
            or stat.S_IMODE(st.st_mode) & 0o077):
        raise PermissionError("budget registry is not root-owned protected directory")
    name = x["request_id"] + ".json"
    path = root / name
    data = _canonical(x) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def read(directory, request_id):
    if not _HEX.fullmatch(request_id):
        raise ValueError("budget request ID invalid")
    root = Path(directory)
    root_stat = root.lstat()
    if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != 0
            or stat.S_IMODE(root_stat.st_mode) & 0o077):
        raise PermissionError("untrusted budget registry")
    fd = os.open(root / (request_id + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 8192):
            raise PermissionError("untrusted root budget checkpoint")
        data = os.read(fd, 8193)
    finally:
        os.close(fd)
    value = validate(json.loads(data))
    if value["request_id"] != request_id:
        raise ValueError("budget record substituted")
    return value


def attest_live(bound, guard, telemetry, *, root_owner_verified):
    """Mandatory native owner budget check on each fresh supervisor transition.

    The trusted native host-owner must verify root registry inode, active
    independently scheduled watchdog, boot activation and immutable quota
    before setting root_owner_verified. A dispatcher-supplied JSON 'true'
    must NEVER be interpreted as this result.
    """
    if root_owner_verified is not True:
        raise PermissionError("host-owned budget watchdog is not authenticated")
    owner = bound["compiler_execution_identity"]
    if (owner["schema"] != "host-deploy-compiler-execution-v3"
            or guard["request_id"] != bound["request_id"]
            or guard["project_root"] != bound["project_root"]
            or guard["host_id"] != bound["target"]["instance_id"]
            or guard["sidecar_plan_sha256"] != telemetry.get("sidecar_plan_sha256")
            or guard["monitor_receipt_sha256"] != telemetry.get(
                "monitor_receipt_sha256")):
        raise RuntimeError("new compiler request differs from native budget owner")
    selected = {key: telemetry[key] for key in (
        "host_id", "project_root", "boot_id", "now_seconds",
        "monotonic_seconds", "used_bytes", "monitor_receipt_sha256",
        "watchdog_active", "sidecar_active")}
    if evaluate(guard, **selected) != "active":
        raise RuntimeError("aggregate compiler budget exhausted or uncertain")
    return True


def _protected_root(directory):
    """Reject link redirects and writable parents for the host-owned journal."""
    root = Path(directory)
    if not root.is_absolute() or root == Path("/"):
        raise PermissionError("budget registry must be a dedicated absolute path")
    cursor = Path("/")
    for component in root.parts[1:]:
        cursor = cursor / component
        st = cursor.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            raise PermissionError("unsafe budget registry ancestry")
    if stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise PermissionError("budget registry must be private")
    return root


def watch_once(directory, request_id, *, native_owner):
    """Durably sample+cancel one operation under a root-only host-owned lock.

    native_owner.sample_exact must return counters from an independently
    installed host quota/clock/readback—not from an SSM/GitHub request.
    Caller must schedule this outside the compiler process and across boots.
    Cancellation failure remains uncertain and never triggers a new submit.
    """
    if os.geteuid() != 0 or not native_owner.is_trusted_native_owner():
        raise PermissionError("independent root-owned watchdog required")
    root = _protected_root(directory)
    lock_path = root / ".watchdog.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or stat.S_IMODE(st.st_mode) != 0o600):
            raise PermissionError("untrusted budget watchdog lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        before = read(root, request_id)
        telemetry = native_owner.sample_exact(before)
        after = tick(before, telemetry=telemetry, host_owner=native_owner)
        if after == before:
            return before
        # Root-only atomic replacement. Reject manual budget rollback by
        # verifying retained bytes again while the serialized lock is held.
        if read(root, request_id) != before:
            raise RuntimeError("concurrent or substituted aggregate budget")
        path = root / (request_id + ".json")
        temp = root / (".budget-" + uuid.uuid4().hex)
        tf = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        try:
            payload = _canonical(validate(after)) + b"\n"
            os.write(tf, payload)
            os.fsync(tf)
        finally:
            os.close(tf)
        try:
            os.replace(temp, path)
        finally:
            if temp.exists():
                temp.unlink()
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        return after
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
