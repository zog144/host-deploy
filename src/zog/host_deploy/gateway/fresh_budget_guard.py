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
        "status": "active", "stop_reason": None, "stop_receipt": None,
        "cancellation_id": _digest({"schema": SCHEMA, "request_id": request_id,
                                    "host_id": host_id, "project_root": project_root}),
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
            or value["status"] not in ("active", "stop_requested", "stop_attempted", "stopped", "uncertain")
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
    if (value["cancellation_id"] != _digest({
            "schema": SCHEMA, "request_id": value["request_id"],
            "host_id": value["host_id"],
            "project_root": value["project_root"]})
            or (value["status"] == "active" and (
                value["stop_reason"] is not None or value["stop_receipt"] is not None))
            or (value["status"] != "active" and value["stop_reason"] not in (
                "aggregate-budget-stop", "aggregate-budget-uncertain"))
            or (value["status"] in ("stop_requested", "stop_attempted", "uncertain")
                and value["stop_receipt"] is not None)
            or (value["status"] == "stopped" and (
                type(value["stop_receipt"]) is not dict
                or value["stop_receipt"].get("confirmed") is not True
                or value["stop_receipt"].get("cancellation_id") !=
                    value["cancellation_id"]))):
        raise ValueError("budget stop intent/receipt is not authenticated")
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


def tick(value, *, telemetry, host_owner=None):
    """Pure transition only; NEVER call cancellation before fsync of intent.

    The real host watchdog owns subsequent attempted-start and the single
    cancellation mutation. Old callers may pass host_owner, but it is
    deliberately not used: no unjournaled cancellation is permitted.
    """
    x = validate(value)
    if x["status"] != "active":
        return x
    decision = evaluate(x, **telemetry)
    if decision == "active":
        x["last_tick_seconds"] = telemetry["now_seconds"]
        x["last_monotonic_seconds"] = telemetry["monotonic_seconds"]
        x["last_disk_used_bytes"] = telemetry["used_bytes"]
    else:
        x["status"] = "stop_requested"
        x["stop_reason"] = "aggregate-budget-" + decision
    return validate(x)


def write_once(directory, value):
    """Install root-owned, non-link 0600 budget checkpoint before first mutation.

    This does not create the watchdog; the protected native owner must ensure
    a separate continuously scheduled/boot-reconciled watchdog is active.
    """
    if os.geteuid() != 0:
        raise PermissionError("budget registry requires privileged host owner")
    x = validate(value)
    root = _protected_root(directory)
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
    root = _protected_root(directory)
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


def _commit(root, request_id, before, after):
    """Atomic root-owned replacement under the caller's exclusive lock."""
    if read(root, request_id) != before:
        raise RuntimeError("concurrent or substituted aggregate budget")
    path = root / (request_id + ".json")
    temp = root / (".budget-" + uuid.uuid4().hex)
    tf = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        payload = _canonical(validate(after)) + b"\n"
        if os.write(tf, payload) != len(payload):
            raise OSError("short protected budget write")
        os.fsync(tf)
    finally:
        os.close(tf)
    try:
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    return after


def _confirmed_receipt(receipt, x):
    return (type(receipt) is dict
            and receipt.get("confirmed") is True
            and receipt.get("cancellation_id") == x["cancellation_id"]
            and receipt.get("request_id") == x["request_id"]
            and receipt.get("project_root") == x["project_root"])


def watch_once(directory, request_id, *, native_owner):
    """Crash-safe one-attempt cancellation; recover only via read-only inspect.

    Freeze stop_requested before any side effect and stop_attempted before
    invoking the host owner's exact new-Project cancellation. On restart
    after an attempted request, never issue another cancel: inspect only
    the original immutable cancellation_id. Unknown result remains blocked.
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
        state = read(root, request_id)
        if state["status"] == "active":
            telemetry = native_owner.sample_exact(state)
            next_state = tick(state, telemetry=telemetry)
            if next_state != state:
                next_state = _commit(root, request_id, state, next_state)
            state = next_state
        if state["status"] == "stop_requested":
            attempted = dict(state, status="stop_attempted")
            # The attempt is fsync-durable BEFORE external cancellation.
            state = _commit(root, request_id, state, attempted)
            try:
                receipt = native_owner.cancel_exact_project(
                    state["project_root"], state["request_id"],
                    reason=state["stop_reason"],
                    cancellation_id=state["cancellation_id"],
                )
            except BaseException:
                # External mutation may have succeeded. NEVER resubmit it.
                raise
            if _confirmed_receipt(receipt, state):
                next_state = dict(state, status="stopped", stop_receipt=receipt)
                return _commit(root, request_id, state, next_state)
            # Unverified ack must remain stop_attempted, recover by inspect.
            return state
        if state["status"] == "stop_attempted":
            # On replay this is read-only; never call cancel_exact_project.
            try:
                receipt = native_owner.inspect_cancel_exact_project(
                    state["project_root"], state["request_id"],
                    cancellation_id=state["cancellation_id"],
                )
            except Exception:
                return state
            if _confirmed_receipt(receipt, state):
                return _commit(root, request_id, state, dict(
                    state, status="stopped", stop_receipt=receipt))
        return state
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
