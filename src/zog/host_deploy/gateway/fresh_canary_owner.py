"""Root-owned fixed canary/worker grant and phase evidence (fresh only).

There is no remote RPC, arbitrary command, or automatic compiler admission.
The operator-installed reviewed-<kind>-intent.json must have exact immutable
job identity. The fresh root-control sidecar independently consumes the
grant under a shared native lock before committing a PID1 start attempt.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from contextlib import contextmanager

from . import fresh_aggregate_disk as aggregate
from . import fresh_budget_guard as budget
from . import fresh_quota_volume as quota

STATE = Path(aggregate.EXTERNAL_MOUNT) / "owner-state"
LOCK = STATE / "fresh-start.lock"
PHASE = STATE / "fresh-start-phase.json"
GRANT = STATE / "fresh-start-grant.json"
CANARY_INTENT = STATE / "reviewed-canary-intent.json"
COMPILER_INTENT = STATE / "reviewed-compiler-intent.json"
CANARY_LIVE = STATE / "canary-live-witness.json"
CANARY_TERMINAL = STATE / "canary-terminal.json"
CANARY_ACCEPTED = STATE / "canary-accepted.json"
GRANT_SCHEMA = "host-deploy-fresh-start-grant-v1"
PHASE_SCHEMA = "host-deploy-fresh-start-phase-v1"
INTENT_SCHEMA = "host-deploy-fresh-reviewed-worker-intent-v1"
_HEX = re.compile(r"[0-9a-f]{32}\Z")


def _digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")).hexdigest()


@contextmanager
def locked(owner):
    owner._root()
    budget._protected_root(STATE)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise PermissionError("untrusted fresh start lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _identity(owner, plan, admission):
    if (owner._boot() != plan["installed"]["boot_id"]
            or plan["host_id"] != admission["host_id"]
            or admission["plan_sha256"] != plan["sha256"]):
        raise RuntimeError("cold-start grant host/boot/plan changed")
    return {"host_id": admission["host_id"],
            "boot_id": owner._boot(),
            "project_root": plan["project_root"],
            "request_id": admission["request_id"],
            "plan_sha256": plan["sha256"]}


def _timer(owner):
    observed = owner._show(owner.hard_deadline.UNIT)
    if (observed.get("LoadState") != "loaded"
            or observed.get("ActiveState") != "active"
            or observed.get("Unit") != owner.hard_deadline.STOP_UNIT
            or not observed.get("NextElapseUSecMonotonic", "").isdigit()
            or int(observed["NextElapseUSecMonotonic"]) <=
                time.monotonic_ns() // 1000):
        raise RuntimeError("cold-start deadline absent or expired")
    return observed


def _budget(owner, admission, plan):
    x = budget.read(owner.BUDGET_DIR, admission["request_id"])
    if (x["status"] != "active"
            or any(x[k] != v for k,v in {
                "request_id": admission["request_id"],
                "host_id": admission["host_id"],
                "project_root": plan["project_root"],
                "boot_id": owner._boot(),
                "sidecar_plan_sha256": plan["sha256"],
            }.items())
            or int(time.monotonic()) >= x["started_monotonic_seconds"]
                + budget.DEADLINE_SECONDS - owner.hard_deadline.MARGIN_SECONDS):
        raise RuntimeError("cold-start protected budget not active")
    return x


def arm_empty(owner, native, plan, admission):
    """Only after PID1 deadline + budget fsync; never starts a canary."""
    _identity(owner, plan, admission)
    _budget(owner, admission, plan)
    _timer(owner)
    native.verify_empty_storage(plan, admission)
    with locked(owner):
        if PHASE.exists() or PHASE.is_symlink():
            raise RuntimeError("cold-start phase has already been established")
        owner._store(PHASE, {
            "schema": PHASE_SCHEMA, **_identity(owner, plan, admission),
            "phase": "armed-idle", "pending_job": None,
            "last_worker_job_id": None,
        }, exclusive=True)


def _intent(owner, path, *, kind, plan, admission):
    value = owner._read_json(path)
    if (type(value) is not dict
            or set(value) != {"schema","kind","host_id","boot_id",
                  "project_root","request_id","plan_sha256","job_id","request"}
            or value["schema"] != INTENT_SCHEMA
            or value["kind"] != kind
            or any(value.get(k) != v for k,v in
                   _identity(owner, plan, admission).items())
            or type(value["job_id"]) is not str
            or not _HEX.fullmatch(value["job_id"])
            or type(value["request"]) is not dict):
        raise RuntimeError("reviewed worker intent changed")
    request = value["request"]
    root_id = request.get("build_root_id")
    if (type(root_id) is not str or not _HEX.fullmatch(root_id)
            or request.get("execution_user_id") != plan["identity"]["build_uid"]
            or request.get("execution_group_id") != plan["identity"]["build_gid"]
            or request.get("read_only_root") is not True
            or request.get("network_access") is not False
            or request.get("execution_timeout_seconds", 999999) > (
                45 if kind == "canary" else budget.DEADLINE_SECONDS)
            or not 1 <= request.get("startup_timeout_seconds", 100) <= 10):
        raise RuntimeError("worker intent violates fixed identity/runtime bounds")
    if kind == "canary":
        if (request.get("command") != ["/usr/bin/sleep", "30"]
                or request.get("working_directory") != "/"
                or request.get("environment") != {"PATH": "/usr/bin:/bin"}
                or request.get("execution_timeout_seconds") != 40
                or request.get("termination_grace_seconds") != 3
                or request.get("resource_limits") != {
                    "thread-count-maximum": 16,
                    "memory-maximum-bytes": 128 * 1024 * 1024}):
            raise RuntimeError("canary executable/resource policy differs")
    return value


def grant(owner, native, *, kind):
    """Consume separately operator-reviewed intent; NO remote job selection."""
    owner._root()
    plan = owner._read_json(owner.PLAN_PATH)
    admission = owner._admission(plan)
    native.verify_source_and_nss(plan)
    path = CANARY_INTENT if kind == "canary" else COMPILER_INTENT
    if kind not in ("canary", "compiler"):
        raise RuntimeError("unsupported start kind")
    with locked(owner):
        _timer(owner)
        _budget(owner, admission, plan)
        state = owner._read_json(PHASE)
        expected = "armed-idle" if kind == "canary" else "canary-clean-idle"
        if (state.get("schema") != PHASE_SCHEMA
                or state.get("phase") != expected
                or any(state.get(k) != v for k,v in
                       _identity(owner, plan, admission).items())
                or state.get("pending_job") is not None
                or GRANT.exists() or GRANT.is_symlink()):
            raise RuntimeError("start grant already attempted or lane not idle")
        native.verify_empty_storage(plan, admission)
        canary_receipt = None
        if kind == "compiler":
            prior = owner._read_json(CANARY_ACCEPTED)
            if (prior.get("status") != "native-canary-accepted"
                    or any(prior.get(k) != v for k,v in
                           _identity(owner, plan, admission).items())):
                raise RuntimeError("compiler lacks verified same-boot canary")
            canary_receipt = _digest(prior)
        intent = _intent(owner, path, kind=kind, plan=plan, admission=admission)
        owner._store(GRANT, {
            "schema": GRANT_SCHEMA, "kind": kind,
            **_identity(owner, plan, admission),
            "job_id": intent["job_id"],
            "request_sha256": _digest(intent["request"]),
            "budget_scope": aggregate.BUDGET_SCOPE,
            "canary_receipt_sha256": canary_receipt,
        }, exclusive=True)
        return {"status": "one-job-grant-only", "kind": kind,
                "job_id": intent["job_id"], "no_pid1_mutation": True}


def observe_live(owner, native):
    """Durably capture actual canary worker and fixed systemd invocation."""
    owner._root()
    plan = owner._read_json(owner.PLAN_PATH)
    a = owner._admission(plan)
    with locked(owner):
        _timer(owner)
        _budget(owner, a, plan)
        state = owner._read_json(PHASE)
        claim = owner._read_json(STATE / "fresh-canary-claim.json")
        intent = _intent(owner, CANARY_INTENT, kind="canary",
                         plan=plan, admission=a)
        if (state.get("phase") != "canary-start-attempted"
                or state.get("pending_job") != claim
                or claim.get("job_id") != intent["job_id"]
                or CANARY_LIVE.exists()):
            raise RuntimeError("canary is not exact unobserved start attempt")
        evidence = native.verify_live_storage(plan, a)
        job = intent["job_id"]
        unit = ("zog-" + plan["project_root"].split("/")[-1]
                + "-build" + job + ".service")
        observed = owner._worker_show(unit, job)
        if (observed.get("ActiveState") != "active"
                or not observed.get("InvocationID")
                or not observed.get("MainPID", "").isdigit()
                or int(observed["MainPID"]) not in
                    [w["pid"] for w in evidence["workers"]]):
            raise RuntimeError("canary PID1 invocation not live in native witness")
        receipt = {**_identity(owner, plan, a), "schema":
                   "host-deploy-fresh-canary-live-v1",
                   "job_id": job, "unit": unit,
                   "invocation_id": observed["InvocationID"],
                   "worker_pid": int(observed["MainPID"]),
                   "worker_evidence_sha256": _digest(evidence),
                   "seen_monotonic_ns": time.monotonic_ns()}
        owner._store(CANARY_LIVE, receipt, exclusive=True)
        owner._store(PHASE, {**state, "phase": "canary-live",
                             "pending_job": None}, exclusive=False)
        return receipt


def observe_terminal(owner):
    """Read PID1 exit evidence before root-control releases the unit."""
    owner._root()
    plan = owner._read_json(owner.PLAN_PATH)
    a = owner._admission(plan)
    with locked(owner):
        _budget(owner, a, plan)
        live = owner._read_json(CANARY_LIVE)
        state = owner._read_json(PHASE)
        if (state.get("phase") != "canary-live"
                or CANARY_TERMINAL.exists()
                or live.get("boot_id") != owner._boot()):
            raise RuntimeError("canary exit cannot be attested")
        observed = owner._worker_show(live["unit"], live["job_id"])
        if (observed.get("ActiveState") not in ("inactive", "failed")
                or observed.get("InvocationID") != live["invocation_id"]
                or observed.get("ExecMainCode") != "1"
                or observed.get("ExecMainStatus") != "0"
                or observed.get("ControlGroup") not in ("", "n/a")
                and owner._worker_cgroup_populated(observed["ControlGroup"])):
            raise RuntimeError("finite canary did not exit cleanly")
        record = {**_identity(owner, plan, a),
                  "schema": "host-deploy-fresh-canary-terminal-v1",
                  "invocation_id": live["invocation_id"],
                  "job_id": live["job_id"],
                  "live_sha256": _digest(live),
                  "terminal_monotonic_ns": time.monotonic_ns()}
        owner._store(CANARY_TERMINAL, record, exclusive=True)
        return record


def accept_canary(owner, native):
    """Accept only after separate root-control unit cleanup and empty census."""
    owner._root()
    plan = owner._read_json(owner.PLAN_PATH)
    a = owner._admission(plan)
    with locked(owner):
        _timer(owner)
        _budget(owner, a, plan)
        live = owner._read_json(CANARY_LIVE)
        terminal = owner._read_json(CANARY_TERMINAL)
        state = owner._read_json(PHASE)
        if (state.get("phase") != "canary-live"
                or CANARY_ACCEPTED.exists()
                or terminal.get("live_sha256") != _digest(live)
                or terminal.get("invocation_id") != live["invocation_id"]):
            raise RuntimeError("canary acceptance not supported by native exit")
        native.verify_empty_storage(plan, a)
        receipt = {**_identity(owner, plan, a),
                   "schema": "host-deploy-fresh-canary-accepted-v1",
                   "status": "native-canary-accepted",
                   "live_sha256": _digest(live),
                   "terminal_sha256": _digest(terminal)}
        owner._store(CANARY_ACCEPTED, receipt, exclusive=True)
        owner._store(PHASE, {**state, "phase": "canary-clean-idle",
                             "pending_job": None}, exclusive=False)
        return receipt
