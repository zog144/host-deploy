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
                or (kind == "canary" and (GRANT.exists() or GRANT.is_symlink()))):
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
        if kind == "compiler":
            prior_grant = owner._read_json(GRANT)
            prior_claim = owner._read_json(STATE / "fresh-canary-claim.json")
            if (prior_grant.get("kind") != "canary"
                    or prior_claim.get("job_id") != prior_grant.get("job_id")):
                raise RuntimeError("compiler cannot replace unconsumed canary grant")
        owner._store(GRANT, {
            "schema": GRANT_SCHEMA, "kind": kind,
            **_identity(owner, plan, admission),
            "job_id": intent["job_id"],
            "request_sha256": _digest(intent["request"]),
            "budget_scope": aggregate.BUDGET_SCOPE,
            "canary_receipt_sha256": canary_receipt,
        }, exclusive=(kind == "canary"))
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
        observed = native.worker_show(job)
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
                and owner.NativeOwner().worker_cgroup_populated(observed["ControlGroup"])):
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


def watch_allowed(*, fresh_owner, native, plan, admission, budget_record):
    """Called under the shared start lock by the protected budget watchdog.

    Idle is permitted only after a true empty kernel census and the durable
    correct phase. Claimed, missing workers have a ten-second maximum.
    The running phase still demands the complete live worker mount/FD proof.
    No caller-provided 'idle' or 'canary_verified' attribute is accepted.
    """
    from . import fresh_cold_start_policy as policy
    _identity(fresh_owner, plan, admission)
    if (budget_record.get("status") != "active"
            or budget_record.get("request_id") != admission["request_id"]):
        raise RuntimeError("watchdog budget no longer active")
    _timer(fresh_owner)
    state = fresh_owner._read_json(PHASE)
    if (state.get("schema") != PHASE_SCHEMA
            or any(state.get(k) != v for k,v in
                   _identity(fresh_owner, plan, admission).items())):
        raise RuntimeError("watchdog phase identity drift")
    phase = state.get("phase")
    if phase in ("armed-idle", "canary-clean-idle", "compiler-clean-idle"):
        evidence = native.verify_empty_storage(plan, admission)
        if evidence.get("status") != "verified-empty-lane-not-start-authority":
            raise RuntimeError("idle lacks native empty evidence")
        if state.get("pending_job") is not None:
            raise RuntimeError("idle still has a claimed worker")
        canary_ok = False
        if phase != "armed-idle":
            accepted = fresh_owner._read_json(CANARY_ACCEPTED)
            canary_ok = (accepted.get("status") == "native-canary-accepted"
                         and all(accepted.get(k) == v for k,v in
                                 _identity(fresh_owner, plan, admission).items()))
        decision = policy.classify(
            phase=phase, **{k: state[k] for k in (
                "host_id", "boot_id", "project_root", "request_id")},
            bound=state, worker_pids=[],
            controller_pid=evidence["controller_pid"],
            now_monotonic_ns=time.monotonic_ns(),
            budget_record=budget_record, deadline_observed=True,
            previous_canary_verified=canary_ok,
            all_jobs_clean=True)
        if decision["status"] != "native-idle-only":
            raise RuntimeError("idle phase not accepted")
        return decision
    if phase in ("canary-start-attempted", "compiler-start-attempted"):
        kind = phase.split("-", 1)[0]
        claim = fresh_owner._read_json(STATE / ("fresh-" + kind + "-claim.json"))
        if state.get("pending_job") != claim:
            raise RuntimeError("pending worker lacks exact durable one-shot claim")
        elapsed = time.monotonic_ns() - claim["attempt_monotonic_ns"]
        if elapsed < 0 or elapsed > policy.PENDING_SECONDS * 1_000_000_000:
            raise RuntimeError("worker absent beyond protected start allowance")
        # A process may have started before the first positive readback.
        # If live, require complete witness; if absent, require the full
        # pending-mode native kernel census and exact durable claim.
        try:
            return native.verify_live_storage(plan, admission)
        except RuntimeError as exc:
            if "no live finite worker available" not in str(exc):
                raise
        evidence = native.verify_pending_storage(plan, admission)
        decision = policy.classify(
            phase=phase, **{k: state[k] for k in (
                "host_id", "boot_id", "project_root", "request_id")},
            bound=state, worker_pids=[],
            controller_pid=evidence["controller_pid"],
            pending_job=claim, now_monotonic_ns=time.monotonic_ns(),
            budget_record=budget_record, deadline_observed=True,
            previous_canary_verified=(kind == "compiler" and
                fresh_owner._read_json(CANARY_ACCEPTED).get("status") ==
                "native-canary-accepted"))
        return decision
    if phase in ("canary-live", "compiler-live"):
        if state.get("pending_job") is not None:
            raise RuntimeError("live worker still has pending start claim")
        try:
            return native.verify_live_storage(plan, admission)
        except RuntimeError as exc:
            if phase != "canary-live" or (
                    "no live finite worker available" not in str(exc)):
                raise
        # A finite successful canary can exit before the next watchdog tick.
        # This is NOT authorized idle: require the exact already-persisted
        # terminal PID1 success, a fresh empty native census, and a STRICT
        # <=10-second cleanup handoff window, or cancel the whole fresh slice.
        terminal = fresh_owner._read_json(CANARY_TERMINAL)
        live = fresh_owner._read_json(CANARY_LIVE)
        delta = time.monotonic_ns() - terminal["terminal_monotonic_ns"]
        if (terminal.get("live_sha256") != _digest(live)
                or terminal.get("invocation_id") != live["invocation_id"]
                or not 0 <= delta <=
                    policy.PENDING_SECONDS * 1_000_000_000):
            raise RuntimeError("native canary terminal cleanup window expired")
        evidence = native.verify_pending_storage(plan, admission)
        return {"schema": PHASE_SCHEMA,
                "status": "terminal-cleanup-pending-not-idle",
                "controller_pid": evidence["controller_pid"],
                "compiler_admission": False}
    raise RuntimeError("unreviewed cold-start watchdog phase")
