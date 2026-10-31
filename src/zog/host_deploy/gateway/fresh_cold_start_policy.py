"""Fresh-only, non-authorizing cold-start and canary phase policy.

This does NOT activate PID1, create admission/grant records or permit workers.
Only a protected root owner may combine this pure policy with live native
cgroup, timer, budget, journal and root-control durable-job observations.

The crucial distinction: no process in the fresh slice is *not* in itself
proof of idle. The prior phase, immutable request/boot/Project identity,
outstanding launch attempt and the entire kernel PID census matter.
"""
from . import fresh_budget_guard as budget

SCHEMA = "host-deploy-fresh-cold-start-policy-v1"
PENDING_SECONDS = 10
PHASES = frozenset({
    "prearm-empty", "armed-idle", "canary-start-attempted",
    "canary-live", "canary-clean-idle", "compiler-start-attempted",
    "compiler-live", "compiler-clean-idle",
})
_ACTIVE = frozenset({"armed-idle", "canary-start-attempted",
                     "canary-live", "canary-clean-idle",
                     "compiler-start-attempted", "compiler-live",
                     "compiler-clean-idle"})
_PENDING = frozenset({"canary-start-attempted", "compiler-start-attempted"})
_LIVE = frozenset({"canary-live", "compiler-live"})
_IDLE = frozenset({"prearm-empty", "armed-idle", "canary-clean-idle",
                   "compiler-clean-idle"})


def classify(*, phase, host_id, boot_id, project_root, request_id,
             bound, worker_pids, controller_pid, pending_job=None,
             now_monotonic_ns, budget_record=None, deadline_observed=False,
             previous_canary_verified=False, all_jobs_clean=False):
    """Return a descriptive phase, NEVER a compiler/canary start grant.

    All inputs must originate from protected owner + live PID1 observation;
    calling this function on a JSON claim does not authorize anything.
    """
    if (phase not in PHASES or type(bound) is not dict
            or bound.get("host_id") != host_id
            or bound.get("boot_id") != boot_id
            or bound.get("project_root") != project_root
            or bound.get("request_id") != request_id
            or not all(type(x) is str and x for x in (
                host_id, boot_id, project_root, request_id))
            or type(now_monotonic_ns) is not int
            or now_monotonic_ns <= 0
            or type(controller_pid) is not int or controller_pid < 2
            or type(worker_pids) not in (list, tuple)
            or any(type(p) is not int or p < 2 or p == controller_pid
                   for p in worker_pids)
            or len(set(worker_pids)) != len(worker_pids)):
        raise RuntimeError("cold-start host/boot/Project/request or PID identity drift")
    if phase == "prearm-empty":
        if budget_record is not None or worker_pids or pending_job is not None:
            raise RuntimeError("prearm lane is not empty and unarmed")
        return {"schema": SCHEMA, "phase": phase, "status": "empty-prearm-only",
                "compiler_admission": False}
    if (type(budget_record) is not dict or deadline_observed is not True
            or budget_record.get("schema") != budget.SCHEMA
            or budget_record.get("host_id") != host_id
            or budget_record.get("boot_id") != boot_id
            or budget_record.get("project_root") != project_root
            or budget_record.get("request_id") != request_id
            or budget_record.get("status") != "active"
            or type(budget_record.get("started_monotonic_seconds")) is not int
            or now_monotonic_ns >= (
                budget_record["started_monotonic_seconds"]
                + budget.DEADLINE_SECONDS - 30) * 1_000_000_000):
        raise RuntimeError("cold-start has no current independent budget/deadline")
    if phase in _IDLE:
        if worker_pids or pending_job is not None:
            raise RuntimeError("authorized idle contains unclean worker or launch")
        if phase in ("canary-clean-idle", "compiler-clean-idle"):
            if previous_canary_verified is not True or all_jobs_clean is not True:
                raise RuntimeError("post-worker idle has no verified cleanup/canary")
        elif phase == "armed-idle" and previous_canary_verified:
            raise RuntimeError("pre-canary idle cannot claim prior canary")
        return {"schema": SCHEMA, "phase": phase, "status": "native-idle-only",
                "compiler_admission": False}
    if phase in _PENDING:
        if worker_pids or type(pending_job) is not dict:
            raise RuntimeError("launch-pending requires missing worker and exact attempt")
        if (pending_job.get("host_id") != host_id
                or pending_job.get("boot_id") != boot_id
                or pending_job.get("request_id") != request_id
                or pending_job.get("project_root") != project_root
                or pending_job.get("kind") != (
                    "canary" if phase == "canary-start-attempted" else "compiler")
                or type(pending_job.get("attempt_monotonic_ns")) is not int
                or not 0 <= now_monotonic_ns - pending_job["attempt_monotonic_ns"] <=
                    PENDING_SECONDS * 1_000_000_000):
            raise RuntimeError("worker missing after unapproved/expired launch attempt")
        if phase == "compiler-start-attempted" and not previous_canary_verified:
            raise RuntimeError("compiler start before canary acceptance")
        return {"schema": SCHEMA, "phase": phase,
                "status": "bounded-missing-worker-pending",
                "compiler_admission": False}
    if phase in _LIVE:
        if (not worker_pids or pending_job is not None
                or phase == "compiler-live" and not previous_canary_verified):
            raise RuntimeError("live phase has no attested worker/canary")
        # This pure check cannot prove mount/cgroup/FD containment. An actual
        # native witness MUST be read on every active worker transition.
        return {"schema": SCHEMA, "phase": phase,
                "status": "requires-current-kernel-worker-witness",
                "compiler_admission": False}
    raise RuntimeError("unhandled cold-start phase")
