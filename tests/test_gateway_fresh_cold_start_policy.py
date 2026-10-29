"""No worker ≠ authorized idle: fail-closed phase logic and native veto."""
from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import fresh_budget_guard as budget
from zog.host_deploy.gateway import fresh_cold_start_policy as policy
from zog.host_deploy.gateway import fresh_native_storage_verifier as verifier


REQ = "a" * 32
BIND = {"host_id": "i-test", "boot_id": "boot-1",
        "project_root": "/fresh", "request_id": REQ}
NOW = 200 * 1_000_000_000
GUARD = {"schema": budget.SCHEMA, "status": "active",
         "host_id": "i-test", "boot_id": "boot-1",
         "project_root": "/fresh", "request_id": REQ,
         "started_monotonic_seconds": 190}


def classified(phase, **kwargs):
    params = {"phase": phase, **BIND, "bound": BIND,
              "worker_pids": [], "controller_pid": 400,
              "now_monotonic_ns": NOW, "budget_record": GUARD,
              "deadline_observed": True}
    params.update(kwargs)
    return policy.classify(**params)


def test_prearm_empty_is_only_observation_without_authority():
    v = classified("prearm-empty", budget_record=None,
                   deadline_observed=False)
    assert v["status"] == "empty-prearm-only"
    assert v["compiler_admission"] is False
    with pytest.raises(RuntimeError, match="not empty"):
        classified("prearm-empty", budget_record=None, worker_pids=[401])


def test_armed_empty_lane_is_legitimate_but_never_general_start_grant():
    v = classified("armed-idle")
    assert v["status"] == "native-idle-only"
    assert v["compiler_admission"] is False
    with pytest.raises(RuntimeError, match="unclean"):
        classified("armed-idle", worker_pids=[411])
    with pytest.raises(RuntimeError, match="unclean"):
        classified("armed-idle", pending_job={"untrusted": True})


@pytest.mark.parametrize("change", [
    {"host_id": "foreign"}, {"boot_id": "rebooted"},
    {"request_id": "b" * 32}, {"project_root": "/old"},
])
def test_stale_host_boot_project_request_never_authorizes_idle(change):
    with pytest.raises(RuntimeError, match="identity drift"):
        classified("armed-idle", **change)


def test_deadline_is_required_and_cannot_be_extended_by_idle():
    with pytest.raises(RuntimeError, match="budget/deadline"):
        classified("armed-idle", deadline_observed=False)
    with pytest.raises(RuntimeError, match="budget/deadline"):
        classified("armed-idle", budget_record={**GUARD, "status": "uncertain"})
    expiry = (190 + budget.DEADLINE_SECONDS - 30) * 1_000_000_000
    with pytest.raises(RuntimeError, match="budget/deadline"):
        classified("armed-idle", now_monotonic_ns=expiry)


def test_only_exact_short_pending_canary_is_distinct_from_missing_worker():
    attempt = {**BIND, "kind": "canary",
               "attempt_monotonic_ns": NOW - 2 * 1_000_000_000}
    v = classified("canary-start-attempted", pending_job=attempt)
    assert v["status"] == "bounded-missing-worker-pending"
    assert not v["compiler_admission"]
    with pytest.raises(RuntimeError, match="expired launch"):
        classified("canary-start-attempted",
                   pending_job={**attempt,
                                "attempt_monotonic_ns": NOW -
                                (policy.PENDING_SECONDS + 1)*1_000_000_000})
    with pytest.raises(RuntimeError, match="expired launch"):
        classified("canary-start-attempted",
                   pending_job={**attempt, "boot_id": "old"})
    with pytest.raises(RuntimeError, match="pending"):
        classified("canary-start-attempted",
                   worker_pids=[401], pending_job=attempt)


def test_compiler_launch_requires_prior_attested_canary():
    attempted = {**BIND, "kind": "compiler", "attempt_monotonic_ns": NOW}
    with pytest.raises(RuntimeError, match="before canary"):
        classified("compiler-start-attempted", pending_job=attempted)
    result = classified("compiler-start-attempted", pending_job=attempted,
                        previous_canary_verified=True)
    assert result["compiler_admission"] is False
    with pytest.raises(RuntimeError, match="no verified cleanup"):
        classified("compiler-clean-idle", previous_canary_verified=True)
    ok = classified("compiler-clean-idle", previous_canary_verified=True,
                    all_jobs_clean=True)
    assert ok["status"] == "native-idle-only"


def test_live_phase_demands_worker_and_only_returns_non_authorizing_policy():
    with pytest.raises(RuntimeError, match="no attested worker"):
        classified("canary-live")
    v = classified("canary-live", worker_pids=[411])
    assert v["status"] == "requires-current-kernel-worker-witness"
    assert v["compiler_admission"] is False


def test_root_control_attempted_worker_prevents_empty_kernel_witness(
        tmp_path, monkeypatch):
    import hashlib
    root = tmp_path / "work" / "controller-build-resources"
    project = tmp_path / "reviewed-project"
    monkeypatch.setattr(verifier.project_state, "PROJECT_ROOT", project)
    resource_id, job_id = "b" * 32, "c" * 32
    area = root / hashlib.sha256(str(project).encode()).hexdigest()
    jobs = area / resource_id / "jobs"
    jobs.mkdir(parents=True)
    item = jobs / (job_id + ".json")
    record = {"job_id": job_id,
              "request": {"build_root_id": resource_id},
              "parent_slice": verifier.sidecar.SLICE_UNIT,
              "log_namespace": verifier.sidecar.LOG_NAMESPACE,
              "unit_name": f"zog-{verifier.sidecar.PROJECT}-build{job_id}.service",
              "slice_name": (verifier.sidecar.SLICE_UNIT.removesuffix(".slice") +
                             f"-build{job_id}.slice"),
              "start_attempted": True, "process_cleanup_complete": False}
    item.write_text(json.dumps(record))
    monkeypatch.setattr(verifier.quota, "MOUNT", root.parent)
    device = root.stat().st_dev
    with pytest.raises(RuntimeError, match="missing without cleanup"):
        verifier._assert_no_unclean_starts(device)
    record["process_cleanup_complete"] = True
    item.write_text(json.dumps(record))
    verifier._assert_no_unclean_starts(device)
    item.unlink()
    item.symlink_to(tmp_path / "foreign")
    with pytest.raises(RuntimeError, match="invalid registered"):
        verifier._assert_no_unclean_starts(device)


def test_empty_witness_remains_separate_from_live_witness():
    assert verifier.inspect_empty is not verifier.inspect_live
    import inspect
    s = inspect.getsource(verifier._inspect_native)
    assert 'mode in ("empty", "pending") and workers' in s
    assert "_assert_no_unclean_starts(device)" in s
    assert "first != _processes()" in s
    assert "unaccounted_writable_roots=[]" not in inspect.getsource(
        verifier._inspect_native)  # never silently clear the inventory
