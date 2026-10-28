"""Protected cold-start claim/phase tests; no real PID1 or native mutation."""
from contextlib import nullcontext
from types import SimpleNamespace
import time

import pytest

from zog.host_deploy.gateway import fresh_canary_owner as c
from zog.host_deploy.gateway import fresh_budget_guard as budget
from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate


BIND = {"host_id": "i-fresh", "boot_id": "fresh-boot",
        "project_root": "/home/zog-cross-owner/fresh-cross-bootstrap-oct25",
        "request_id": "a"*32, "plan_sha256": "sha256:"+"b"*64}
PLAN = {"host_id": BIND["host_id"], "sha256": BIND["plan_sha256"],
        "project_root": BIND["project_root"],
        "installed": {"boot_id": BIND["boot_id"],
                      "root_control_revision": c.REQUIRED_GATE_REVISION}}
ADMISSION = {"request_id": BIND["request_id"], "host_id": BIND["host_id"],
             "plan_sha256": BIND["plan_sha256"]}


def guard():
    now = int(time.monotonic())
    return budget.begin(
        request_id=BIND["request_id"], host_id=BIND["host_id"],
        project_root=BIND["project_root"], boot_id=BIND["boot_id"],
        now_seconds=100, monotonic_seconds=now-3, used_bytes=4096,
        sidecar_plan_sha256=BIND["plan_sha256"],
        monitor_receipt_sha256="sha256:"+"e"*64)


class Native:
    def verify_source_and_nss(self, plan):
        assert plan == PLAN
    def verify_empty_storage(self, plan, admission):
        return {"status": "verified-empty-lane-not-start-authority",
                "controller_pid": 400}
    def verify_pending_storage(self, plan, admission):
        return {"status": "verified-missing-pending-not-start-authority",
                "controller_pid": 400}
    def verify_live_storage(self, plan, admission):
        raise RuntimeError("no live finite worker available for native witness")


def setup(monkeypatch, *, phase="armed-idle", pending=None, accepted=None):
    records = {
        c.PHASE: {"schema": c.PHASE_SCHEMA, **BIND,
                  "phase": phase, "pending_job": pending,
                  "last_worker_job_id": None},
    }
    if accepted is not None:
        records[c.CANARY_ACCEPTED] = accepted
    host = SimpleNamespace(
        _root=lambda: None,
        _boot=lambda: BIND["boot_id"],
        _read_json=lambda p: records[p],
        _store=lambda p, obj, **kw: records.__setitem__(p, obj),
        _admission=lambda p: ADMISSION,
        PLAN_PATH=c.STATE/"reviewed-plan.json",
        BUDGET_DIR=c.STATE/"budget",
    )
    monkeypatch.setattr(c, "_timer", lambda owner: True)
    monkeypatch.setattr(c, "_budget", lambda *a: guard())
    monkeypatch.setattr(c, "locked", lambda owner: nullcontext())
    monkeypatch.setattr(c, "_identity", lambda *_: BIND.copy())
    return host, records


def test_armed_idle_requires_real_empty_census_and_cannot_grant_worker(monkeypatch):
    host, records = setup(monkeypatch)
    result = c.watch_allowed(fresh_owner=host, native=Native(),
                             plan=PLAN, admission=ADMISSION,
                             budget_record=guard())
    assert result["status"] == "native-idle-only"
    assert result["compiler_admission"] is False
    records[c.PHASE]["pending_job"] = {"forged": True}
    with pytest.raises(RuntimeError, match="still has"):
        c.watch_allowed(fresh_owner=host, native=Native(), plan=PLAN,
                        admission=ADMISSION, budget_record=guard())


def test_pending_worker_requires_claim_and_strict_ten_second_age(monkeypatch):
    pending = {**BIND, "schema": "root-control-fresh-worker-claim-v1",
               "kind": "canary", "job_id": "c"*32,
               "request_sha256": "sha256:"+"d"*64,
               "attempt_monotonic_ns": time.monotonic_ns()-1_000_000_000}
    host, records = setup(monkeypatch, phase="canary-start-attempted",
                          pending=pending)
    records[c.STATE/"fresh-canary-claim.json"] = pending
    result = c.watch_allowed(fresh_owner=host, native=Native(),
                             plan=PLAN, admission=ADMISSION,
                             budget_record=guard())
    assert result["status"] == "bounded-missing-worker-pending"
    assert result["compiler_admission"] is False
    pending["attempt_monotonic_ns"] -= 20_000_000_000
    with pytest.raises(RuntimeError, match="beyond"):
        c.watch_allowed(fresh_owner=host, native=Native(), plan=PLAN,
                        admission=ADMISSION, budget_record=guard())


def test_unaccepted_canary_cannot_make_compiler_idle(monkeypatch):
    host, _ = setup(monkeypatch, phase="canary-clean-idle")
    with pytest.raises(KeyError):
        c.watch_allowed(fresh_owner=host, native=Native(),
                        plan=PLAN, admission=ADMISSION, budget_record=guard())


def test_root_source_pin_checked_before_cold_arm():
    c.require_gate_source(PLAN)
    with pytest.raises(RuntimeError, match="installed reviewed"):
        c.require_gate_source({**PLAN, "installed":
                               {"root_control_revision": "old"}})


def test_prearm_phase_requires_budget_timer_and_empty_native_witness(
        monkeypatch):
    host, records = setup(monkeypatch)
    records.clear()
    monkeypatch.setattr(c.PHASE, "exists", lambda: False)
    monkeypatch.setattr(c.PHASE, "is_symlink", lambda: False)
    c.arm_empty(host, Native(), PLAN, ADMISSION)
    assert records[c.PHASE]["phase"] == "armed-idle"
    assert records[c.PHASE]["pending_job"] is None


def test_grant_does_not_take_job_command_from_rpc_or_start_pid1(monkeypatch):
    host, records = setup(monkeypatch)
    monkeypatch.setattr(c.GRANT, "exists", lambda: False)
    monkeypatch.setattr(c.GRANT, "is_symlink", lambda: False)
    intended = {**BIND, "schema": c.INTENT_SCHEMA, "kind": "canary",
                "job_id": "c"*32, "request": {"command":["/usr/bin/sleep","30"]}}
    monkeypatch.setattr(c, "_intent", lambda *args, **kw: intended)
    result = c.grant(host, Native(), kind="canary")
    assert result["status"] == "one-job-grant-only"
    assert result["no_pid1_mutation"]
    assert records[c.GRANT]["kind"] == "canary"
    assert records[c.GRANT]["budget_scope"] == aggregate.BUDGET_SCOPE
    assert records[c.GRANT]["request_sha256"] == c._digest(intended["request"])
