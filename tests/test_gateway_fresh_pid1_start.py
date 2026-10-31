"""No PID1/EC2 mutation. Exercise actual dbus-next job signals and timeouts."""
import asyncio
from types import SimpleNamespace
import pytest
from dbus_next import Message, MessageType

from zog.host_deploy.gateway import fresh_pid1_job as jobs
from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_watchdog_service as wd


UNIT = wd.UNIT
JOB = "/org/freedesktop/systemd1/job/42"


def reply(signature="", body=None):
    return Message(message_type=MessageType.METHOD_RETURN,
                   reply_serial=1, signature=signature, body=body or [])


class Bus:
    def __init__(self, *, result="done", event="before", fail_reply=False):
        self.handler = None
        self.calls = []
        self.result, self.event = result, event
        self.fail_reply = fail_reply

    def add_message_handler(self, h):
        self.handler = h

    def remove_message_handler(self, h):
        assert self.handler is h
        self.handler = None

    def signal(self):
        self.handler(Message(
            path="/org/freedesktop/systemd1",
            interface="org.freedesktop.systemd1.Manager",
            member="JobRemoved", message_type=MessageType.SIGNAL,
            signature="uoss", body=[42, JOB, UNIT, self.result],
            sender=":1.1"))

    async def call(self, msg):
        self.calls.append(msg.member)
        if msg.member == "GetNameOwner":
            return reply(signature="s", body=[":1.1"])
        if msg.member == "StartTransientUnit":
            if self.fail_reply:
                raise TimeoutError("lost reply")
            if self.event == "before":
                self.signal()
            elif self.event == "after":
                asyncio.get_running_loop().call_soon(self.signal)
            return reply(signature="o", body=[JOB])
        return reply()


@pytest.mark.parametrize("event", ["before", "after"])
def test_early_or_late_pid1_job_removed_is_correlated(event):
    bus = Bus(event=event)
    acks = []
    result = asyncio.run(jobs.start_and_wait(
        bus, Message(path="/org/freedesktop/systemd1",
                     interface="org.freedesktop.systemd1.Manager",
                     member="StartTransientUnit"),
        UNIT, timeout=2, on_ack=lambda job: acks.append(job)))
    assert result["job_result"] == "done"
    assert result["job_path"] == JOB
    assert acks == [JOB]
    assert bus.calls == ["AddMatch", "GetNameOwner", "Subscribe", "StartTransientUnit"]


def test_explicit_failed_job_rejected_but_ack_persisted():
    bus = Bus(result="failed")
    acks = []
    with pytest.raises(jobs.JobNotProven, match="failed-result-failed"):
        asyncio.run(jobs.start_and_wait(
            bus, Message(path="/org/freedesktop/systemd1",
                         member="StartTransientUnit"), UNIT,
            timeout=2, on_ack=lambda path: acks.append(path)))
    assert acks == [JOB]


def test_missing_job_removed_is_bounded_and_never_restarted():
    bus = Bus(event="missing")
    with pytest.raises(jobs.JobNotProven, match="completion-timeout"):
        asyncio.run(jobs.start_and_wait(
            bus, Message(path="/org/freedesktop/systemd1",
                         member="StartTransientUnit"), UNIT, timeout=0.025))
    assert bus.calls.count("StartTransientUnit") == 1


def test_lost_method_reply_does_not_retry():
    class Lost(Bus):
        async def call(self, msg):
            if msg.member == "StartTransientUnit":
                self.calls.append(msg.member)
                await asyncio.sleep(10)
            return await super().call(msg)
    bus = Lost()
    with pytest.raises(jobs.JobNotProven, match="method-timeout"):
        asyncio.run(jobs.start_and_wait(
            bus, Message(path="/org/freedesktop/systemd1",
                         member="StartTransientUnit"), UNIT, timeout=0.025))
    assert bus.calls.count("StartTransientUnit") == 1


def test_sidecar_readiness_requires_three_full_stable_witnesses(monkeypatch):
    plan = {"identity": {}, "installed": {}}
    monkeypatch.setattr(owner, "_read_json", lambda _: plan)
    monkeypatch.setattr(owner.sidecar, "review_plan", lambda *_: plan)
    evidence = {"MainPID": "41", "InvocationID": "a"*32,
                "ActiveState": "active"}
    observed = [None, evidence, evidence, evidence]
    def probe(_, *, deadline):
        item = observed.pop(0)
        if item is None:
            raise RuntimeError("sidecar not listening yet")
        return item
    monkeypatch.setattr(owner, "_sidecar_pid1_evidence", probe)
    monkeypatch.setattr(owner.time, "sleep", lambda _: None)
    got = owner._wait_exact_sidecar_readiness(object(), owner.sidecar.UNIT)
    assert got == evidence
    assert observed == []


def test_watchdog_wait_requires_three_full_stable_readbacks(monkeypatch):
    evidence = {"MainPID": "42", "InvocationID": "a"*32}
    observed = [None, evidence, evidence, evidence]
    def probe(_, *, deadline):
        item = observed.pop(0)
        if item is None:
            raise RuntimeError("still activating")
        return item
    monkeypatch.setattr(owner, "_watchdog_pid1_evidence", probe)
    monkeypatch.setattr(owner.time, "sleep", lambda _: None)
    assert owner._wait_exact_watchdog({}) == evidence
    assert observed == []


def test_watchdog_expired_readiness_stays_no_go(monkeypatch):
    monkeypatch.setattr(owner, "_watchdog_pid1_evidence",
                        lambda _, *, deadline: (_ for _ in ()).throw(
                            RuntimeError("unready")))
    initial = owner.time.monotonic()
    monotonic = iter([initial, initial+30])
    monkeypatch.setattr(owner.time, "monotonic",
                        lambda: next(monotonic, initial+30))
    with pytest.raises(RuntimeError, match="activation unproven"):
        owner._wait_exact_watchdog({})


def test_reconciliation_never_calls_start_or_removes_marker(monkeypatch):
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "_read_json", lambda p: {
        "schema": "unknown", "sha256": "sha256:"+"a"*64})
    invoked = []
    monkeypatch.setattr(owner.sidecar, "review_plan",
                        lambda *args: None)
    monkeypatch.setattr(owner.independent_watchdog, "start",
                        lambda *args, **kwargs: invoked.append("start"))
    with pytest.raises((RuntimeError, KeyError)):
        owner.reconcile_install_approved()
    assert invoked == []


def test_reconcile_approval_and_no_repeat_watchdog_start_in_source():
    import inspect
    s = inspect.getsource(owner.reconcile_install_approved)
    assert "_read_json(WATCHDOG_RECONCILE_APPROVAL)" in s
    assert "WATCHDOG_RECONCILED" in s
    assert "sidecar.install(plan, host_owner=owner)" in s
    assert "independent_watchdog.start" not in s
    assert "allow_continue_original" in s
    assert "_store(WATCHDOG_RECONCILED" in s
    assert s.index("_store(WATCHDOG_RECONCILED") < s.index("sidecar.install(")


def test_foreign_signal_cannot_fake_PID1_completion():
    class WrongSender(Bus):
        def signal(self):
            self.handler(Message(
                path="/org/freedesktop/systemd1",
                interface="org.freedesktop.systemd1.Manager",
                member="JobRemoved", message_type=MessageType.SIGNAL,
                signature="uoss", body=[42, JOB, UNIT, "done"],
                sender=":1.999"))
    bus = WrongSender(event="before")
    with pytest.raises(jobs.JobNotProven, match="completion-timeout"):
        asyncio.run(jobs.start_and_wait(
            bus, Message(path="/org/freedesktop/systemd1",
                         member="StartTransientUnit"), UNIT, timeout=0.02))
    assert bus.calls.count("StartTransientUnit") == 1


def test_one_shot_selected_reconcile_no_watchdog_restart(tmp_path, monkeypatch):
    """Exact root-approved original job may advance once to sidecar, never twice."""
    state = tmp_path / "owner-state"
    state.mkdir(mode=0o700)
    plan = {"sha256": "sha256:"+"a"*64, "host_id": "fresh-host",
            "identity": {"controller_uid": 24301},
            "installed": {"legacy_baseline_sha256": "sha256:"+"b"*64,
                          "watchdog_receipt_sha256": owner._sha(b"cron")}}
    readback = {
        "schema": "host-deploy-fresh-watchdog-reconciliation-review-v1",
        "host_id": "fresh-host", "boot_id": "fresh-boot",
        "plan_sha256": plan["sha256"],
        "attempt_sha256": "sha256:"+"c"*64,
        "job_path": JOB, "job_record_sha256": "sha256:"+"d"*64,
        "evidence": {"InvocationID": "e"*32, "MainPID": "42"},
        "evidence_sha256": "sha256:"+"f"*64,
        "status": "original-attempt-readback-only", "compiler_authorized": False,
    }
    approved = {
        "schema": "host-deploy-fresh-watchdog-reconcile-approval-v1",
        "status": "operator-approved", "allow_continue_original": True,
        "host_id": readback["host_id"], "boot_id": readback["boot_id"],
        "plan_sha256": readback["plan_sha256"],
        "attempt_sha256": readback["attempt_sha256"],
        "job_path": readback["job_path"],
        "job_record_sha256": readback["job_record_sha256"],
        "invocation_id": readback["evidence"]["InvocationID"],
        "main_pid": readback["evidence"]["MainPID"],
        "evidence_sha256": readback["evidence_sha256"],
    }
    monkeypatch.setattr(owner, "STATE", state)
    monkeypatch.setattr(owner, "PLAN_PATH", state / "plan.json")
    monkeypatch.setattr(owner, "INSTALL_PATH", state / "sidecar-install.json")
    monkeypatch.setattr(owner, "WATCHDOG_RECONCILED", state / "reconciled.json")
    monkeypatch.setattr(owner, "WATCHDOG_RECONCILE_APPROVAL", state / "approval.json")
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "_boot", lambda: "fresh-boot")
    monkeypatch.setattr(owner, "_read_json", lambda path:
                        approved if path == owner.WATCHDOG_RECONCILE_APPROVAL
                        else plan)
    monkeypatch.setattr(owner, "_file", lambda path: b"protected-approval")
    monkeypatch.setattr(owner, "_budget_directory_prepared",
                        lambda *, require_empty: True)
    monkeypatch.setattr(owner, "schedule_text", lambda: "cron")
    monkeypatch.setattr(owner, "verify_schedule", lambda: True)
    monkeypatch.setattr(owner, "inspect_watchdog_attempt", lambda: readback)
    monkeypatch.setattr(owner.sidecar, "review_plan", lambda *args: plan)
    monkeypatch.setattr(owner.quota, "inspect",
                        lambda: {"capacity_bytes": owner.aggregate.BUILD_BYTES})
    monkeypatch.setattr(owner.project_state, "inspect", lambda uid: True)
    monkeypatch.setattr(owner.aggregate, "inspect_external_native", lambda: {})
    monkeypatch.setattr(owner.aggregate, "validate_pre_activation", lambda *a,**kw: True)
    monkeypatch.setattr(owner.os, "chown", lambda *a: None)
    monkeypatch.setattr(owner.os, "chmod", lambda *a: None)
    class Native:
        def verify_source_and_nss(self, plan): pass
        def validate_old_baseline(self, digest): pass
        def is_trusted_native_owner(self): return True
        def read_unit(self, unit): return None
        def socket_exists(self, path): return False
    monkeypatch.setattr(owner, "NativeOwner", Native)
    calls = []
    def record(path, item, *, exclusive):
        calls.append((path, item))
        if path == owner.WATCHDOG_RECONCILED:
            assert exclusive
            path.write_bytes(owner._bytes(item))
    monkeypatch.setattr(owner, "_store", record)
    def sidecar_installer(plan, *, host_owner):
        calls.append(("sidecar", plan))
        return {"plan_sha256": plan["sha256"], "invocation_id": "new-only"}
    monkeypatch.setattr(owner.sidecar, "install", sidecar_installer)
    monkeypatch.setattr(owner.independent_watchdog, "start", lambda *args, **kw:
                        pytest.fail("reconciliation cannot start watchdog again"))
    got = owner.reconcile_install_approved()
    assert got["invocation_id"] == "new-only"
    assert calls[0][0] == owner.WATCHDOG_RECONCILED
    assert calls[1][0] == "sidecar"
    with pytest.raises(RuntimeError, match="prior sidecar installation"):
        owner.reconcile_install_approved()
    assert [x for x in calls if x[0] == "sidecar"] == [("sidecar", plan)]


def test_wrong_approval_does_not_write_or_start(monkeypatch, tmp_path):
    # Explicit original-attempt approval must bind actual MainPID, not merely
    # the right Host and plan. Guard this branch in the full fixture above.
    import inspect
    source = inspect.getsource(owner.reconcile_install_approved)
    assert 'if approved != expected:' in source
    assert '"main_pid": review["evidence"]["MainPID"]' in source
    assert '"evidence_sha256": review["evidence_sha256"]' in source
    assert 'if inspect_watchdog_attempt() != review:' in source


@pytest.mark.parametrize("field,value", [
    ("ActiveState", "activating"), ("NRestarts", "1"),
    ("ControlGroup", "/system.slice/other.service"),
    ("Type", "simple"), ("MainPID", "0"),
    ("InvocationID", ""), ("LogNamespace", "foreign"),
])
def test_incorrect_watchdog_pid1_identity_is_rejected_before_proc(
        monkeypatch, field, value):
    valid = {
        "LoadState": "loaded", "ActiveState": "active",
        "SubState": "running", "MainPID": "42",
        "InvocationID": "a"*32,
        "ControlGroup": "/system.slice/" + wd.UNIT,
        "Type": "exec", "Restart": "always",
        "NRestarts": "0", "LogNamespace": "zogfreshcrossbootstrapoct25",
    }
    valid[field] = value
    monkeypatch.setattr(owner, "_pid1_fields", lambda _, **kwargs: valid)
    monkeypatch.setattr(wd, "properties", lambda plan: {
        "ExecStart": ["/usr/bin/python3", "-B", "-m", "zog.host_deploy.gateway.fresh_native_owner",
                      "watch-loop"],
        "Environment": ["PYTHONPATH=/opt/pinned",
                        "PYTHONDONTWRITEBYTECODE=1"],
        "LogNamespace": "zogfreshcrossbootstrapoct25"})
    with pytest.raises(RuntimeError, match="identity not established"):
        owner._watchdog_pid1_evidence({})

def test_cached_completed_job_with_slow_durable_ack_cannot_pass_deadline():
    bus = Bus(event="before")
    confirmed = []
    async def run():
        loop = asyncio.get_running_loop()
        native_time = loop.time
        offset = [0]
        loop.time = lambda: native_time() + offset[0]
        def slow_ack(path):
            confirmed.append(path)
            offset[0] = 21
        try:
            return await jobs.start_and_wait(
                bus, Message(path="/org/freedesktop/systemd1",
                             member="StartTransientUnit"),
                UNIT, timeout=20, on_ack=slow_ack)
        finally:
            loop.time = native_time
    with pytest.raises(jobs.JobNotProven, match="ack-after-deadline"):
        asyncio.run(run())
    assert confirmed == [JOB]
    assert bus.calls.count("StartTransientUnit") == 1


def test_stalled_system_bus_connection_does_not_submit():
    bus = Bus()
    async def connect():
        await asyncio.sleep(1)
        return bus
    with pytest.raises(jobs.JobNotProven, match="connect-timeout"):
        asyncio.run(jobs.connect_and_wait(
            connect, Message(path="/org/freedesktop/systemd1",
                             member="StartTransientUnit"),
            UNIT, timeout=0.02))
    assert bus.calls == []


def test_sidecar_rejects_foreign_process_before_socket_probe(monkeypatch):
    fields = {
        "LoadState": "loaded", "ActiveState": "active",
        "SubState": "running", "MainPID": "123",
        "InvocationID": "a"*32, "ControlGroup":
            "/"+owner.sidecar.SLICE_UNIT+"/"+owner.sidecar.UNIT,
        "Type": "exec", "Restart": "no", "NRestarts": "0",
        "LogNamespace": owner.sidecar.LOG_NAMESPACE}
    monkeypatch.setattr(owner, "_pid1_fields", lambda _, **kw: fields)
    monkeypatch.setattr(owner, "_bounded_proc_probe",
                        lambda *a: pytest.fail("unexpected proc/socket probe"))
    plan = {"properties":{"ExecStart":["/usr/bin/python3","-B",
                                      "-m","zog.root_control"],
                          "Environment":["ROOT_CONTROL_ROLE=build-only-project-v1"]},
            "identity":{"controller_gid":123}}
    for key, changed in [("Type","simple"), ("Restart","always"),
                         ("NRestarts","1"), ("MainPID","0"),
                         ("LogNamespace","foreign"), ("SubState","dead"),
                         ("ControlGroup","/system.slice/other.service")]:
        with pytest.raises(RuntimeError, match="identity not established"):
            owner._sidecar_pid1_evidence(
                plan, deadline=owner.time.monotonic()+5)
        # Ensure each distinct bad field cannot fall back to pathname check.
        old = fields[key]; fields[key] = changed
        with pytest.raises(RuntimeError, match="identity not established"):
            owner._sidecar_pid1_evidence(
                plan, deadline=owner.time.monotonic()+5)
        fields[key] = old


def test_over_budget_watchdog_proc_read_cannot_become_success(monkeypatch):
    evidence = {"MainPID":"42","InvocationID":"a"*32}
    real_time = owner.time.monotonic
    advance=[0.]
    def timed(): return real_time()+advance[0]
    monkeypatch.setattr(owner.time,"monotonic",timed)
    def slow_read(_, *, deadline):
        advance[0] = 16
        return evidence
    monkeypatch.setattr(owner, "_watchdog_pid1_evidence",slow_read)
    with pytest.raises(RuntimeError, match="activation unproven"):
        owner._wait_exact_watchdog({})


def test_over_budget_sidecar_socket_read_cannot_become_success(monkeypatch):
    plan={"identity":{},"installed":{}}
    monkeypatch.setattr(owner,"_read_json",lambda _:plan)
    monkeypatch.setattr(owner.sidecar,"review_plan",lambda *_:plan)
    real_time=owner.time.monotonic
    advance=[0.]
    monkeypatch.setattr(owner.time,"monotonic",
                        lambda:real_time()+advance[0])
    def slow_read(_, *, deadline):
        advance[0]=16
        return {"MainPID":"42","InvocationID":"a"*32}
    monkeypatch.setattr(owner,"_sidecar_pid1_evidence",slow_read)
    with pytest.raises(RuntimeError,match="readiness timed out"):
        owner._wait_exact_sidecar_readiness(object(), owner.sidecar.UNIT)


def test_proc_probe_cannot_succeed_after_subprocess_timeout_budget(monkeypatch):
    from types import SimpleNamespace
    clock = [0.]
    monkeypatch.setattr(owner.time,"monotonic",lambda:clock[0])
    def fake_run(cmd, **kwargs):
        assert kwargs["timeout"] == 15
        assert cmd[1:3] == ["-I", "-B"]
        clock[0]=16.
        return SimpleNamespace(returncode=0,stdout='{"status":"exact-process-verified"}')
    monkeypatch.setattr(owner.subprocess, "run",fake_run)
    with pytest.raises(RuntimeError,match="deadline expired"):
        owner._bounded_proc_probe(
            {"kind":"watchdog","pid":2,"cgroup":"/system.slice/fixed"},15.)
