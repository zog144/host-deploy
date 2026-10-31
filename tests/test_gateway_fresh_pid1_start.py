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
    return Message.new_method_return(Message(
        destination="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member="StartTransientUnit"), signature=signature, body=body or [])


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
            signature="uoss", body=[42, JOB, UNIT, self.result]))

    async def call(self, msg):
        self.calls.append(msg.member)
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
    assert bus.calls == ["AddMatch", "Subscribe", "StartTransientUnit"]


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


def test_unit_readiness_waits_for_active_and_socket(monkeypatch):
    recorded = iter([
        {"ActiveState": "activating", "MainPID": "0"},
        {"ActiveState": "active", "MainPID": "41", "InvocationID": "a"*32},
        {"ActiveState": "active", "MainPID": "41", "InvocationID": "a"*32},
        {"ActiveState": "active", "MainPID": "41", "InvocationID": "a"*32}])
    checks = iter([False, True, True])
    native = SimpleNamespace(
        read_unit=lambda _: next(recorded),
        socket_exists=lambda _: next(checks))
    monkeypatch.setattr(owner.time, "sleep", lambda _: None)
    observed = owner._wait_exact_sidecar_readiness(native, owner.sidecar.UNIT)
    assert observed["MainPID"] == "41"


def test_watchdog_wait_requires_two_stable_readbacks(monkeypatch):
    evidence = {"MainPID": "42", "InvocationID": "a"*32}
    observations = iter([None, evidence, evidence])
    def observe(_):
        item = next(observations)
        if item is None:
            raise RuntimeError("still activating")
        return item
    monkeypatch.setattr(owner, "_watchdog_pid1_evidence", observe)
    monkeypatch.setattr(owner.time, "sleep", lambda _: None)
    assert owner._wait_exact_watchdog({}) == evidence


def test_watchdog_expired_readiness_stays_no_go(monkeypatch):
    monkeypatch.setattr(owner, "_watchdog_pid1_evidence",
                        lambda _: (_ for _ in ()).throw(RuntimeError("unready")))
    counter = iter([0., 30.])
    monkeypatch.setattr(owner.time, "monotonic", lambda: next(counter))
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
    with pytest.raises(RuntimeError):
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
