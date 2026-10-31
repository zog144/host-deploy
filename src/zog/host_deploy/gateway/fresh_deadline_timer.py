"""PID1-enforced one-shot overall deadline for the NEW compiler only.

Starts before budget arming; systemd owns a monotonic deadline independent
of cron and the Python watchdog. The timer's auxiliary oneshot reopens the
same root-owned ledger and cancels the same approved fresh cgroup.
No user-selected unit, executable, command, deadline or project.
"""
import asyncio
import os

from .fresh_budget_guard import DEADLINE_SECONDS
from .fresh_watchdog_service import UNIT as WATCHDOG_UNIT
from .fresh_sidecar_install import LOG_NAMESPACE

UNIT = "zogfreshcrossbootstrapoct25-deadline.timer"
STOP_UNIT = "zogfreshcrossbootstrapoct25-deadline.service"
# Arm this timer BEFORE recording budget start; conservative safety margin.
# Timer monotonic clock is owned by PID1, independent from the Python loops.
MARGIN_SECONDS = 30
TRIGGER_SECONDS = DEADLINE_SECONDS - MARGIN_SECONDS


def _paths(plan):
    if (type(plan) is not dict
            or plan.get("unit") !=
                "zog-fresh-cross-bootstrap-oct25-controller.service"
            or plan.get("schema") != "host-deploy-fresh-sidecar-install-v1"):
        raise ValueError("deadline requires the exact new sidecar binding")
    installed = plan["installed"]
    binary = installed["python_executable"]
    source = installed["host_deploy_python_root"]
    if (type(binary) is not str or type(source) is not str
            or not binary.startswith("/") or not source.startswith("/")
            or any(x in binary + source for x in ("\0", "\n", " ", ":"))):
        raise ValueError("deadline executable/source is not immutable")
    return binary, source


def message(plan):
    from dbus_next import Message, Variant
    binary, source = _paths(plan)
    env = ["PYTHONPATH=" + source, "PYTHONDONTWRITEBYTECODE=1"]
    # PID1's Timer.Unit is a READ-ONLY property; systemd resolves the
    # same-basename <timer>.service implicitly. Never submit "Unit" to
    # StartTransientUnit. In systemd 252 the writable monotonic constructor is
    # TimersMonotonic: a(st), with "OnActiveSec" and a MICROSECOND value.
    # OnActiveUSec is only a readback name, not a transient setter.
    if UNIT.removesuffix(".timer") != STOP_UNIT.removesuffix(".service"):
        raise RuntimeError("fixed timer and cancellation service diverged")
    timer = [
        ["Description", Variant("s", "Fixed fresh compiler overall deadline")],
        ["TimersMonotonic", Variant(
            "a(st)", [["OnActiveSec", TRIGGER_SECONDS * 1_000_000]])],
        ["AccuracyUSec", Variant("t", 1_000_000)],
    ]
    # Declare an auxiliary oneshot unit, but only START the timer.
    # Starting the service directly is never exposed through this adapter.
    stop = [
        ["Description", Variant("s", "Stop only frozen fresh compiler slice")],
        ["Type", Variant("s", "oneshot")],
        ["ExecStart", Variant("a(sasb)", [[binary, [
            binary, "-B", "-m", "zog.host_deploy.gateway.fresh_native_owner",
            "hard-stop",
        ], False]])],
        ["Environment", Variant("as", env)],
        ["User", Variant("s", "0")], ["Group", Variant("s", "0")],
        ["Slice", Variant("s", "system.slice")],
        ["NoNewPrivileges", Variant("b", True)],
        ["StandardOutput", Variant("s", "journal")],
        ["StandardError", Variant("s", "journal")],
        ["LogNamespace", Variant("s", LOG_NAMESPACE)],
    ]
    return Message(
        destination="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member="StartTransientUnit",
        signature="ssa(sv)a(sa(sv))",
        body=[UNIT, "fail", timer, [[STOP_UNIT, stop]]],
    )


async def _start(plan, *, connect=None):
    from dbus_next import BusType, MessageType
    from dbus_next.aio import MessageBus
    bus = await (MessageBus(bus_type=BusType.SYSTEM).connect()
                 if connect is None else connect())
    try:
        reply = await bus.call(message(plan))
        if (reply.message_type == MessageType.ERROR or reply.signature != "o"
                or len(reply.body) != 1):
            raise RuntimeError("PID1 independent hard deadline uncertain")
        return {"unit": UNIT, "target": STOP_UNIT,
                "job_path": reply.body[0], "reload": False}
    finally:
        bus.disconnect()


def start(plan, *, connect=None):
    if os.geteuid() != 0:
        raise PermissionError("protected root owner required for timer admission")
    return asyncio.run(_start(plan, connect=connect))
