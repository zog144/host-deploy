"""Fixed PID1-supervised watchdog independent of crond.

No general transient unit API is exported. This root-owned service continues
to sample the same protected budget when cron is inactive, triggering the
already durable one-attempt new-Project cancellation. It does not submit work.
"""
import asyncio
import os

UNIT = "zogfreshcrossbootstrapoct25-watchdog.service"
INTERVAL_SECONDS = 5
RESTART_SECONDS = 1


def properties(plan):
    from .fresh_sidecar_install import SCHEMA
    from .fresh_native_owner import STATE
    if (type(plan) is not dict or plan.get("schema") != SCHEMA
            or plan.get("unit") != "zog-fresh-cross-bootstrap-oct25-controller.service"):
        raise ValueError("watchdog requires exact reviewed sidecar plan")
    installed = plan["installed"]
    binary = installed["python_executable"]
    source = installed["host_deploy_python_root"]
    if (type(binary) is not str or type(source) is not str
            or not binary.startswith("/") or not source.startswith("/")
            or any(c in binary + source for c in ("\x00", "\n", " ", ":"))):
        raise ValueError("untrusted watchdog executable/source")
    return {
        "Description": "Zog protected fresh compiler independent budget watchdog",
        "Type": "exec",
        "ExecStart": [binary, "-B", "-m",
                      "zog.host_deploy.gateway.fresh_native_owner", "watch-loop"],
        "Environment": ["PYTHONPATH=" + source, "PYTHONDONTWRITEBYTECODE=1"],
        "User": "0", "Group": "0",
        "Slice": "system.slice",
        "Restart": "always", "RestartUSec": 1_000_000,
        "NoNewPrivileges": True,
        "StandardOutput": "journal", "StandardError": "journal",
    }


def message(plan):
    """Wire-serializable real dbus-next StartTransientUnit, no shared reload."""
    from dbus_next import Message, Variant
    p = properties(plan)
    argv = p["ExecStart"]
    typed = {
        "Description": ("s", p["Description"]),
        "Type": ("s", "exec"),
        "ExecStart": ("a(sasb)", [[argv[0], argv, False]]),
        "Environment": ("as", p["Environment"]),
        "User": ("s", "0"), "Group": ("s", "0"),
        "Slice": ("s", "system.slice"),
        "Restart": ("s", "always"), "RestartUSec": ("t", 1_000_000),
        "NoNewPrivileges": ("b", True),
        "StandardOutput": ("s", "journal"), "StandardError": ("s", "journal"),
    }
    return Message(
        destination="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member="StartTransientUnit",
        signature="ssa(sv)a(sa(sv))",
        body=[UNIT, "fail", [[k, Variant(*v)] for k, v in typed.items()], []],
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
            raise RuntimeError("independent watchdog PID1 activation uncertain")
        return {"unit": UNIT, "job_path": reply.body[0],
                "method": "StartTransientUnit", "reload": False}
    finally:
        bus.disconnect()


def start(plan, *, connect=None):
    if os.geteuid() != 0:
        raise PermissionError("independent watchdog requires protected root owner")
    return asyncio.run(_start(plan, connect=connect))
