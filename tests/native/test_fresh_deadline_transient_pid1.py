"""Disposable-only native PID1 acceptance of the production D-Bus timer shape.

This may run ONLY on a GitHub-hosted ephemeral Actions VM as root. It never
starts the production six-hour timer, protected hard-stop command, Zog slice
or compiler. A two-second same-basename dummy pair proves systemd accepts
the REAL production timer property names and auto-activates its service.
"""
import asyncio
import os
from pathlib import Path
import subprocess
import time

from dbus_next import BusType, Message, MessageType, Variant
from dbus_next.aio import MessageBus

from zog.host_deploy.gateway import fresh_deadline_timer as deadline
from zog.host_deploy.gateway import fresh_sidecar_install as sidecar


def _assert_ephemeral():
    if (os.geteuid() != 0
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise RuntimeError("native test only allowed as root on disposable GitHub-hosted PID1")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdecimal() or len(run_id) > 20:
        raise RuntimeError("invalid disposable Actions test identity")
    return run_id


def _show(unit, property):
    return subprocess.check_output(
        ["/usr/bin/systemctl", "show", unit, "--property=" + property,
         "--value"], text=True, timeout=10).strip()


async def _activate(timer_name, service_name, sentinel):
    # Compile the actual production constructor, then substitute only the
    # UNIT ID, duration and the inert service. Any unsupported production
    # timer property remains in the D-Bus request and causes native failure.
    p = {
        "schema": sidecar.SCHEMA,
        "unit": sidecar.UNIT,
        "installed": {
            "python_executable": "/usr/bin/python3",
            "host_deploy_python_root": "/opt/zog/accepted/host-deploy/src",
        },
    }
    production = deadline.message(p)
    assert set(dict(production.body[2])) == {
        "Description", "TimersMonotonic", "AccuracyUSec"}
    assert production.body[0].removesuffix(".timer") == (
        production.body[3][0][0].removesuffix(".service"))
    timer_props = [
        [key, Variant("a(st)", [["OnActiveSec", 2_000_000]])
         if key == "TimersMonotonic" else value]
        for key, value in production.body[2]
    ]
    service_props = [
        ["Description", Variant("s", "Disposable inert PID1 timer witness")],
        ["Type", Variant("s", "oneshot")],
        ["RemainAfterExit", Variant("b", True)],
        ["ExecStart", Variant("a(sasb)", [
            ["/usr/bin/touch", ["/usr/bin/touch", str(sentinel)], False],
        ])],
    ]
    message = Message(
        destination="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member="StartTransientUnit",
        signature="ssa(sv)a(sa(sv))",
        body=[timer_name, "fail", timer_props, [[service_name, service_props]]],
    )
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        reply = await bus.call(message)
        if reply.message_type != MessageType.METHOD_RETURN or reply.signature != "o":
            raise RuntimeError("disposable PID1 rejected timer settings: " +
                               str(reply.body))
        return reply.body[0]
    finally:
        bus.disconnect()


def main():
    run_id = _assert_ephemeral()
    name = "zog-fresh-pid1-deadline-check-" + run_id
    timer, service = name + ".timer", name + ".service"
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if not str(root).startswith("/home/runner/"):
        raise RuntimeError("unexpected disposable runner temp path")
    sentinel = root / (name + ".fired")
    if sentinel.exists() or sentinel.is_symlink():
        raise RuntimeError("disposable timer witness already ran")
    try:
        job = asyncio.run(_activate(timer, service, sentinel))
        assert job.startswith("/org/freedesktop/systemd1/job/")
        assert _show(timer, "Unit") == service
        clocks = _show(timer, "TimersMonotonic")
        assert "OnActiveUSec" in clocks, clocks  # readback name, NOT writable key
        assert "2000000" in clocks or "2s" in clocks, clocks
        deadline_at = time.monotonic() + 25
        while not sentinel.exists() and time.monotonic() < deadline_at:
            time.sleep(0.1)
        if not sentinel.is_file():
            raise RuntimeError("paired disposable service was never activated")
        print("PASS: native PID1 accepted TimersMonotonic, inferred same-name "
              "service, and executed inert 2-second timer")
    finally:
        # On the ephemeral runner only. Never run production hard-stop or
        # operate any pre-existing Zog service.
        subprocess.run(["/usr/bin/systemctl", "stop", timer, service],
                       check=False, timeout=10, capture_output=True)
        subprocess.run(["/usr/bin/systemctl", "reset-failed", timer, service],
                       check=False, timeout=10, capture_output=True)
        sentinel.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
