"""Native systemd D-Bus transport for the one fixed privileged compiler sidecar.

Exposed only to an independently approved root-owned installer. GitHub and
SSM messages MUST NOT be able to invoke this module as a generic command.
No disk .service file, daemon-reload, generic unit or arbitrary ExecStart.
"""
import asyncio
import os

from .fresh_sidecar_install import UNIT, ROLE, SOCKET, SLICE_UNIT, LOG_NAMESPACE, REGISTRATION_SOURCE, REGISTRATION_DEST


def _checked_properties(unit, mode, properties):
    if unit != UNIT or mode != "fail" or type(properties) is not dict:
        raise ValueError("only one absent fixed host sidecar may start")
    required = {
        "Description", "Type", "ExecStart", "Environment", "User", "Group",
        "Restart", "RestartSec", "StartLimitBurst",
        "StartLimitIntervalSec", "StandardOutput", "StandardError",
        "NoNewPrivileges", "Slice", "LogNamespace", "BindPaths",
    }
    if set(properties) != required:
        raise ValueError("unsupported transient systemd service property")
    argv = properties["ExecStart"]
    if (type(argv) is not list or len(argv) != 4
            or argv[1:] != ["-B", "-m", "zog.root_control"]
            or type(argv[0]) is not str or not argv[0].startswith("/")):
        raise ValueError("unreviewed root-control service executable")
    if (properties["Slice"] != SLICE_UNIT
            or properties["Type"] != "exec" or properties["User"] != "0"
            or properties["Group"] != "0"
            or properties["Restart"] != "no"
            or properties["RestartSec"] != "0s"
            or properties["StartLimitBurst"] != 1
            or properties["StartLimitIntervalSec"] != "60s"
            or properties["StandardOutput"] != "journal"
            or properties["BindPaths"] != [[REGISTRATION_SOURCE, REGISTRATION_DEST, False, 0]]
            or properties["LogNamespace"] != LOG_NAMESPACE
            or properties["StandardError"] != "journal"
            or properties["NoNewPrivileges"] is not True):
        raise ValueError("unreviewed root-control lifecycle properties")
    env = properties["Environment"]
    if (type(env) is not list or len(env) != 7
            or len({x.split("=", 1)[0] for x in env}) != len(env)):
        raise ValueError("root-control startup environment must be exact")
    env_map = dict(x.split("=", 1) for x in env)
    if (env_map.get("ROOT_CONTROL_ROLE") != ROLE
            or env_map.get("ROOT_CONTROL_SOCKET") != SOCKET
            or not env_map.get("ROOT_CONTROL_AUTHORIZED_PROJECT", "").endswith(
                "/fresh-cross-bootstrap-oct25")
            or not env_map.get("ROOT_CONTROL_CONTROLLER_UID", "").isdecimal()
            or not env_map.get("ROOT_CONTROL_SOCKET_GID", "").isdecimal()
            or env_map.get("PYTHONDONTWRITEBYTECODE") != "1"
            or not env_map.get("PYTHONPATH", "").startswith("/")):
        raise ValueError("privileged sidecar startup role/Project is incomplete")
    # Exact D-Bus types: ExecStart is a(sasb); StartLimit and Restart
    # intervals are usec properties rather than free-form unit-file text.
    return [
        ("Description", "s", properties["Description"]),
        ("Type", "s", "exec"),
        ("ExecStart", "a(sasb)", [[argv[0], argv, False]]),
        ("Environment", "as", env),
        ("User", "s", "0"), ("Group", "s", "0"),
        ("Slice", "s", SLICE_UNIT),
        ("Restart", "s", "no"),
        ("RestartUSec", "t", 0),
        ("StartLimitBurst", "u", 1),
        ("StartLimitIntervalUSec", "t", 60_000_000),
        ("StandardOutput", "s", "journal"),
        ("StandardError", "s", "journal"),
        ("LogNamespace", "s", LOG_NAMESPACE),
        ("BindPaths", "a(ssbt)", [[REGISTRATION_SOURCE, REGISTRATION_DEST, False, 0]]),
        ("NoNewPrivileges", "b", True),
    ]


def _message(unit, typed_properties):
    """Build a complete dbus-next message with actual list-valued structs.

    dbus-next 0.2.3 requires Python lists for D-Bus structs; tuples that
    look plausible in Python fail its signature verifier on serialization.
    """
    from dbus_next import Message, Variant
    return Message(
        destination="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member="StartTransientUnit",
        signature="ssa(sv)a(sa(sv))",
        body=[
            unit, "fail",
            [[key, Variant(signature, value)]
             for key, signature, value in typed_properties],
            [],
        ],
    )


async def _start(unit, typed_properties, *, connect=None, on_ack=None):
    from dbus_next import BusType
    from dbus_next.aio import MessageBus
    from . import fresh_pid1_job
    return await fresh_pid1_job.connect_and_wait(
        (lambda: MessageBus(bus_type=BusType.SYSTEM).connect())
        if connect is None else connect,
        _message(unit, typed_properties), unit, on_ack=on_ack)


def start_exact_sidecar(unit, mode, properties, *, connect=None,
                        on_ack=None):
    """Synchronous host-owner-only wrapper. No SSM/root-shell entrypoint."""
    if os.geteuid() != 0:
        raise PermissionError("only privileged installer may contact PID1")
    typed = _checked_properties(unit, mode, properties)
    return asyncio.run(_start(unit, typed, connect=connect, on_ack=on_ack))
