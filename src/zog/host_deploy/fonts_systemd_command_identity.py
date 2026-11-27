"""Stable systemd 252 command identity, separate from process observations.

"systemctl show" ExecStart/ExecStartPre contains both persistent command
configuration and transient PID/timing/exit metadata. Never approve a release
by hashing or comparing the transient fields. Fail closed on unknown keys.
"""
from __future__ import annotations

import re
import shlex

EXEC_KEYS = ("ExecStart", "ExecStartPre")
PROCESS_KEYS = frozenset({
    "pid", "start_time", "stop_time", "code", "status",
    "start_timestamp", "stop_timestamp",
})
COMMAND_KEYS = frozenset({"path", "argv[]", "ignore_errors", "flags"})
_RECORD = re.compile(r"\{\s*([^{}]*?)\s*\}")


class CommandIdentityHold(ValueError):
    """Invalid or changed configured systemd executable/argv/flags."""


def require(ok, reason):
    if not ok:
        raise CommandIdentityHold(reason)


def parse_property(name, raw):
    """Parse manager records to stable command arrays and volatile evidence.

    Preserve the systemd-serialized argv[] verbatim as the selected argv
    representation; never collapse it into a shell string derived from the
    process command line. Observed timing/PID/exit fields are returned
    separately, never used as immutable selection keys.
    """
    require(name in EXEC_KEYS and type(raw) is str
            and len(raw) <= 65536 and "\n" not in raw and "\r" not in raw,
            "invalid systemd command property")
    if not raw.strip():
        require(name == "ExecStartPre", "missing effective ExecStart")
        return [], []
    stable, evidence = [], []
    end = 0
    for match in _RECORD.finditer(raw):
        require(not raw[end:match.start()].strip(),
                "ambiguous " + name + " systemd command separator")
        end = match.end()
        body = match.group(1).strip()
        if body.endswith(" ;"):
            body = body[:-2].rstrip()
        fields = {}
        for entry in body.split(" ; "):
            key, sep, value = entry.partition("=")
            require(bool(sep) and bool(value) and key not in fields
                    and key in COMMAND_KEYS | PROCESS_KEYS,
                    "unknown or incomplete " + name + " command field")
            fields[key] = value
        require({"path", "argv[]", "ignore_errors"}.issubset(fields),
                "incomplete " + name + " executable/argv/flags")
        path, argv = fields["path"], fields["argv[]"]
        require(path.startswith("/") and path.strip() == path
                and not any(ch in path for ch in " \t\n\r")
                and 0 < len(path) <= 1024 and 0 < len(argv) <= 8192
                and fields["ignore_errors"] in ("yes", "no"),
                "invalid " + name + " executable/argv/flags")
        stable.append({"path": path, "argv": argv,
                       "flags": {"ignore_errors": fields["ignore_errors"],
                                 "flags": fields.get("flags", "")}})
        evidence.append({key: fields[key] for key in sorted(PROCESS_KEYS & fields.keys())})
    require(bool(stable) and not raw[end:].strip(),
            "ambiguous " + name + " command records")
    validate_commands(name, stable)
    return stable, evidence


def validate_commands(name, commands):
    require(name in EXEC_KEYS and type(commands) is list
            and (len(commands) == 1 if name == "ExecStart"
                 else len(commands) <= 64),
            "invalid reviewed " + name + " command count")
    for command in commands:
        require(type(command) is dict
                and set(command) == {"path", "argv", "flags"},
                "invalid reviewed " + name + " command fields")
        require(type(command["path"]) is str
                and command["path"].startswith("/")
                and 0 < len(command["path"]) <= 1024
                and type(command["argv"]) is str
                and 0 < len(command["argv"]) <= 8192,
                "invalid reviewed " + name + " executable/argv")
        flags = command["flags"]
        require(type(flags) is dict
                and set(flags) == {"ignore_errors", "flags"}
                and flags["ignore_errors"] in ("yes", "no")
                and type(flags["flags"]) is str
                and len(flags["flags"]) <= 128,
                "invalid reviewed " + name + " execution flags")


def normalize_effective(raw, keys):
    """Return immutable effective selection and separate process evidence."""
    require(type(raw) is dict and set(raw) == set(keys),
            "incomplete manager-effective properties")
    stable, evidence = {}, {}
    for name in keys:
        if name in EXEC_KEYS:
            stable[name], evidence[name] = parse_property(name, raw[name])
        else:
            value = raw[name]
            require(type(value) is str and len(value) < 8192
                    and "\n" not in value and "\r" not in value,
                    "invalid manager-effective " + name)
            stable[name] = value
    return stable, evidence


def composed_commands(fragment, ordered_dropins):
    """Apply ordered ExecStart/ExecStartPre assignments and blank resets."""
    commands = {name: [] for name in EXEC_KEYS}
    for raw in [fragment, *ordered_dropins]:
        try:
            body = raw.decode("utf-8")
        except UnicodeError as error:
            raise CommandIdentityHold("invalid unit UTF-8") from error
        section = False
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line == "[Service]"
            elif section:
                for name in EXEC_KEYS:
                    if line.startswith(name + "="):
                        value = line.partition("=")[2].strip()
                        if not value:
                            commands[name].clear()
                        else:
                            commands[name].append(value)
    require(len(commands["ExecStart"]) == 1,
            "composed unit has missing or multiple ExecStart")
    return commands


def verify_composed(fragment, ordered_dropins, stable):
    """Check *both* ordered unit commands against manager stable argv/flags."""
    commands = composed_commands(fragment, ordered_dropins)
    for name in EXEC_KEYS:
        expected = stable[name]
        validate_commands(name, expected)
        require(len(commands[name]) == len(expected),
                "composed " + name + " count differs")
        for file_value, recorded in zip(commands[name], expected):
            try:
                file_argv = shlex.split(file_value)
                manager_argv = shlex.split(recorded["argv"])
            except ValueError as error:
                raise CommandIdentityHold("ambiguous " + name + " argv quoting") from error
            require(bool(file_argv) and bool(manager_argv),
                    "composed " + name + " argv is empty")
            # Supported systemd '-' prefix changes *execution* semantics, not
            # argv[0]. Check it against the manager's ignore_errors flag.
            ignore_errors = "yes" if file_argv[0].startswith("-") else "no"
            if ignore_errors == "yes":
                file_argv[0] = file_argv[0][1:]
            require(file_argv == manager_argv
                    and file_argv[0] == recorded["path"],
                    "composed " + name + " argv differs")
            require(recorded["flags"]["ignore_errors"] == ignore_errors
                    and recorded["flags"]["flags"] == "",
                    "composed " + name + " execution flags differ")
    return True
