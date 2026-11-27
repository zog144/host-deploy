"""Read-only complete compiler systemd unit composition and loaded-property checks.

An approved main fragment alone does not select an ExecStart: later drop-ins
may reset it. This inspector never mutates systemd or installed files.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

from . import fonts_systemd_command_identity as command_identity

KEYS = ("ExecStart", "ExecStartPre", "ReadOnlyPaths", "Requires", "After")

GUARD_NAME = "zzzz-zog-compiler-transaction-guard.conf"


def transaction_guard_bytes(release):
    """Permanent-disk, deny-by-default systemd condition during a transaction.

    No startup-permit file is ever issued by this installer. This drop-in
    survives reboot independently of the fragment's temporary /dev/null mask.
    """
    need(type(release) is str and re.fullmatch(r"[0-9a-f]{32,64}", release),
         "invalid guarded release")
    return ("[Unit]\nConditionPathExists=/opt/zog/compiler-runtime/rollback/"
            + release + "/startup-permit\n").encode("ascii")


def verify_transaction_guard(directory, release):
    path = Path(directory) / GUARD_NAME
    expected = transaction_guard_bytes(release)
    actual = inventory(directory)
    need(all(item["name"] <= GUARD_NAME for item in actual),
         "drop-in ordered after protective startup guard")
    matches = [item for item in actual if item["name"] == GUARD_NAME]
    need(len(matches) == 1 and matches[0]["mode"] == 0o644,
         "missing protected persistent startup guard")
    need(path.read_bytes() == expected,
         "persistent startup guard differs from reviewed condition")
    permit = Path("/opt/zog/compiler-runtime/rollback") / release / "startup-permit"
    need(not permit.exists() and not permit.is_symlink(),
         "compiler startup permit unexpectedly exists")
    return matches[0]

_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\.conf\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")


class CompositionHold(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise CompositionHold(reason)


def _files(spec, role):
    need(type(spec) is list and len(spec) <= 64, "invalid " + role + " drop-ins")
    names = set()
    for entry in spec:
        need(type(entry) is dict and set(entry) ==
             {"name", "sha256", "size", "mode", "uid", "gid"},
             "invalid " + role + " drop-in inventory")
        name = entry["name"]
        need(type(name) is str and _NAME.fullmatch(name) is not None
             and name not in names, "invalid or duplicate drop-in name")
        names.add(name)
        need(type(entry["sha256"]) is str
             and _HEX.fullmatch(entry["sha256"]) is not None
             and type(entry["size"]) is int and 0 < entry["size"] <= 1024 * 1024
             and type(entry["mode"]) is int
             and entry["mode"] in (0o600, 0o640, 0o644)
             and entry["uid"] == entry["gid"] == 0,
             "invalid or unprotected drop-in selection")
    need([entry["name"] for entry in spec] == sorted(names),
         "drop-in selection must follow systemd lexical override order")
    return names


def _fragment_spec(spec):
    need(type(spec) is dict and set(spec) ==
         {"path", "sha256", "size", "mode", "uid", "gid"},
         "incomplete compiler fragment metadata")
    need(type(spec["path"]) is str and spec["path"].startswith("/")
         and ".." not in Path(spec["path"]).parts
         and type(spec["sha256"]) is str and _HEX.fullmatch(spec["sha256"]) is not None
         and type(spec["size"]) is int and 0 < spec["size"] <= 1024 * 1024
         and type(spec["mode"]) is int and spec["mode"] in (0o600, 0o640, 0o644)
         and spec["uid"] == spec["gid"] == 0,
         "invalid compiler fragment metadata")


def verify_fragment(path, spec):
    _fragment_spec(spec)
    need(str(path) == spec["path"], "compiler fragment path differs")
    path = Path(path)
    need(not path.is_symlink(), "linked compiler fragment")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and info.st_uid == spec["uid"] and info.st_gid == spec["gid"]
         and stat.S_IMODE(info.st_mode) == spec["mode"],
         "compiler fragment ownership or mode differs")
    raw = path.read_bytes()
    need(len(raw) == spec["size"] and
         hashlib.sha256(raw).hexdigest() == spec["sha256"],
         "compiler fragment bytes differ")


def validate(composition):
    need(type(composition) is dict and set(composition) ==
         {"original_fragment", "selected_fragment",
          "original_dropins", "selected_dropins", "original_effective",
          "selected_effective"},
         "incomplete compiler unit composition")
    _fragment_spec(composition["original_fragment"])
    _fragment_spec(composition["selected_fragment"])
    _files(composition["original_dropins"], "original")
    _files(composition["selected_dropins"], "selected")
    for phase in ("original", "selected"):
        effective = composition[phase + "_effective"]
        need(type(effective) is dict and set(effective) == set(KEYS),
             "incomplete effective systemd property selection")
        for name in command_identity.EXEC_KEYS:
            try:
                command_identity.validate_commands(name, effective[name])
            except command_identity.CommandIdentityHold as error:
                raise CompositionHold(str(error)) from error
        for name in set(KEYS) - set(command_identity.EXEC_KEYS):
            value = effective[name]
            need(type(value) is str and len(value) < 8192
                 and chr(10) not in value and chr(13) not in value,
                 "incomplete effective systemd property selection")
    return composition


def inventory(directory):
    """Read exact directory entries; linked/foreign drop-ins always HOLD."""
    directory = Path(directory)
    if not directory.exists() and not directory.is_symlink():
        return []
    need(not directory.is_symlink() and directory.is_dir(),
         "foreign systemd drop-in directory")
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
         and not info.st_mode & 0o022,
         "unprotected systemd drop-in directory")
    result = []
    for entry in sorted(directory.iterdir()):
        need(_NAME.fullmatch(entry.name) is not None, "unknown systemd drop-in")
        info = entry.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and info.st_uid == info.st_gid == 0
             and not info.st_mode & 0o022
             and 0 < info.st_size <= 1024 * 1024,
             "unprotected systemd drop-in")
        raw = entry.read_bytes()
        need(len(raw) == info.st_size, "changed systemd drop-in")
        result.append({"name": entry.name, "sha256": hashlib.sha256(raw).hexdigest(),
                       "size": len(raw), "mode": stat.S_IMODE(info.st_mode),
                       "uid": info.st_uid, "gid": info.st_gid})
    return result


def verify(directory, entries):
    need(inventory(directory) == entries,
         "systemd drop-in set or installed bytes differ")


def composed_exec(fragment, ordered_dropins):
    """Systemd's ordered empty ExecStart= reset semantics (simple services)."""
    commands = []
    for raw in (fragment, *ordered_dropins):
        try:
            text = raw.decode("utf-8")
        except UnicodeError as error:
            raise CompositionHold("invalid systemd unit UTF-8") from error
        in_service = False
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_service = line == "[Service]"
            elif in_service and line.startswith("ExecStart="):
                command = line.split("=", 1)[1].strip()
                if not command:
                    commands.clear()
                else:
                    commands.append(command)
    need(len(commands) == 1, "effective unit has missing or multiple ExecStart")
    return commands[0]


def normalize_loaded_commands(raw):
    """Read-only split for host-install: stable identity plus process evidence."""
    try:
        return command_identity.normalize_effective(raw, KEYS)
    except command_identity.CommandIdentityHold as error:
        raise CompositionHold(str(error)) from error


def verify_composed(fragment, ordered_dropins, expected):
    """Require ordered ExecStart AND ExecStartPre source to match stable argv."""
    try:
        return command_identity.verify_composed(
            fragment, ordered_dropins, expected)
    except command_identity.CommandIdentityHold as error:
        raise CompositionHold(str(error)) from error


def read_loaded(service, *, runner=subprocess.run):
    """Read systemd's manager-effective properties, not just fragment text."""
    need(type(service) is str and re.fullmatch(r"zog-[a-z0-9-]+\.service", service),
         "unrecognized service")
    args = ["/usr/bin/systemctl", "show", "--no-pager",
            "--property=" + ",".join((*KEYS, "FragmentPath", "DropInPaths", "LoadState")),
            service]
    result = runner(args, check=False, text=True, capture_output=True)
    need(result.returncode == 0, "cannot read effective systemd controller unit")
    values = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        need(sep and key not in values, "invalid systemd manager result")
        values[key] = value
    need(set(values) == set(KEYS) | {"FragmentPath", "DropInPaths", "LoadState"}
         and values["LoadState"] == "loaded",
         "systemd manager has incomplete or unloaded unit")
    return values


def verify_loaded(service, *, fragment, names, expected, runner=subprocess.run):
    loaded = read_loaded(service, runner=runner)
    need(loaded["FragmentPath"] == str(fragment), "loaded systemd fragment differs")
    expected_paths = {str(Path(str(fragment) + ".d") / name) for name in names}
    need(set(loaded["DropInPaths"].split()) == expected_paths,
         "loaded systemd drop-ins differ from reviewed selection")
    try:
        stable, process_metadata = command_identity.normalize_effective(
            {key: loaded[key] for key in KEYS}, KEYS)
    except command_identity.CommandIdentityHold as error:
        raise CompositionHold(str(error)) from error
    for prop in KEYS:
        actual, wanted = stable[prop], expected[prop]
        if prop in ("Requires", "After"):
            need(sorted(actual.split()) == sorted(wanted.split()),
                 "effective " + prop + " differs from approved selection")
        else:
            need(actual == wanted,
                 "effective " + prop + " differs from approved selection")
    return {"fragment": loaded["FragmentPath"],
            "dropins": sorted(expected_paths),
            "effective": stable,
            "process_metadata": process_metadata}
