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

KEYS = ("ExecStart", "ExecStartPre", "ReadOnlyPaths", "Requires", "After")
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


def validate(composition):
    need(type(composition) is dict and set(composition) ==
         {"original_dropins", "selected_dropins", "original_effective",
          "selected_effective"},
         "incomplete compiler unit composition")
    _files(composition["original_dropins"], "original")
    _files(composition["selected_dropins"], "selected")
    for phase in ("original", "selected"):
        effective = composition[phase + "_effective"]
        need(type(effective) is dict and set(effective) == set(KEYS)
             and all(type(v) is str and len(v) < 8192
                     and "\n" not in v and "\r" not in v
                     for v in effective.values()),
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
    for prop in KEYS:
        actual, wanted = loaded[prop], expected[prop]
        if prop in ("Requires", "After"):
            need(sorted(actual.split()) == sorted(wanted.split()),
                 "effective " + prop + " differs from approved selection")
        else:
            need(actual == wanted,
                 "effective " + prop + " differs from approved selection")
    return {"fragment": loaded["FragmentPath"],
            "dropins": sorted(expected_paths), "effective": {k: loaded[k] for k in KEYS}}
