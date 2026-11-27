"""Independent, read-only compiler issuer-persistence composition verification.

This checks the preservation requirements visible in the selected systemd
unit and protected drop-in bytes. It does NOT inspect issuer private storage
or authorize startup; the issuer persistence owner retains that native gate.
"""
from __future__ import annotations

import hashlib
import shlex
import posixpath

COMPILER_UNIT = "zog-certbot-seed-root.service"
ISSUER_DROPIN = "issuer-persistence.conf"
RETIRED_COMPILER_RUNTIME = "/opt/zog/fonts-controller-d9dfd6c0-20261114"


class IssuerPersistenceHold(RuntimeError):
    """Selected compiler loses a protected issuer persistence restriction."""


def require(value, reason):
    if not value:
        raise IssuerPersistenceHold(reason)


def _member(entries):
    require(type(entries) is list, "missing issuer drop-in selection")
    found = [entry for entry in entries
             if type(entry) is dict and entry.get("name") == ISSUER_DROPIN]
    require(len(found) == 1, "issuer persistence drop-in missing or duplicated")
    record = found[0]
    require(set(record) == {"name", "sha256", "size", "mode", "uid", "gid"}
            and record["uid"] == 0 and record["gid"] == 0
            and record["mode"] in (0o600, 0o640, 0o644),
            "issuer persistence drop-in ownership or mode differs")
    return record


def _constraints(raw):
    require(type(raw) is bytes and bool(raw),
            "missing issuer persistence drop-in bytes")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise IssuerPersistenceHold("invalid issuer persistence encoding") from error
    section = None
    prestart = []
    readonly = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section != "[Service]":
            continue
        key, sep, value = line.partition("=")
        if key not in ("ExecStartPre", "ReadOnlyPaths"):
            continue
        require(bool(sep) and bool(value.strip()),
                "issuer persistence restriction cleared")
        if key == "ExecStartPre":
            require(not value.strip().startswith("-"),
                    "issuer persistence prestart must not ignore failures")
            try:
                command = shlex.split(value.strip())
            except ValueError as error:
                raise IssuerPersistenceHold("issuer persistence prestart is ambiguous") from error
            require(bool(command) and command[0].startswith("/"),
                    "issuer persistence prestart executable is invalid")
            prestart.append(command)
        else:
            values = value.split()
            require(all(item.startswith("/") and ".." not in item.split("/")
                        for item in values),
                    "issuer persistence read-only path is invalid")
            readonly.extend(values)
    require(bool(prestart) and bool(readonly),
            "issuer persistence prestart/read-only restrictions missing")
    return prestart, set(readonly)


def _effective(comp, phase, prestart, readonly):
    props = comp[phase + "_effective"]
    require(type(props) is dict, "issuer manager-effective selection missing")
    commands = props.get("ExecStartPre")
    require(type(commands) is list and commands,
            "issuer persistence effective prestart is missing")
    available = []
    for item in commands:
        require(type(item) is dict and set(item) == {"path", "argv", "flags"},
                "issuer persistence effective prestart is unreviewed")
        flags = item["flags"]
        require(type(flags) is dict and set(flags) == {"ignore_errors", "flags"},
                "issuer persistence effective prestart execution flags invalid")
        try:
            argv = shlex.split(item["argv"])
        except (TypeError, ValueError) as error:
            raise IssuerPersistenceHold("issuer effective prestart argv invalid") from error
        require(argv and argv[0] == item["path"],
                "issuer persistence effective executable differs")
        available.append((argv, flags))
    require(all(any(argv == actual and
                    flags == {"ignore_errors": "no", "flags": ""}
                    for argv, flags in available) for actual in prestart),
            "issuer persistence effective prestart or execution flags changed")
    paths = props.get("ReadOnlyPaths")
    require(type(paths) is str and readonly <= set(paths.split()),
            "issuer persistence effective read-only mounts differ")
    for name in ("Requires", "After"):
        value = props.get(name)
        require(type(value) is str and bool(value.strip()),
                "issuer persistence effective mount dependency missing: " + name)
    return props


def _retired_runtime(selection):
    """One independently recorded original runtime, never an issuer mount."""
    rollback = selection.get("rollback")
    require(type(rollback) is dict, "missing protected rollback runtime")
    path = rollback.get("original_runtime")
    require(type(path) is str and path.startswith("/")
            and path != "/" and "//" not in path
            and "." not in path.split("/") and ".." not in path.split("/"),
            "unusable protected original compiler runtime")
    # Only the known old compiler tree is eligible. In particular the
    # issuer's separately protected /opt/zog/certbot-seed-oct21 must not
    # become a permitted retired path.
    require(path == RETIRED_COMPILER_RUNTIME,
            "original runtime is not the reviewed retiring compiler")
    return path


def _runtime_path(token, old_root):
    # A textual slash prefix is insufficient: /old/compiler/../issuer and
    # /old/compiler/./alias are NOT reviewed descendants of the old runtime.
    # Never resolve symlinks or consult mutable Host filesystem state here;
    # require a canonical absolute path as part of the immutable selection.
    return (type(token) is str and token.startswith("/")
            and token == posixpath.normpath(token)
            and (token == old_root or token.startswith(old_root + "/")))


def _runtime_prestart(command, old_root):
    """Only a command actually referring to the retired tree is removable."""
    require(type(command) is dict and set(command) == {"path", "argv", "flags"},
            "unreviewed original prestart identity")
    try:
        argv = shlex.split(command["argv"])
    except (TypeError, ValueError) as error:
        raise IssuerPersistenceHold("unparseable original prestart argv") from error
    return (type(command["path"]) is str
            and (_runtime_path(command["path"], old_root)
                 or any(_runtime_path(arg, old_root) for arg in argv)))


def verify(selection, original_dropin, selected_dropin):
    """Verify the original and selected issuer restrictions independently.

    All bytes and manager properties are also verified by the general
    host-deploy unit-composition gate. This check binds the *issuer meaning*
    of those properties; it must not trust installer success or approvals.
    """
    require(type(selection) is dict and type(selection.get("service")) is dict
            and type(selection.get("composition")) is dict,
            "issuer persistence selection is incomplete")
    service = selection["service"]
    comp = selection["composition"]
    original = comp.get("original_dropins", [])
    selected = comp.get("selected_dropins", [])
    present = any(type(entry) is dict and entry.get("name") == ISSUER_DROPIN
                  for entry in [*original, *selected])
    if service.get("name") != COMPILER_UNIT:
        require(not present, "issuer drop-in attached to an unselected service")
        return {"applicable": False, "verified": False}
    before, after = _member(original), _member(selected)
    require(before == after,
            "issuer persistence drop-in metadata changed across selection")
    require(type(original_dropin) is bytes and type(selected_dropin) is bytes
            and original_dropin == selected_dropin
            and hashlib.sha256(original_dropin).hexdigest() == before["sha256"]
            and len(original_dropin) == before["size"],
            "issuer persistence bytes differ from protected rollback")
    prestart, readonly = _constraints(original_dropin)
    original_properties = _effective(comp, "original", prestart, readonly)
    selected_properties = _effective(comp, "selected", prestart, readonly)
    # The original compiler may have additional prestart commands and
    # read-only paths for its *retiring runtime*. The issuer's drop-in
    # commands/paths are already required by _effective() in BOTH versions.
    # All other original protections must remain in the selected manager.
    old_runtime = _retired_runtime(selection)
    retained_prestarts = [
        command for command in original_properties["ExecStartPre"]
        if not _runtime_prestart(command, old_runtime)
    ]
    require(all(command in selected_properties["ExecStartPre"]
                for command in retained_prestarts),
            "non-retired original prestart or issuer check removed")
    protected_paths = {
        entry for entry in original_properties["ReadOnlyPaths"].split()
        if not _runtime_path(entry, old_runtime)
    }
    require(protected_paths <= set(selected_properties["ReadOnlyPaths"].split()),
            "issuer or non-retired original read-only mount removed")
    # Requires/After may include backing-mount and issuer dependencies;
    # never treat a unit dependency as retiring merely because an unrelated
    # compiler path is retired. Keep them all until independently classified.
    for name in ("Requires", "After"):
        require(set(original_properties[name].split())
                <= set(selected_properties[name].split()),
                "issuer persistence backing mount dependency removed: " + name)
    return {
        "applicable": True,
        "verified": True,
        "issuer_dropin_sha256": before["sha256"],
        "original_unit_sha256": selection["rollback"]["unit_sha256"],
        "selected_unit_sha256": service["staged_sha256"],
        "native_issuer_storage_verified": False,
        "startup_authorized": False,
    }
