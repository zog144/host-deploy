"""Read-only versioned controller deployment and inherited-child admission.

Source acceptance never selects a service or permits first Fonts compilation.
The root-owned installer retains the existing unit and the whole old runtime
separately before selecting a new immutable generation. The live Host's
root-control owner must independently authenticate its peer-to-child binding.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

SCHEMA = "zog-first-fonts-versioned-controller-selection-v1"
CONTRACT = "zog-build-inherited-peer-v2"
RELEASES = "/opt/zog/compiler-runtime/versions"
ROLLBACK = "/opt/zog/compiler-runtime/rollback"
UNIT_DIR = "/etc/systemd/system"
SELECTIONS = "/var/lib/zog/compiler-runtime/selections"
COMPONENTS = frozenset({"root-control", "box-control", "image-build"})
# Actual clean Git checkout SHA256 inventories measured by the exact-revision
# CI on 2026-11-21. These are source bytes, NOT installed module/RECORD hashes.
# Each new candidate requires an explicit reviewed source change to these pins.
SELECTED_SOURCES = {
    "root-control": {
        "revision": "58b5a94311d771bb1c5f4c3e9c6191b44d6565c9",
        "source_tree_sha256": "0ffddcfb39a9cc5295cc67196362e2dcb57301ed70199c502af1203e20c2d097",
    },
    "box-control": {
        "revision": "ad61fa6a4e9c3176149720868cb008e0512dbec9",
        "source_tree_sha256": "9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00",
    },
    "image-build": {
        "revision": "ff968a431dd2067e7d0e1f17d6e547f2779f647a",
        "source_tree_sha256": "e0aacfb08a8b0ef9b1883080ece7d93673906263bee30caa09a285e7a1466310",
    },
}
MODULE_PATH_SUFFIXES = {
    "root-control-module": "/zog/root_control/build.py",
    "box-control-module": "/zog/box_control/build_jobs.py",
    "image-build-module": "/zog/image_build/box_control_adapter.py",
}
REQUIRED_FILES = frozenset(MODULE_PATH_SUFFIXES)
SEPARATE_RECORD_ROLES = frozenset({
    "root-control-record", "box-control-record", "image-build-record",
})
AGGREGATE_RECORD_ROLES = frozenset({"zog-record"})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_GIT = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[0-9a-f]{32,64}\Z")
_UNIT = re.compile(r"zog-[a-z0-9-]+\.service\Z")


class RuntimeHold(RuntimeError):
    """The selected service/build has not satisfied the native admission gate."""


def _exact(value, keys, title):
    if type(value) is not dict or set(value) != set(keys):
        raise RuntimeHold("invalid " + title)
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")).hexdigest()


def _hash(value, title):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise RuntimeHold("invalid " + title)
    return value


def _path(value, title):
    if (type(value) is not str or not value.startswith("/")
            or "\0" in value or len(value) > 1024
            or any(p in {"", ".", ".."} for p in value.split("/")[1:])
            or str(PurePosixPath(value)) != value):
        raise RuntimeHold("invalid " + title)
    return value


def _under(path, directory):
    return path.startswith(directory + "/")


def validate(selection):
    """Validate reviewed source pins and immutable install/rollback selection."""
    _exact(selection, {"schema", "contract", "release_id", "sources",
                       "service", "rollback", "files", "installed_tree_sha256",
                       "lane"}, "selection")
    if selection["schema"] != SCHEMA or selection["contract"] != CONTRACT:
        raise RuntimeHold("unsupported versioned inherited-identity contract")
    release = selection["release_id"]
    if type(release) is not str or _ID.fullmatch(release) is None:
        raise RuntimeHold("invalid immutable release identifier")
    folder = RELEASES + "/" + release
    sources = _exact(selection["sources"], COMPONENTS, "source selection")
    for role, source in sources.items():
        _exact(source, {"revision", "source_tree_sha256"}, role + " source")
        if type(source["revision"]) is not str or _GIT.fullmatch(source["revision"]) is None:
            raise RuntimeHold("invalid " + role + " immutable Git commit")
        _hash(source["source_tree_sha256"], role + " source tree")
        if source != SELECTED_SOURCES[role]:
            raise RuntimeHold("selected " + role + " source revision or tree SHA256 differs from pinned tuple")
    service = _exact(selection["service"], {"name", "staged_unit", "active_unit",
                                            "staged_sha256", "exec_start"},
                     "service selection")
    if type(service["name"]) is not str or _UNIT.fullmatch(service["name"]) is None:
        raise RuntimeHold("invalid controller service unit")
    if _path(service["staged_unit"], "staged unit") != (
            folder + "/systemd/" + service["name"]):
        raise RuntimeHold("staged unit is not owned by selected version")
    if _path(service["active_unit"], "active unit") != (
            UNIT_DIR + "/" + service["name"]):
        raise RuntimeHold("active service selection differs")
    _hash(service["staged_sha256"], "selected unit bytes")
    exe = _path(service["exec_start"], "selected executable")
    if not _under(exe, folder + "/bin"):
        raise RuntimeHold("service executable is not version-owned")
    rollback = _exact(selection["rollback"],
                      {"saved_unit", "unit_sha256", "saved_runtime_root",
                       "runtime_tree_sha256"}, "rollback selection")
    if (_path(rollback["saved_unit"], "rollback unit") !=
            ROLLBACK + "/" + release + "/" + service["name"]):
        raise RuntimeHold("rollback unit location differs")
    _hash(rollback["unit_sha256"], "rollback service bytes")
    saved_root = _path(rollback["saved_runtime_root"], "rollback runtime")
    if not _under(saved_root, ROLLBACK + "/" + release):
        raise RuntimeHold("old runtime must be retained in separate rollback custody")
    _hash(rollback["runtime_tree_sha256"], "rollback runtime inventory")
    if saved_root == folder or saved_root.startswith(folder + "/"):
        raise RuntimeHold("rollback runtime aliases selected version")
    lane = _exact(selection["lane"],
                  {"name", "specification_sha256", "enabled"}, "Fonts lane")
    if lane["name"] != "gateway-first-fonts-runtime" or lane["enabled"] is not False:
        raise RuntimeHold("Fonts lane must remain explicitly disabled")
    _hash(lane["specification_sha256"], "lane candidate specification")
    _hash(selection["installed_tree_sha256"], "selected version complete installed tree")
    files = selection["files"]
    if type(files) is not list or len(files) < len(REQUIRED_FILES) + 1 or len(files) > 4096:
        raise RuntimeHold("incomplete installed-byte inventory")
    seen_names, seen_paths = set(), set()
    for item in files:
        _exact(item, {"role", "path", "sha256", "size"}, "installed file")
        role = item["role"]
        if (type(role) is not str or not re.fullmatch(r"[a-z0-9-]{1,64}", role)
                or role in seen_names):
            raise RuntimeHold("duplicate or invalid installed file role")
        seen_names.add(role)
        path = _path(item["path"], "installed file path")
        if not _under(path, folder) or path in seen_paths:
            raise RuntimeHold("installed bytes are not independently versioned")
        seen_paths.add(path)
        if role in MODULE_PATH_SUFFIXES and not path.endswith(MODULE_PATH_SUFFIXES[role]):
            raise RuntimeHold("installed critical module path differs from selected component")
        if (role in SEPARATE_RECORD_ROLES | AGGREGATE_RECORD_ROLES
                and not path.endswith(".dist-info/RECORD")):
            raise RuntimeHold("installed RECORD role must name an actual distribution RECORD")
        _hash(item["sha256"], "installed file SHA256")
        if type(item["size"]) is not int or not 0 < item["size"] <= 512 * 1024 * 1024:
            raise RuntimeHold("invalid installed file length")
    if not REQUIRED_FILES.issubset(seen_names):
        raise RuntimeHold("controller/producer critical module closure is incomplete")
    record_roles = seen_names & (SEPARATE_RECORD_ROLES | AGGREGATE_RECORD_ROLES)
    if record_roles not in (SEPARATE_RECORD_ROLES, AGGREGATE_RECORD_ROLES):
        raise RuntimeHold("installed distribution RECORD closure is incomplete")
    return selection


def source_tree_sha256(source):
    """Immutable SHA256 inventory of a clean, tracked, regular Git checkout."""
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise RuntimeHold("selected source is not a real directory")
    try:
        def git(*args):
            return subprocess.check_output(
                ["git", "-C", str(source), *args],
                stderr=subprocess.DEVNULL, timeout=30)
        commit = git("rev-parse", "--verify", "HEAD").decode("ascii").strip()
        changed = git("status", "--porcelain=v1", "--untracked-files=all")
        paths = git("ls-files", "-z").split(bytes([0]))
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise RuntimeHold("cannot authenticate exact Git source checkout") from error
    if _GIT.fullmatch(commit) is None or changed:
        raise RuntimeHold("source Git revision unavailable or checkout is dirty")
    inventory = []
    for raw in paths:
        if not raw:
            continue
        try:
            rel = raw.decode("utf-8")
        except UnicodeError as error:
            raise RuntimeHold("non-UTF8 tracked source path") from error
        if (not rel or rel.startswith("/") or "\0" in rel
                or any(part in {"", ".", ".."} for part in rel.split("/"))):
            raise RuntimeHold("unsafe tracked source path")
        file = source / rel
        if any(parent.is_symlink() for parent in file.parents if parent != source.parent):
            raise RuntimeHold("linked tracked source ancestor")
        info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024 * 1024:
            raise RuntimeHold("tracked source file is linked or nonregular")
        raw_bytes = file.read_bytes()
        if len(raw_bytes) != info.st_size:
            raise RuntimeHold("tracked source changed during SHA256 review")
        inventory.append({"path": rel, "size": len(raw_bytes),
                          "sha256": hashlib.sha256(raw_bytes).hexdigest()})
    if not inventory:
        raise RuntimeHold("selected Git source is empty")
    return {"revision": commit, "source_tree_sha256": _digest(inventory)}


def inspect_sources(selection, checkouts):
    """Verify all three exact clean source revisions and tracked byte trees."""
    validate(selection)
    _exact(checkouts, COMPONENTS, "source checkout selection")
    if len({str(Path(path).resolve()) for path in checkouts.values()}) != 3:
        raise RuntimeHold("controller and producer sources must be distinct")
    for role in sorted(COMPONENTS):
        if source_tree_sha256(checkouts[role]) != selection["sources"][role]:
            raise RuntimeHold("reviewed " + role + " source revision or SHA256 differs")
    return {"schema": SCHEMA, "status": "exact-source-bytes-verified",
            "selection_sha256": selection_sha256(selection),
            "execution_authorized": False}


def selection_sha256(selection):
    return _digest(validate(selection))


def selection_bytes(selection):
    """Deterministic reviewed selection; raw file digest remains separate."""
    return (json.dumps(validate(selection), sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + chr(10)).encode("ascii")


def load_reviewed_selection(path, expected_sha256):
    """Root-owned reviewed input; exact external selection hash is required.

    This only establishes the integrity of a locally selected manifest, not
    permission to change a unit, send a build or assert an authenticated peer.
    """
    _hash(expected_sha256, "externally approved selection SHA256")
    path = _path(path, "selection manifest")
    if not _under(path, SELECTIONS) or not path.endswith(".json"):
        raise RuntimeHold("selection must reside in protected local custody")
    for parent in reversed(Path(path).parents):
        if parent.is_symlink():
            raise RuntimeHold("linked selection manifest ancestor")
        if parent == Path(SELECTIONS):
            info = parent.stat()
            if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
                raise RuntimeHold("reviewed selection directory is not root-protected")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or info.st_nlink != 1
                    or info.st_mode & 0o022 or not 0 < info.st_size <= 1024 * 1024):
                raise RuntimeHold("selected manifest has unsafe ownership or size")
            raw = os.read(fd, info.st_size + 1)
            if len(raw) != info.st_size:
                raise RuntimeHold("selected manifest changed during inspection")
        finally:
            os.close(fd)
    except OSError as error:
        raise RuntimeHold("cannot read reviewed local selection") from error
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeHold("selected manifest bytes differ from externally approved digest")
    try:
        selected = validate(json.loads(raw))
        if raw != selection_bytes(selected):
            raise RuntimeHold("reviewed selection file is not canonical")
        if Path(path).name != selected["release_id"] + ".json":
            raise RuntimeHold("reviewed selection filename differs from release")
        return selected
    except (ValueError, UnicodeError, TypeError, KeyError) as error:
        raise RuntimeHold("invalid reviewed runtime selection JSON") from error


def _read_fixed(path, expected_hash, expected_size=None):
    """Read installed regular bytes without following the final path or parents."""
    path = Path(path)
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise RuntimeHold("linked installed path ancestor: " + str(parent))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise RuntimeHold("installed object is not immutable root-owned regular file: " + str(path))
            if (expected_size is not None and info.st_size != expected_size):
                raise RuntimeHold("installed file length differs: " + str(path))
            if info.st_size > 512 * 1024 * 1024 or info.st_size == 0:
                raise RuntimeHold("unbounded or empty installed file: " + str(path))
            h = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise RuntimeHold("installed byte read truncated: " + str(path))
                h.update(chunk)
                remaining -= len(chunk)
            if h.hexdigest() != expected_hash:
                raise RuntimeHold("installed SHA256 differs: " + str(path))
            return info
        finally:
            os.close(fd)
    except (OSError, ValueError) as error:
        raise RuntimeHold("cannot verify installed bytes: " + str(path)) from error


def _retained_tree_inventory(root):
    """Inventory every retained regular byte; reject links or writable roots.

    The rollback image is an independent byte-preserved directory snapshot,
    not just a recorded digest or a link to the selected live runtime.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeHold("rollback runtime directory is absent or linked")
    for parent in reversed(root.parents):
        if parent.is_symlink():
            raise RuntimeHold("linked rollback runtime ancestor")
    inventory = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        current = Path(current)
        for directory in [current] + [current / name for name in directories]:
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or info.st_mode & 0o022):
                raise RuntimeHold("rollback directory is not protected root-owned")
        inventory.append({"type": "directory",
                          "path": current.relative_to(root).as_posix(),
                          "mode": stat.S_IMODE(current.lstat().st_mode)})
        for name in files:
            file = current / name
            info = file.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != 0 or info.st_gid != 0
                    or info.st_mode & 0o022 or info.st_size > 512 * 1024 * 1024):
                raise RuntimeHold("rollback has unsafe or linked file")
            data = file.read_bytes()
            if len(data) != info.st_size:
                raise RuntimeHold("rollback bytes changed during inventory")
            inventory.append({
                "type": "file", "path": file.relative_to(root).as_posix(),
                "mode": stat.S_IMODE(info.st_mode),
                "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            })
    if not any(entry["type"] == "file" for entry in inventory):
        raise RuntimeHold("rollback runtime inventory is empty")
    return inventory


def _retained_tree_sha256(root):
    return _digest(_retained_tree_inventory(root))


def capture_installed_inventory(release_id):
    """Read-only, root-owned evidence from a *real* staged versioned runtime.

    Do not assume module/RECORD paths or invent installed hashes before they
    exist. The output is a candidate for separate immutable source/installer
    review; it is not an approved selection or compilation authorization.
    """
    if os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeHold("installed runtime inventory requires trusted root owner")
    if type(release_id) is not str or _ID.fullmatch(release_id) is None:
        raise RuntimeHold("invalid installed immutable version ID")
    root = Path(RELEASES) / release_id
    inventory = _retained_tree_inventory(root)
    required_modules = {
        "root-control-module": "/zog/root_control/build.py",
        "box-control-module": "/zog/box_control/build_jobs.py",
        "image-build-module": "/zog/image_build/box_control_adapter.py",
    }
    selected = {}
    for role, suffix in required_modules.items():
        matches = [record for record in inventory
                   if record["type"] == "file"
                   and record["path"].endswith(suffix.lstrip("/"))
                   and ("/" + record["path"]).endswith(suffix)]
        if len(matches) != 1:
            raise RuntimeHold("installed " + role + " is missing or ambiguous")
        selected[role] = matches[0]
    records = [record for record in inventory
               if record["type"] == "file"
               and record["path"].endswith(".dist-info/RECORD")]
    if not records:
        raise RuntimeHold("installed distribution RECORD absent")
    # The integrated 'zog' distribution may have one aggregate RECORD, while
    # separately packaged components have multiple RECORDs. Neither form
    # is presumed until exact installed bytes and dependency closure exist.
    return {
        "schema": "zog-first-fonts-staged-installed-inventory-v1",
        "release_id": release_id,
        "sources": SELECTED_SOURCES,
        "installed_tree_sha256": _digest(inventory),
        "modules": {
            role: {"path": str(root / file["path"]), "size": file["size"],
                   "sha256": file["sha256"]}
            for role, file in sorted(selected.items())
        },
        "records": [
            {"path": str(root / file["path"]), "size": file["size"],
             "sha256": file["sha256"]}
            for file in records
        ],
        "file_count": sum(entry["type"] == "file" for entry in inventory),
        "complete_runtime_inventory": inventory,
        "independently_reviewed": False,
        "execution_authorized": False,
        "fonts_lane_enabled": False,
    }


def verify_module_record_bindings(selection):
    """Verify each pinned critical module is attested inside its installed RECORD.

    A matching RECORD *file hash* alone is insufficient: a stale RECORD could
    describe different installed modules. Both combined Zog and distinct
    component distributions are supported, but partial/mixed records HOLD.
    """
    validate(selection)
    named = {entry["role"]: entry for entry in selection["files"]}
    aggregate = named.get("zog-record")
    for module_role, suffix in MODULE_PATH_SUFFIXES.items():
        module = named[module_role]
        record_role = "zog-record" if aggregate else module_role.removesuffix("-module") + "-record"
        record = named[record_role]
        record_path = Path(record["path"])
        site = record_path.parent.parent
        module_path = Path(module["path"])
        try:
            relative = module_path.relative_to(site).as_posix()
        except ValueError as error:
            raise RuntimeHold(module_role + " is outside its distribution's site-packages") from error
        if not relative.endswith(suffix.lstrip("/")):
            raise RuntimeHold(module_role + " RECORD path is foreign")
        _read_fixed(record["path"], record["sha256"], record["size"])
        try:
            rows = list(csv.reader(io.StringIO(record_path.read_text(encoding="utf-8"))))
        except (OSError, UnicodeError, csv.Error) as error:
            raise RuntimeHold("cannot parse installed distribution RECORD") from error
        matches = [row for row in rows if row and row[0] == relative]
        encoded = base64.urlsafe_b64encode(
            bytes.fromhex(module["sha256"])).decode("ascii").rstrip("=")
        if (len(matches) != 1 or len(matches[0]) != 3
                or matches[0][1] != "sha256=" + encoded
                or matches[0][2] != str(module["size"])):
            raise RuntimeHold("installed " + module_role + " differs from distribution RECORD")
    return True


def inspect_installed(selection, *, phase="staged"):
    """Read only. Require old unit live before switch, selected unit after switch.

    This function does not run systemctl, create a unit, switch its target,
    start/stop a service or authorize a build.
    """
    validate(selection)
    if phase not in {"staged", "selected"}:
        raise RuntimeHold("unknown service selection phase")
    service, rollback = selection["service"], selection["rollback"]
    _read_fixed(service["staged_unit"], service["staged_sha256"])
    old = _read_fixed(rollback["saved_unit"], rollback["unit_sha256"])
    current = _read_fixed(service["active_unit"], rollback["unit_sha256"]
                          if phase == "staged" else service["staged_sha256"])
    if (old.st_dev, old.st_ino) == (current.st_dev, current.st_ino):
        raise RuntimeHold("rollback unit hardlinked to active service")
    if _retained_tree_sha256(rollback["saved_runtime_root"]) != rollback["runtime_tree_sha256"]:
        raise RuntimeHold("retained previous runtime bytes differ")
    unit = Path(service["staged_unit"]).read_bytes()
    commands = [line for line in unit.splitlines()
                if line.strip().startswith(b"ExecStart=")]
    if len(commands) != 1 or commands[0] != (
            b"ExecStart=" + service["exec_start"].encode("utf-8")):
        raise RuntimeHold("installed controller ExecStart differs from selected release")
    executable = [f for f in selection["files"]
                  if f["path"] == service["exec_start"]]
    if len(executable) != 1:
        raise RuntimeHold("selected ExecStart executable absent from installed-byte inventory")
    for item in selection["files"]:
        _read_fixed(item["path"], item["sha256"], item["size"])
    verify_module_record_bindings(selection)
    selected_root = RELEASES + "/" + selection["release_id"]
    if _retained_tree_sha256(selected_root) != selection["installed_tree_sha256"]:
        raise RuntimeHold("selected full installed tree differs from reviewed bytes")
    # Full selected and retained runtime tree bytes are independently read
    # back, in addition to each named module/RECORD and service unit.
    return {"schema": SCHEMA, "status": "installed-byte-selection-verified",
            "phase": phase, "release_id": selection["release_id"],
            "selection_sha256": selection_sha256(selection),
            "source_revisions": {k: v["revision"] for k, v in selection["sources"].items()},
            "rollback_preserved": True, "fonts_lane_enabled": False,
            "child_identity_verified": False, "execution_authorized": False}


def inspect_child_identity(selection, *, pid, peer_uid, peer_gid, unit_cgroup,
                           proc_root="/proc"):
    """Native witness only; kernel /proc child identity is not SSM caller identity.

    peer_uid/gid MUST come from root-control's authenticated SO_PEERCRED and
    bound registration, never from a user-supplied request or root SSM UID.
    This returns *evidence*, not build authorization; the trusted root owner
    must independently attest the peer and unchanged cgroup/operation.
    """
    validate(selection)
    if (type(pid) is not int or pid <= 1 or type(peer_uid) is not int
            or type(peer_gid) is not int or peer_uid <= 0 or peer_gid <= 0
            or type(unit_cgroup) is not str or not unit_cgroup.startswith("/")
            or ".." in unit_cgroup.split("/") or not unit_cgroup.endswith(".service")):
        raise RuntimeHold("missing nonroot peer or authenticated unit binding")
    proc = Path(proc_root) / str(pid)
    def read():
        status = (proc / "status").read_text()
        values = {}
        for line in status.splitlines():
            if line.startswith("Uid:") or line.startswith("Gid:"):
                key, body = line.split(":", 1)
                nums = body.strip().split()
                if len(nums) != 4 or not all(v.isdigit() for v in nums):
                    raise RuntimeHold("unusable kernel child credential readback")
                values[key] = tuple(map(int, nums))
        if set(values) != {"Uid", "Gid"}:
            raise RuntimeHold("missing kernel child UID/GID")
        stat_line = (proc / "stat").read_text()
        right = stat_line.rfind(")")
        if right < 0 or not stat_line[:right].startswith(str(pid) + " ("):
            raise RuntimeHold("child process stat identity differs")
        fields = stat_line[right + 1:].split()
        if len(fields) <= 19 or not fields[19].isdigit():
            raise RuntimeHold("missing kernel child start time")
        cgroups = (proc / "cgroup").read_text().splitlines()
        if not any(line.split(":", 2)[-1] == unit_cgroup
                   for line in cgroups if line.count(":") == 2):
            raise RuntimeHold("child cgroup differs from authenticated systemd unit")
        return values, fields[19]
    try:
        first, started = read()
        second, started_again = read()
    except OSError as error:
        raise RuntimeHold("cannot observe live compiler child") from error
    if first != second or started != started_again:
        raise RuntimeHold("compiler child identity changed during observation")
    uid, gid = first["Uid"][1], first["Gid"][1]
    if (any(value != peer_uid for value in first["Uid"])
            or any(value != peer_gid for value in first["Gid"])
            or uid == 0 or gid == 0):
        raise RuntimeHold("actual compiler child is root or not bound to authenticated nonroot peer")
    return {"schema": "zog-fonts-inherited-child-observation-v1",
            "status": "kernel-child-identity-verified",
            "selection_sha256": selection_sha256(selection),
            "pid": pid, "start_time_ticks": started,
            "effective_uid": uid, "effective_gid": gid, "unit_cgroup": unit_cgroup,
            "root_compilation_allowed": False,
            "execution_authorized": False}
