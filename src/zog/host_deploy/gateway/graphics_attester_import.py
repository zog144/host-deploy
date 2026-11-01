"""Root-installed, immutable Python import boundary for graphical acceptance.

Git HEAD and worktree checks are provenance hints, never root import authority.
Only an independently installed 0600 policy and fully root-owned, non-writable,
non-symlinked import tree may be used by the privileged attester. No mutable
Project checkout or project virtualenv is executed with EUID 0.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "host-deploy-graphical-attester-import-v1"
POLICY = "/etc/zog/host-deploy/graphical-attester-import-v1.json"
SNAPSHOT = "/usr/lib/zog/graphical-attester/"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_FILES = 20000
MAX_BYTES = 2 * 1024**3


class ImportBoundaryBlocked(RuntimeError):
    pass


def _deny():
    raise ImportBoundaryBlocked("root-graphical-attester-import-not-immutable")


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _protected(path, *, directory=False, mode=None):
    """No-follow the *entire* root-owned, non-writable path, not Path.resolve()."""
    if (type(path) is not str or not path.startswith("/") or
            ".." in Path(path).parts or not path.startswith(("/",))):
        _deny()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for i, component in enumerate(parts):
            last = i == len(parts)-1
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if not last or directory:
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=fd)
            info = os.fstat(child)
            if (info.st_uid != 0 or info.st_mode & 0o022 or
                    (not last or directory) != stat.S_ISDIR(info.st_mode)):
                os.close(child)
                _deny()
            if last and (info.st_nlink != 1 and not directory or
                         mode is not None and stat.S_IMODE(info.st_mode) != mode):
                os.close(child)
                _deny()
            os.close(fd)
            fd = child
        return fd
    except OSError:
        _deny()
    finally:
        # Caller owns fd only on successful return.
        if "last" not in locals() or i != len(parts)-1:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_policy():
    fd = _protected(POLICY, mode=0o600)
    try:
        st = os.fstat(fd)
        if not 0 < st.st_size <= 8192:
            _deny()
        raw = os.read(fd, 8193)
    finally:
        os.close(fd)
    def unique(pairs):
        data = {}
        for k, v in pairs:
            if k in data:
                _deny()
            data[k] = v
        return data
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _deny())
    except (ValueError, UnicodeError, TypeError):
        _deny()


def _inventory(root):
    """Include every file (including ignored and dotfiles); deny link and races."""
    records = []
    total = 0

    def walk(current, relative):
        nonlocal total
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError:
            _deny()
        for entry in entries:
            name = entry.name
            path = relative + "/" + name if relative else name
            if len(records) >= MAX_FILES or len(path) > 2048:
                _deny()
            try:
                st = entry.stat(follow_symlinks=False)
                if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
                    _deny()
                if stat.S_ISDIR(st.st_mode):
                    records.append(["d", path, stat.S_IMODE(st.st_mode), st.st_dev, st.st_ino])
                    walk(entry.path, path)
                elif stat.S_ISREG(st.st_mode):
                    total += st.st_size
                    if total > MAX_BYTES or st.st_size < 0 or st.st_nlink != 1:
                        _deny()
                    fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        actual = os.fstat(fd)
                        if (actual.st_dev, actual.st_ino, actual.st_size,
                            actual.st_mtime_ns) != (
                            st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns):
                            _deny()
                        digest = hashlib.sha256()
                        while True:
                            chunk = os.read(fd, 1024*1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                        final = os.fstat(fd)
                        if (final.st_size, final.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                            _deny()
                        records.append(["f", path, stat.S_IMODE(st.st_mode),
                                        st.st_dev, st.st_ino, digest.hexdigest()])
                    finally:
                        os.close(fd)
                else:
                    _deny()
            except OSError:
                _deny()
    walk(root, "")
    return records


def verify(*, source_revision, monthly_pin_identity):
    """Return root-pinned interpreter and module roots after whole-tree check."""
    pin = _read_policy()
    if (type(pin) is not dict or set(pin) != {
            "schema", "source_revision", "monthly_pin_identity",
            "python", "python_sha256", "module_roots", "tree_sha256"
        } or pin["schema"] != SCHEMA
        or not isinstance(source_revision, str)
        or not _COMMIT.fullmatch(source_revision)
        or pin["source_revision"] != source_revision
        or pin["monthly_pin_identity"] != monthly_pin_identity
        or type(pin["python"]) is not str
        or type(pin["python_sha256"]) is not str
        or not _SHA.fullmatch(pin["python_sha256"])
        or type(pin["tree_sha256"]) is not str
        or not _SHA.fullmatch(pin["tree_sha256"])
        or type(pin["module_roots"]) is not list
        or not 2 <= len(pin["module_roots"]) <= 4
        or len(set(map(str, pin["module_roots"]))) != len(pin["module_roots"])):
        _deny()
    binary = _protected(pin["python"])
    try:
        info = os.fstat(binary)
        if (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111):
            _deny()
        digest = hashlib.sha256()
        while True:
            chunk = os.read(binary, 1024*1024)
            if not chunk:
                break
            digest.update(chunk)
        if "sha256:" + digest.hexdigest() != pin["python_sha256"]:
            _deny()
    finally:
        os.close(binary)

    inventories = []
    for path in pin["module_roots"]:
        if (type(path) is not str or not path.startswith(SNAPSHOT)
                or Path(path).is_symlink()):
            _deny()
        fd = _protected(path, directory=True)
        os.close(fd)
        inventories.append([path, _inventory(path)])
    # Including inode identities in the protected inventory detects path-swap
    # between the first verification and process completion.
    if "sha256:" + hashlib.sha256(_canonical(inventories)).hexdigest() != pin["tree_sha256"]:
        _deny()
    return pin


BOOTSTRAP = (
    "import sys,runpy;"
    "sys.path[:0]=__import__('json').loads(sys.argv.pop(1));"
    "runpy.run_module('zog.image_build.graphical_generation_acceptance',"
    "run_name='__main__')"
)


def command(pin, arguments):
    """Use -I/-S; never inherit mutable PYTHONPATH, site or cwd imports."""
    if type(arguments) is not list or any(type(x) is not str for x in arguments):
        _deny()
    return [pin["python"], "-I", "-S", "-B", "-c", BOOTSTRAP,
            json.dumps(pin["module_roots"], separators=(",", ":")), *arguments]
