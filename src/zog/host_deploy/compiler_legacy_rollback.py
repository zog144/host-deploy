"""Literal-link legacy compiler rollback inventory (never for selected releases)."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat

SCHEMA = "zog-compiler-legacy-rollback-inventory-v1"
LINKS = {
    "venv/lib64": "lib",
    "venv/bin/python": "python3.12",
    "venv/bin/python3": "python3.12",
    "venv/bin/python3.12": "/usr/bin/python3.12",
}
EXTERNAL_PYTHON = "/usr/bin/python3.12"
MAX_SIZE = 512 * 1024 * 1024


class LegacyHold(RuntimeError):
    pass


def need(ok, message):
    if not ok:
        raise LegacyHold(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                        separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def _owner(info, root):
    need(not info.st_mode & 0o022, "writable legacy runtime object")
    if root == Path("/"):
        need(info.st_uid == info.st_gid == 0, "foreign legacy runtime object")


def _sha_file(path, info):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         0 < info.st_size <= MAX_SIZE, "hard-linked, empty or oversized runtime file")
    sha = hashlib.sha256()
    count = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            count += len(chunk)
            need(count <= info.st_size, "runtime file changed during read")
            sha.update(chunk)
    need(count == info.st_size, "runtime file changed during read")
    return {"size": count, "sha256": sha.hexdigest()}


def _absolute_target(path, target):
    need(target and "\0" not in target and
         not any(piece == ".." for piece in Path(target).parts),
         "escaping or invalid symlink target")
    return Path(target) if target.startswith("/") else path.parent / target


def interpreter_chain(root=Path("/")):
    """Attest each literal external interpreter link and final regular bytes."""
    root = Path(root).absolute()
    current = Path(EXTERNAL_PYTHON)
    seen = set()
    result = []
    for _ in range(16):
        need(str(current) not in seen, "external interpreter link cycle")
        seen.add(str(current))
        observed = root / current.relative_to("/")
        try:
            info = observed.lstat()
        except OSError as error:
            raise LegacyHold("external Python interpreter unavailable") from error
        _owner(info, root)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(observed)
            nxt = _absolute_target(current, target)
            need(nxt.is_absolute() and nxt != current,
                 "external interpreter target is unsafe")
            result.append({"path": str(current), "type": "symlink",
                           "target": target, "uid": info.st_uid if root == Path("/") else 0,
                           "gid": info.st_gid if root == Path("/") else 0})
            current = nxt
        else:
            record = _sha_file(observed, info)
            result.append({"path": str(current), "type": "file",
                           "mode": stat.S_IMODE(info.st_mode),
                           "uid": info.st_uid if root == Path("/") else 0,
                           "gid": info.st_gid if root == Path("/") else 0,
                           **record})
            return result
    raise LegacyHold("external interpreter symlink chain too long")


def inventory(root, runtime, *, external=None):
    """Non-following canonical inventory; only four known legacy links allowed."""
    root = Path(root).absolute()
    runtime = Path(runtime)
    need(runtime.is_dir() and not runtime.is_symlink(), "missing legacy runtime")
    entries = []
    observed_links = {}
    for folder, dirs, files in os.walk(runtime, followlinks=False):
        dirs.sort()
        files.sort()
        current = Path(folder)
        info = current.lstat()
        need(stat.S_ISDIR(info.st_mode), "linked legacy runtime directory")
        _owner(info, root)
        entries.append({"type": "directory",
                        "path": current.relative_to(runtime).as_posix(),
                        "mode": stat.S_IMODE(info.st_mode)})
        for name in list(dirs) + files:
            item = current / name
            st = item.lstat()
            rel = item.relative_to(runtime).as_posix()
            _owner(st, root)
            if stat.S_ISLNK(st.st_mode):
                need(rel in LINKS, "unexpected legacy runtime symlink")
                target = os.readlink(item)
                need(target == LINKS[rel], "legacy symlink target differs")
                target_path = _absolute_target(item, target)
                if target.startswith("/"):
                    need(rel == "venv/bin/python3.12" and
                         target == EXTERNAL_PYTHON, "unapproved absolute runtime link")
                else:
                    need(target_path.is_relative_to(runtime), "escaping relative symlink")
                observed_links[rel] = target
                entries.append({"type": "symlink", "path": rel, "target": target})
                if name in dirs:
                    dirs.remove(name)
            elif stat.S_ISDIR(st.st_mode):
                need(name in dirs, "unlisted legacy directory")
            else:
                need(stat.S_ISREG(st.st_mode), "special legacy runtime entry")
                entries.append({"type": "file", "path": rel,
                                "mode": stat.S_IMODE(st.st_mode),
                                **_sha_file(item, st)})
    # Check local link graph without invoking Path.resolve / dereferencing it.
    for rel, target in observed_links.items():
        if not target.startswith("/"):
            current = (Path(rel).parent / target).as_posix()
            visited = {rel}
            while current in observed_links:
                need(current not in visited, "legacy runtime link cycle")
                visited.add(current)
                nxt = observed_links[current]
                if nxt.startswith("/"):
                    break
                current = (Path(current).parent / nxt).as_posix()
            need((runtime / current).exists() or current in observed_links,
                 "legacy relative symlink target missing")
    chain = interpreter_chain(root) if external is None else external
    need(type(chain) is list and len(chain) > 0, "missing external interpreter attestation")
    payload = {"schema": SCHEMA, "entries": entries,
               "python_interpreter_chain": chain}
    return {"schema": SCHEMA, "tree_sha256": digest(entries),
            "python_interpreter_chain": chain, "inventory_sha256": digest(payload)}


def assert_copy(root, original, copied, *, expected=None):
    first = inventory(root, original)
    second = inventory(root, copied)
    need(first == second, "legacy rollback copy differs from original")
    if expected is not None:
        need(first == expected, "legacy rollback differs from reviewed selection")
    return first
