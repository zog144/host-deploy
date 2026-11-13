"""Read-only access probe for a compiler running as its effective process principal.

This MUST execute *inside the actual nonroot compiler/controller process*, not
through a root-owned SSM installation or an impersonating helper. No passwd,
NSS, setuid, setgroups, sudo, su or ownership-repair behavior exists here.
"""
import os
from pathlib import Path
import stat


def inspect(project_root):
    if not isinstance(project_root, str) or not project_root.startswith("/"):
        raise ValueError("compiler project path must be absolute")
    root = Path(project_root)
    if str(root) != project_root or ".." in root.parts or "//" in project_root:
        raise ValueError("compiler project path must be normalized")
    uid, gid = os.geteuid(), os.getegid()
    # A privileged installer or root SSM process is NOT a substitute for a
    # working nonroot compiler. Do not weaken the root-control boundary.
    if uid == 0 or gid == 0:
        raise PermissionError("compiler must run as its existing nonroot effective process principal")
    if root == Path("/"):
        raise ValueError("filesystem root is not a compiler project")
    existing = root
    missing = []
    while True:
        try:
            info = existing.lstat()
        except FileNotFoundError:
            missing.append(existing.name)
            if existing == existing.parent:
                raise RuntimeError("no existing parent for compiler Project")
            existing = existing.parent
            continue
        if not stat.S_ISDIR(info.st_mode) or existing.is_symlink():
            raise PermissionError("compiler Project ancestor is not a real directory: " + str(existing))
        break
    # Check traversal of *every* existing ancestor; testing only the leaf
    # allows inaccessible parents to be silently accepted.
    for directory in (*reversed(existing.parents), existing):
        if directory.is_symlink() or not directory.is_dir():
            raise PermissionError("compiler Project ancestor changed: " + str(directory))
        if not os.access(directory, os.X_OK, effective_ids=True):
            raise PermissionError("effective process cannot traverse compiler Project ancestor: " + str(directory))
    if missing:
        if not os.access(existing, os.W_OK | os.X_OK, effective_ids=True):
            raise PermissionError("effective process cannot create compiler Project under: " + str(existing))
    elif not os.access(root, os.R_OK | os.W_OK | os.X_OK, effective_ids=True):
        raise PermissionError("effective process cannot read/write/traverse compiler Project: " + str(root))
    return {"project_root": project_root, "effective_uid": uid,
            "effective_gid": gid, "status": "can-create" if missing else "accessible",
            "principal": "effective-process", "identity_override": False}
