"""Fixed host-only Project/state binding for the fresh compiler lane.

root-control's BuildBackend.register() requires build roots and source/output
under <Project>/state/image-build/attempts. The prepared 30-GiB quota image
is mounted at <Project>/work. Without an independently verified *real* bind
mount at <Project>/state, the producer can create unaccounted host files.

This module binds only that one initially empty dedicated Project directory.
It never touches old Projects or historic controller mounts. Preparation is
single-attempt and requires reviewed root-owned installer state. Neither this
bind nor a source assertion proves every worker's PrivateTmp/other writes;
aggregate admission MUST continue to refuse unverified worker mounts.
"""
import os
from pathlib import Path
import re
import stat
import subprocess

from . import fresh_quota_volume as quota

PROJECT_ROOT = quota.MOUNT.parent
SOURCE = quota.MOUNT / "state"
DESTINATION = PROJECT_ROOT / "state"
ATTEMPT = "project-state-bind-attempt.json"
SCHEMA = "host-deploy-fresh-project-state-bind-v1"
_LOOP_SOURCE = re.compile(r"/dev/loop[0-9]+\\[/state\\]\\Z")


def _command(argv):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=15,
        env={"PATH": "/usr/sbin:/usr/bin:/bin:/sbin", "LC_ALL": "C"},
    ).stdout.strip()


def _directory(path, uid, *, empty=False):
    path = Path(path)
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or path.is_symlink()
            or st.st_uid != uid or st.st_mode & 0o077
            or path.resolve(strict=True) != path):
        raise PermissionError("fresh Project state directory is not protected")
    if empty and any(path.iterdir()):
        raise PermissionError("fresh Project state mount target is not empty")
    return st


def inspect(controller_uid):
    """Kernel-backed host mount readback; not a worker namespace assertion."""
    if type(controller_uid) is not int or controller_uid < 1:
        raise PermissionError("fresh controller UID required")
    image = quota.inspect()
    project = _directory(PROJECT_ROOT, controller_uid)
    src = _directory(SOURCE, controller_uid)
    dst = _directory(DESTINATION, controller_uid)
    if (src.st_dev != dst.st_dev or src.st_ino != dst.st_ino
            or src.st_dev != quota.MOUNT.stat().st_dev):
        raise RuntimeError("Project state escaped the quota image")
    result = _command([
        "/usr/bin/findmnt", "-rn", "--mountpoint", str(DESTINATION),
        "-o", "TARGET,SOURCE,FSTYPE,MAJ:MIN",
    ]).split()
    if (len(result) != 4 or result[0] != str(DESTINATION)
            or not _LOOP_SOURCE.fullmatch(result[1])
            or result[1].split("[", 1)[0] != image["backing_device"]
            or result[2] != "ext4"
            or result[3] != f"{os.major(src.st_dev)}:{os.minor(src.st_dev)}"):
        raise RuntimeError("Project state has no exact kernel quota bind mount")
    # Host-side nested mounts can redirect a writer to another device. Actual
    # worker-private mount namespaces still require independent PID inspection.
    mounts = _command([
        "/usr/bin/findmnt", "-rn", "--submounts", str(DESTINATION),
        "-o", "TARGET",
    ]).splitlines()
    if mounts != [str(DESTINATION)]:
        raise RuntimeError("Project state contains a foreign nested mount")
    return {"schema": SCHEMA, "project_root": str(PROJECT_ROOT),
            "source": str(SOURCE), "destination": str(DESTINATION),
            "controller_uid": controller_uid, "mount_verified": True,
            "device": result[3], "inode": src.st_ino,
            "image_bytes": image["image_bytes"]}


def install_bind(controller_uid):
    """One-shot binding; fsync attempted intent before the mount syscall.

    Pre-created empty Project/state must belong to the isolated controller UID.
    An uncertain mount reply requires inspection, not a second blind mount.
    """
    if os.geteuid() != 0:
        raise PermissionError("protected host installer required")
    from . import fresh_native_owner as owner
    owner._root()
    if type(controller_uid) is not int or controller_uid < 1:
        raise PermissionError("fixed controller identity required")
    _directory(PROJECT_ROOT, controller_uid)
    _directory(DESTINATION, controller_uid, empty=True)
    if SOURCE.exists() or SOURCE.is_symlink():
        raise RuntimeError("Project state source already exists; inspect only")
    if owner._show(owner.sidecar.UNIT).get("LoadState") != "not-found":
        raise RuntimeError("cannot overlay active/uncertain controller Project")
    quota.inspect()
    SOURCE.mkdir(mode=0o700)
    os.chown(SOURCE, controller_uid, -1)
    _directory(SOURCE, controller_uid, empty=True)
    marker = owner.STATE / ATTEMPT
    if marker.exists() or marker.is_symlink():
        raise RuntimeError("Project state bind already attempted")
    owner._store(marker, {
        "schema": SCHEMA, "boot_id": owner._boot(),
        "source": str(SOURCE), "destination": str(DESTINATION),
        "controller_uid": controller_uid, "state": "attempted",
    }, exclusive=True)
    _command(["/usr/bin/mount", "--bind", str(SOURCE), str(DESTINATION)])
    return inspect(controller_uid)
