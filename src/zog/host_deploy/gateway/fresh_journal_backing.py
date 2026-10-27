"""Trusted host-only journal namespace backing gate (systemd 252).

A LogNamespace is routing, NEVER a disk quota. Fixed persistent and volatile
journal paths MUST both be exact bind mounts from the preallocated 2-GiB
external filesystem *before* any fresh unit can activate the namespace.
This module never starts/stops journald, reloads PID1 or touches default
journal paths. Host PID1 messages and foreign writes remain separately gated.
"""
import os
from pathlib import Path
import re
import stat
import subprocess

from .fresh_sidecar_install import LOG_NAMESPACE
from .fresh_aggregate_disk import EXTERNAL_MOUNT

MACHINE_ID = Path("/etc/machine-id")
JOURNAL_SOURCE = Path(EXTERNAL_MOUNT) / "systemd-journal"
VOLATILE_SOURCE = JOURNAL_SOURCE / "volatile"
JOURNAL_SERVICE = f"systemd-journald@{LOG_NAMESPACE}.service"
JOURNAL_SOCKETS = (
    f"systemd-journald@{LOG_NAMESPACE}.socket",
    f"systemd-journald-varlink@{LOG_NAMESPACE}.socket",
)
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def targets():
    machine = MACHINE_ID.read_text(encoding="ascii").strip()
    if not _HEX32.fullmatch(machine):
        raise RuntimeError("journal namespace machine identity is invalid")
    leaf = machine + "." + LOG_NAMESPACE
    return (Path("/var/log/journal") / leaf,
            Path("/run/log/journal") / leaf)


def _mount_points():
    # Kernel mountinfo distinguishes a real bind mount from a same-device
    # directory. Do not infer a bind merely from st_dev equality.
    from .fresh_quota_volume import _run
    text = _run(["/usr/bin/findmnt", "-rn", "-o",
                 "TARGET,SOURCE,FSTYPE,MAJ:MIN"])
    mounts = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 4:
            raise RuntimeError("unparseable live kernel mount inventory")
        mounts[fields[0]] = fields[1:]
    return mounts


def inspect():
    """Return only trusted actual backing. Never mark a missing mount valid."""
    # This is a read-only native proof, not permission to perform a mount.
    persistent, volatile = targets()
    source = JOURNAL_SOURCE
    volatile_source = VOLATILE_SOURCE
    mounts = _mount_points()
    fs_dev = Path(EXTERNAL_MOUNT).stat().st_dev
    for src, dst in ((source, persistent), (volatile_source, volatile)):
        st = src.lstat()
        dest = dst.lstat()
        if (not stat.S_ISDIR(st.st_mode) or not stat.S_ISDIR(dest.st_mode)
                or src.is_symlink() or dst.is_symlink()
                or st.st_dev != fs_dev or dest.st_dev != fs_dev
                or st.st_ino != dest.st_ino
                or str(dst) not in mounts):
            raise RuntimeError("journal namespace has unbounded fallback path")
        dst_info = mounts[str(dst)]
        if (len(dst_info) != 3 or dst_info[1] != "ext4"
                or not dst_info[0].startswith("/dev/loop")
                or dst_info[2] != mounts[str(EXTERNAL_MOUNT)][2]):
            raise RuntimeError("journal namespace mount is not from bounded pool")
    return {
        "namespace": LOG_NAMESPACE,
        "persistent_path": str(persistent),
        "volatile_path": str(volatile),
        "external_pool": EXTERNAL_MOUNT,
        "verified": True,
    }


def install_binds_before_activation():
    """Fixed one-shot native operation; no caller-selected mount targets.

    Cannot run after namespaced journald or either socket has activated.
    Mount-point directories must be pre-created EMPTY, root-owned and
    independently reviewed; never shadow preexisting journal records.
    """
    from .fresh_quota_volume import _run
    from .fresh_native_owner import _show
    if os.geteuid() != 0:
        raise PermissionError("journal mounting requires protected root")
    for unit in (JOURNAL_SERVICE, *JOURNAL_SOCKETS):
        entry = _show(unit)
        if entry.get("ActiveState") not in ("inactive", "dead"):
            raise RuntimeError("namespaced journal already active or uncertain")
    pool_dev = Path(EXTERNAL_MOUNT).stat().st_dev
    persistent, volatile = targets()
    for src, dest in ((JOURNAL_SOURCE, persistent),
                      (VOLATILE_SOURCE, volatile)):
        for path in (src, dest):
            st = path.lstat()
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                    or st.st_mode & 0o022 or path.is_symlink()
                    or (set(x.name for x in path.iterdir()) != {"volatile"}
                        if path == JOURNAL_SOURCE else bool(list(path.iterdir())))):
                raise PermissionError("journal bind source/target not empty/protected")
        if src.stat().st_dev != pool_dev:
            raise PermissionError("journal bind source is not within accounting pool")
    for src, dest in ((JOURNAL_SOURCE, persistent),
                      (VOLATILE_SOURCE, volatile)):
        _run(["/usr/bin/mount", "--bind", str(src), str(dest)], output=False)
    return inspect()
