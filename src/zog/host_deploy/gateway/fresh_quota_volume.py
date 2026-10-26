"""Concrete Linux quota filesystem for the fresh cross-bootstrap only.

The 32-GiB *additional disk* cap is enforced by the kernel capacity of an
allocated ext4 loop filesystem, not by an advisory du/statvfs monitor.
The native installer must independently prove every mutable build output is
inside this mount. No existing Zog workspace or rootfs is reformatted.
"""
import os
from pathlib import Path
import re
import stat
import subprocess

from .fresh_budget_guard import ADDITIONAL_DISK_BYTES

IMAGE = Path("/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/quota.img")
MOUNT = Path("/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work")
_BACKEND = re.compile(r"/dev/loop[0-9]+\Z")


def _run(args, *, output=True):
    if any(type(item) is not str or "\x00" in item for item in args):
        raise ValueError("quota command cannot contain invalid arguments")
    result = subprocess.run(
        args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                    "LC_ALL": "C"})
    return result.stdout.strip() if output else None


def _private(path, *, file=False):
    """Require an existing non-symlink root-owned protected hierarchy."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PermissionError("quota path must be fixed and canonical")
    cursor = Path("/")
    for part in path.parts[1:-1]:
        cursor /= part
        st = cursor.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            raise PermissionError("unprotected quota ancestry")
    st = path.lstat()
    if (st.st_uid != 0 or st.st_nlink != 1
            or (not stat.S_ISREG(st.st_mode) if file
                else not stat.S_ISDIR(st.st_mode))
            or st.st_mode & 0o022):
        raise PermissionError("unprotected quota object")
    return path


def _source():
    if not os.path.ismount(MOUNT):
        raise RuntimeError("fresh quota filesystem not mounted")
    source = _run(["/usr/bin/findmnt", "--noheadings", "--output",
                   "SOURCE,FSTYPE", "--target", str(MOUNT)]).split()
    if len(source) != 2 or not _BACKEND.fullmatch(source[0]) or source[1] != "ext4":
        raise RuntimeError("fresh quota filesystem has unexpected backing")
    image = _run(["/usr/sbin/losetup", "--noheadings", "--output",
                  "BACK-FILE", source[0]])
    if image != str(IMAGE):
        raise RuntimeError("fresh quota loop does not map to frozen image")
    return source[0]


def inspect():
    """Read real backing size and mount capacity, rejecting other sources."""
    _private(IMAGE, file=True)
    st = IMAGE.stat()
    if (st.st_size != ADDITIONAL_DISK_BYTES
            or st.st_blocks * 512 < ADDITIONAL_DISK_BYTES):
        raise RuntimeError("fresh disk backing is sparse or not fully reserved")
    _source()
    fs = os.statvfs(MOUNT)
    capacity = fs.f_blocks * fs.f_frsize
    if capacity > ADDITIONAL_DISK_BYTES or capacity <= 0:
        raise RuntimeError("quota volume capacity exceeds approved disk")
    used = (fs.f_blocks - fs.f_bfree) * fs.f_frsize
    if used < 0 or used > ADDITIONAL_DISK_BYTES:
        raise RuntimeError("quota accounting is invalid")
    return {"capacity_bytes": capacity, "used_bytes": used,
            "image_bytes": st.st_size, "mount": str(MOUNT),
            "backing_device": _source(), "kernel_enforced": True}


def provision(*, available_after_reservations_bytes, mounted_writable_roots):
    """One-time privileged provision. Never overwrite an image or mount.

    Called only after independent Stage A capacity/source/owner approval.
    Require an EXACT list of build writable roots, all nested under this
    dedicated mount. No other writable root may escape into shared STATE.
    """
    if os.geteuid() != 0:
        raise PermissionError("kernel quota provisioning requires root")
    if (type(available_after_reservations_bytes) is not int
            or available_after_reservations_bytes < ADDITIONAL_DISK_BYTES
            or type(mounted_writable_roots) is not list
            or not mounted_writable_roots
            or any(type(p) is not str or (
                p != str(MOUNT) and not p.startswith(str(MOUNT) + "/"))
                for p in mounted_writable_roots)):
        raise RuntimeError("quota capacity or mutable build mounts not approved")
    _private(IMAGE.parent)
    free = os.statvfs(IMAGE.parent)
    if free.f_bavail * free.f_frsize < available_after_reservations_bytes:
        raise RuntimeError("fresh host capacity shrank below protected admission")
    if IMAGE.exists() or IMAGE.is_symlink() or os.path.ismount(MOUNT):
        raise RuntimeError("fresh filesystem already exists; inspect, never replace")
    # Caller precreates/attests the empty mount directory under the strictly
    # new controller Project. This file is root-only and never chmod-writable.
    target = MOUNT.lstat()
    if (not stat.S_ISDIR(target.st_mode) or target.st_mode & 0o022
            or MOUNT.is_symlink() or any(MOUNT.iterdir())):
        raise PermissionError("fresh quota mount directory is unsafe or nonempty")
    fd = os.open(IMAGE, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW, 0o600)
    try:
        os.posix_fallocate(fd, 0, ADDITIONAL_DISK_BYTES)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(IMAGE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    # Never run mkfs on a caller-selected device: it accepts ONLY the newly
    # reserved frozen image file. Failure keeps it for manual disposition.
    _run(["/usr/sbin/mkfs.ext4", "-F", "-m", "0", str(IMAGE)], output=False)
    loop = _run(["/usr/sbin/losetup", "--find", "--show", "--nooverlap",
                 str(IMAGE)])
    if not _BACKEND.fullmatch(loop):
        raise RuntimeError("unexpected fresh quota loop device")
    _run(["/usr/bin/mount", "-t", "ext4", "-o", "nosuid,nodev",
          loop, str(MOUNT)], output=False)
    return inspect()


def reattach_after_boot():
    """Reattach exact existing image only; never format or change size."""
    if os.geteuid() != 0:
        raise PermissionError("quota reboot reconciliation requires root")
    _private(IMAGE, file=True)
    if os.path.ismount(MOUNT):
        return inspect()
    loop = _run(["/usr/sbin/losetup", "--find", "--show", "--nooverlap",
                 str(IMAGE)])
    if not _BACKEND.fullmatch(loop):
        raise RuntimeError("unexpected loop-device allocation")
    _run(["/usr/bin/mount", "-t", "ext4", "-o", "nosuid,nodev",
          loop, str(MOUNT)], output=False)
    return inspect()
