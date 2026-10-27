"""Read-only PID1 mount evidence for host writes not confined by fresh quotas.

The two loop-backed ext4 images place a hard bound on *their filesystem
capacity*, not on the shared host filesystem. This inspector deliberately
does NOT turn observed inode/device identity into an aggregate budget grant.
It enumerates representative host-writable surfaces to guide native Work.

A missing sample path does not establish absence of its writer class. Nor
can this finite list enumerate all indirect or future host writes. No caller
may pass an arbitrary path, mount, or an authorization override.
"""
import os
from pathlib import Path
import re
import stat

from . import fresh_aggregate_disk as aggregate
from . import fresh_quota_volume as quota

SCHEMA = "host-deploy-fresh-host-write-surfaces-v1"
_MAX_MOUNTINFO_BYTES = 1024 * 1024
_MAX_MOUNTS = 4096
_ESCAPE = re.compile(r"\\([0-7]{3})")
# These are fixed sampling points, not an allowlist of all possible writers.
SURFACES = {
    "pid1-default-journald-unverified": (
        "/var/log/journal", "/run/log/journal", "/var/log/messages",
        "/var/log/syslog", "/run/systemd", "/var/lib/systemd",
    ),
    "ssm-transport-and-agent-unverified": (
        "/var/lib/amazon/ssm", "/var/log/amazon/ssm",
        "/var/lib/ssm", "/var/log/ssm",
    ),
    "cron-schedule-and-daemon-unverified": (
        "/etc/cron.d", "/var/spool/cron", "/var/log/cron",
        "/run/crond.pid",
    ),
    "installer-filesystem-metadata-unverified": (
        "/var/lib/zog/host-deploy",
        "/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25",
        "/home/zog-cross-owner/fresh-cross-bootstrap-oct25",
        "/run/systemd/transient",
        str(quota.IMAGE),
        "/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external.img",
    ),
    "worker-private-tmp-coredump-unverified": (
        "/tmp", "/var/tmp", "/dev/shm", "/run",
        "/var/lib/systemd/coredump",
    ),
}
assert set(SURFACES).issubset(set(aggregate.UNVERIFIED_WRITERS))


def _decode(value):
    return _ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _mounts(raw):
    if len(raw) > _MAX_MOUNTINFO_BYTES:
        raise RuntimeError("PID1 mountinfo exceeded bounded inspection size")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) > _MAX_MOUNTS:
        raise RuntimeError("PID1 mountinfo exceeded bounded entry count")
    mounts = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise RuntimeError("malformed PID1 mountinfo")
        sep = fields.index("-")
        if sep < 6 or len(fields) < sep + 3:
            raise RuntimeError("malformed PID1 mountinfo")
        point = _decode(fields[4])
        root = _decode(fields[3])
        if not point.startswith("/") or not root.startswith("/"):
            raise RuntimeError("PID1 mountinfo contains nonabsolute path")
        mounts.append({
            "point": point, "root": root, "major_minor": fields[2],
            "fstype": fields[sep + 1], "source": _decode(fields[sep + 2]),
            "options": fields[5],
        })
    if not mounts or not any(item["point"] == "/" for item in mounts):
        raise RuntimeError("PID1 mountinfo missing root")
    return mounts


def _covering(mounts, path):
    matching = [
        item for item in mounts if item["point"] == "/"
        or path == item["point"]
        or path.startswith(item["point"].rstrip("/") + "/")
    ]
    if not matching:
        raise RuntimeError("PID1 mountinfo does not cover sampled path")
    return max(matching, key=lambda item: len(item["point"]))


def inspect():
    """Observe representative host paths without altering filesystem state.

    It is intentionally impossible to obtain an admission token or a claim
    of hard-bounded total bytes from this function.
    """
    if os.readlink("/proc/1/ns/mnt") != os.readlink("/proc/self/ns/mnt"):
        raise RuntimeError("audit reader does not share PID1 mount namespace")
    with open("/proc/1/mountinfo", "rb") as handle:
        raw = handle.read(_MAX_MOUNTINFO_BYTES + 1)
    mounts = _mounts(raw)
    rows = {}
    for cls, paths in SURFACES.items():
        samples = []
        for path in paths:
            mount = _covering(mounts, path)
            try:
                fs = os.lstat(path)  # no file reads or atime changes
            except FileNotFoundError:
                samples.append({
                    "path": path, "status": "missing-is-not-no-writes",
                    "pid1_mount": mount,
                })
                continue
            if stat.S_ISLNK(fs.st_mode):
                status = "symlink-destination-not-attested"
            elif stat.S_ISDIR(fs.st_mode) or stat.S_ISREG(fs.st_mode):
                status = "observed-not-quota-proof"
            else:
                status = "special-node-not-quota-proof"
            samples.append({
                "path": path, "status": status,
                "dev": f"{os.major(fs.st_dev)}:{os.minor(fs.st_dev)}",
                "inode": fs.st_ino, "owner_uid": fs.st_uid,
                "pid1_mount": mount,
            })
        rows[cls] = samples
    return {
        "schema": SCHEMA,
        "status": "evidence-only-no-aggregate-admission",
        "pid1_mount_namespace": os.readlink("/proc/1/ns/mnt"),
        "work_image_bytes": aggregate.BUILD_BYTES,
        "external_image_bytes": aggregate.EXTERNAL_BYTES,
        "additional_shared_host_write_limit_verified": False,
        "outstanding_classes": list(aggregate.UNVERIFIED_WRITERS),
        "samples": rows,
    }
