"""Immutable two-pool, kernel-bounded TOTAL host disk envelope.

A fully reserved build image by itself is NOT evidence of an aggregate cap.
A separately kernel-bounded pool must contain all fresh writable host-owned
state, metadata and logs. If any writable bytes escape both pools, native
admission is forbidden. Requires separate native /proc/mount + journal proof.
"""
from pathlib import Path

TOTAL_BYTES = 32 * 1024**3
BUILD_BYTES = 30 * 1024**3
EXTERNAL_BYTES = 2 * 1024**3
EXTERNAL_MOUNT = "/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external"
SCHEMA = "host-deploy-fresh-aggregate-kernel-storage-v1"
# These logical classes must have no additional writable backing outside the
# two reviewed kernel-bounded pools; a path string alone cannot prove that.
REQUIRED_CLASSES = frozenset({
    "owner-state", "budget-journal", "artifact-metadata",
    "compiler-logs", "controller-logs", "systemd-journal",
})


def _within(path, mount):
    return (type(path) is str and path.startswith("/")
            and ".." not in Path(path).parts
            and (path == mount or path.startswith(mount + "/")))


def validate(work, external, *, host_owner_verified=False):
    """Reject missing external hard enforcement or unaudited journal escape.

    Production verifier must supply external from live kernel quota/mount
    inspection; never from prepared GitHub/SSM parameters. Even a signed
    declaration isn't enough if the actual mount and journal are elsewhere.
    """
    if host_owner_verified is not True:
        raise PermissionError("aggregate kernel quota needs trusted native inspector")
    if (type(work) is not dict or type(external) is not dict
            or type(work.get("image_bytes")) is not int
            or type(work.get("capacity_bytes")) is not int
            or work["image_bytes"] != BUILD_BYTES
            or work["capacity_bytes"] > BUILD_BYTES
            or work.get("kernel_enforced") is not True
            or work.get("mount") !=
                "/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work"):
        raise RuntimeError("build pool differs from reviewed kernel cap")
    if (set(external) != {
            "schema", "mount", "limit_bytes", "kernel_enforced",
            "mount_verified", "allocation_verified", "class_roots",
            "unaccounted_writable_roots"}
            or external["schema"] != SCHEMA
            or external["mount"] != EXTERNAL_MOUNT
            or type(external["limit_bytes"]) is not int
            or external["limit_bytes"] > EXTERNAL_BYTES
            or external["limit_bytes"] <= 0
            or external["kernel_enforced"] is not True
            or external["mount_verified"] is not True
            or external["allocation_verified"] is not True
            or external["unaccounted_writable_roots"] != []
            or type(external["class_roots"]) is not dict
            or set(external["class_roots"]) != REQUIRED_CLASSES
            or not all(_within(p, EXTERNAL_MOUNT)
                       for p in external["class_roots"].values())):
        raise RuntimeError("external host state/journal/logs not kernel bounded")
    if work["image_bytes"] + external["limit_bytes"] > TOTAL_BYTES:
        raise RuntimeError("aggregate host disk exceeds approved 32 GiB")
    return {
        "schema": SCHEMA,
        "build_image_bytes": work["image_bytes"],
        "external_kernel_limit_bytes": external["limit_bytes"],
        "aggregate_max_bytes": work["image_bytes"] + external["limit_bytes"],
        "external_mount": EXTERNAL_MOUNT,
        "bounded_classes": sorted(REQUIRED_CLASSES),
    }



def inspect_external_native():
    """Read kernel and loop backing rather than accepting a JSON quota claim.

    This verifies the fixed ACCOUNTING pool itself. Native owner must also
    independently prove the journald namespace and *all* new writable state
    truly use these class roots; a file merely present here is not enough.
    """
    import os
    import re
    import stat
    import subprocess

    from .fresh_quota_volume import _private
    image = Path("/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external.img")
    mount = Path(EXTERNAL_MOUNT)
    _private(image, file=True)
    file_st = image.stat()
    if (file_st.st_size != EXTERNAL_BYTES
            or file_st.st_blocks * 512 < EXTERNAL_BYTES):
        raise RuntimeError("external accounting image is not fully reserved")
    if not os.path.ismount(mount):
        raise RuntimeError("external accounting mount absent")

    def command(argv):
        return subprocess.run(
            argv, check=True, text=True, capture_output=True, timeout=15,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        ).stdout.strip()

    fields = command(["/usr/bin/findmnt", "--noheadings", "--output",
                      "SOURCE,FSTYPE", "--target", str(mount)]).split()
    if (len(fields) != 2 or not re.fullmatch(r"/dev/loop[0-9]+", fields[0])
            or fields[1] != "ext4"):
        raise RuntimeError("external accounting mount has unsafe kernel backing")
    backing = command(["/usr/sbin/losetup", "--noheadings", "--output",
                       "BACK-FILE", fields[0]])
    if backing != str(image):
        raise RuntimeError("external accounting is mounted from other image")
    fs = os.statvfs(mount)
    limit = fs.f_blocks * fs.f_frsize
    if not 0 < limit <= EXTERNAL_BYTES:
        raise RuntimeError("external accounting capacity exceeds reserve")
    roots = {
        "owner-state": mount / "owner-state",
        "budget-journal": mount / "owner-state/budget",
        "artifact-metadata": mount / "artifacts",
        "compiler-logs": mount / "compiler-logs",
        "controller-logs": mount / "controller-logs",
        "systemd-journal": mount / "systemd-journal",
    }
    dev = mount.stat().st_dev
    for cls, path in roots.items():
        st = path.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_dev != dev
                or path.is_symlink() or path.resolve() != path):
            raise RuntimeError("external accounting root is not on bounded mount: " + cls)
    return {
        "schema": SCHEMA, "mount": str(mount), "limit_bytes": limit,
        "kernel_enforced": True, "mount_verified": True,
        "allocation_verified": True,
        "class_roots": {key: str(path) for key, path in roots.items()},
        # UNKNOWN UNTIL actual kernel-worker mount and journal-namespace
        # acceptance. Do not infer an empty escape list just from 6 dirs.
        "unaccounted_writable_roots": ["worker-mounts-unverified",
                                      "journald-namespace-unverified"],
    }
