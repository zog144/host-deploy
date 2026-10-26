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
