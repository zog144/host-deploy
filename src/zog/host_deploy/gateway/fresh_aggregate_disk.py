"""Fixed 32-GiB DEDICATED storage reservation for the fresh compiler.

This policy excludes ordinary shared-host PID1/default journal, SSM, cron and
host-fs management overhead from the DEDICATED storage allowance, per explicit
2026-10-27 owner decision. These host writes are still observable, but this
policy does NOT assert or enforce a TOTAL shared-host write limit. Every fresh
compiler-owned data/workspace/log path must be backed by the two capped images.
Native admission remains fail-closed pending independent worker mount proof.
"""
from pathlib import Path

TOTAL_BYTES = 32 * 1024**3
BUILD_BYTES = 30 * 1024**3
EXTERNAL_BYTES = 2 * 1024**3
EXTERNAL_MOUNT = "/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external"
SCHEMA = "host-deploy-fresh-dedicated-storage-v2"
BUDGET_SCOPE = "fresh-dedicated-reservation-32gib-v1"
# These logical classes must have no additional writable backing outside the
# two reviewed kernel-bounded pools; a path string alone cannot prove that.
REQUIRED_CLASSES = frozenset({
    "owner-state", "budget-journal", "artifact-metadata",
    "compiler-logs", "controller-logs", "systemd-journal",
})

# Every attributable writer class outside the two kernel-limited images
# remains explicitly NOT PROVEN. Shared PID1/crond/SSM writes cannot be
# attributed to a private loop quota merely by configuring unit LogNamespace.
# New generic classes require separately reviewed confinement/provenance and
# disposable native negative proof; they are never auto-credited as bounded.
UNVERIFIED_WRITERS = (
    "worker-mounts-unverified",
    "worker-private-tmp-coredump-unverified",
    "root-control-registration-unverified",
    "pid1-default-journald-unverified",
    "ssm-transport-and-agent-unverified",
    "cron-schedule-and-daemon-unverified",
    "installer-filesystem-metadata-unverified",
    "other-attributable-host-writes-unverified",
)


# Revised approved boundary. Shared-host management overhead is excluded
# ONLY from dedicated storage reservation accounting, not from diagnostic
# visibility or the six-hour execution budget.
EXCLUDED_SHARED_HOST_WRITERS = (
    "pid1-default-journald-unverified",
    "ssm-transport-and-agent-unverified",
    "cron-schedule-and-daemon-unverified",
    "installer-filesystem-metadata-unverified",
)
# These are compiler-owned writes; absence of real mount/inode proof still
# prevents native admission. The last class catches unenumerated fresh writes.
DEDICATED_UNVERIFIED_WRITERS = (
    "worker-mounts-unverified",
    "worker-private-tmp-coredump-unverified",
    "root-control-registration-unverified",
    "other-attributable-host-writes-unverified",
)
assert set(UNVERIFIED_WRITERS) == set(
    EXCLUDED_SHARED_HOST_WRITERS + DEDICATED_UNVERIFIED_WRITERS)


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
            "unaccounted_writable_roots", "budget_scope",
            "excluded_shared_host_overhead"}
            or external["schema"] != SCHEMA
            or external["budget_scope"] != BUDGET_SCOPE
            or external["excluded_shared_host_overhead"] !=
                list(EXCLUDED_SHARED_HOST_WRITERS)
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
        raise RuntimeError("dedicated compiler state/journal/logs not kernel bounded")
    if work["image_bytes"] + external["limit_bytes"] > TOTAL_BYTES:
        raise RuntimeError("dedicated storage reservation exceeds approved 32 GiB")
    return {
        "schema": SCHEMA,
        "build_image_bytes": work["image_bytes"],
        "external_kernel_limit_bytes": external["limit_bytes"],
        "dedicated_reserved_max_bytes": work["image_bytes"] + external["limit_bytes"],
        "budget_scope": BUDGET_SCOPE,
        "excluded_shared_host_overhead": list(EXCLUDED_SHARED_HOST_WRITERS),
        "external_mount": EXTERNAL_MOUNT,
        "bounded_classes": sorted(REQUIRED_CLASSES),
    }



def validate_pre_activation(work, external, *, host_owner_verified=False):
    """Allow only storage/controller observation, NEVER compiler admission.

    Final dedicated storage admission still requires independent live proof
    that worker/registration writes stay inside the two images. Shared-host
    management overhead is explicitly excluded by fixed scope, not passed as
    falsely verified. This pre-activation receipt NEVER arms a compiler.
    """
    expected_blockers = list(DEDICATED_UNVERIFIED_WRITERS)
    if (type(external) is not dict
            or external.get("unaccounted_writable_roots") != expected_blockers):
        raise RuntimeError("unreviewed or falsely certified pre-activation classes")
    # Validate unchanged byte caps, mount/source and quota fields, but do NOT
    # return or persist a fabricated all-writers-verified observation.
    checked = dict(external, unaccounted_writable_roots=[])
    shape = validate(work, checked, host_owner_verified=host_owner_verified)
    return {"schema": SCHEMA, "status": "preactivation-only",
            "budget_scope": BUDGET_SCOPE,
            "dedicated_reserved_max_bytes": shape["dedicated_reserved_max_bytes"],
            "outstanding_classes": expected_blockers,
            "excluded_shared_host_overhead": list(EXCLUDED_SHARED_HOST_WRITERS)}


def inspect_external_pool_native():
    """Inspect the fixed ext4 backing independently of journal bind setup.

    This is a PREPARATION receipt only. It deliberately retains all unknown
    writer classes; it MUST NOT be accepted as aggregate admission proof.
    Provisioning and reboot recovery cannot call the final journal inspector
    before the journal bind mounts have been installed on this boot.
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
        "schema": SCHEMA, "budget_scope": BUDGET_SCOPE,
        "excluded_shared_host_overhead": list(EXCLUDED_SHARED_HOST_WRITERS),
        "mount": str(mount), "limit_bytes": limit,
        "kernel_enforced": True, "mount_verified": True,
        "allocation_verified": True,
        "class_roots": {key: str(path) for key, path in roots.items()},
        # These kernel/provenance classes are still outstanding. The only
        # permitted positive proof is a reviewed fixed source correction
        # plus independent native mount/log/ENOSPC acceptance.
        "unaccounted_writable_roots": list(DEDICATED_UNVERIFIED_WRITERS),
    }



def inspect_external_native():
    """Final external readback: pool AND actual journal mounts required.

    Verifying the journal bind paths does not establish that ALL host writes
    use the bounded volume. The remaining classes deliberately stay NO-GO.
    """
    pool = inspect_external_pool_native()
    from . import fresh_journal_backing
    journal = fresh_journal_backing.inspect()
    if (journal.get("external_pool") != pool["mount"]
            or journal.get("verified") is not True):
        raise RuntimeError("journal namespace backing is unverified")
    return pool


def provision_external(*, available_after_reservations_bytes):
    """One-shot native 2-GiB accounting pool, before staging reviewed PLAN.

    Caller must already have independent authority to reserve host capacity.
    Cannot format any existing rootfs, partition, file, mount or old Project.
    """
    import os
    import stat
    from .fresh_quota_volume import _private, _run, _BACKEND

    if os.geteuid() != 0:
        raise PermissionError("protected native accounting pool owner required")
    if (type(available_after_reservations_bytes) is not int
            or available_after_reservations_bytes < TOTAL_BYTES):
        raise RuntimeError("no approved total host capacity for accounting pool")
    image = Path("/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external.img")
    mount = Path(EXTERNAL_MOUNT)
    _private(image.parent)
    fs = os.statvfs(image.parent)
    if fs.f_bavail * fs.f_frsize < available_after_reservations_bytes:
        raise RuntimeError("host reservation changed before external pool")
    if image.exists() or image.is_symlink() or os.path.ismount(mount):
        raise RuntimeError("external accounting already exists; never replace")
    st = mount.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
            or st.st_mode & 0o022 or mount.is_symlink()
            or any(mount.iterdir())):
        raise PermissionError("external accounting mount not empty and trusted")
    fd = os.open(image, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.posix_fallocate(fd, 0, EXTERNAL_BYTES)
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(image.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    _run(["/usr/sbin/mkfs.ext4", "-F", "-m", "0", "-E", "nodiscard",
          str(image)], output=False)
    st = image.stat()
    if (st.st_size != EXTERNAL_BYTES
            or st.st_blocks * 512 < EXTERNAL_BYTES):
        raise RuntimeError("external mkfs discarded reserved host capacity")
    loop = _run(["/usr/sbin/losetup", "--find", "--show", "--nooverlap",
                 str(image)])
    if not _BACKEND.fullmatch(loop):
        raise RuntimeError("external accounting got unexpected loop backing")
    _run(["/usr/bin/mount", "-t", "ext4", "-o", "nosuid,nodev",
          loop, str(mount)], output=False)
    for suffix in ("owner-state", "owner-state/budget", "artifacts",
                   "artifacts/build-resources",
                   "compiler-logs", "controller-logs", "systemd-journal",
                   "systemd-journal/volatile"):
        new = mount / suffix
        new.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chown(new, 0, 0)
        os.chmod(new, 0o700)
    return inspect_external_pool_native()


def reattach_external_after_boot():
    """Recover the SAME allocated accounting image. Never reformat or select another."""
    import os
    from .fresh_quota_volume import _private, _run, _BACKEND
    if os.geteuid() != 0:
        raise PermissionError("protected external pool reboot recovery requires root")
    image = Path("/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external.img")
    mount = Path(EXTERNAL_MOUNT)
    _private(image, file=True)
    if not os.path.ismount(mount):
        loop = _run(["/usr/sbin/losetup", "--find", "--show", "--nooverlap",
                     str(image)])
        if not _BACKEND.fullmatch(loop):
            raise RuntimeError("unreviewed external loop on reboot")
        _run(["/usr/bin/mount", "-t", "ext4", "-o", "nosuid,nodev",
              loop, str(mount)], output=False)
    return inspect_external_pool_native()
