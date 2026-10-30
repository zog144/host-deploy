"""Protected HugeTLB cgroup prerequisite for the one fresh compiler slice.

systemd 252 does not manage hugetlb via Delegate=/resource properties.
The root of cgroup2 is PID1-owned and shared. A change there is ONLY an
independently authorized host-owner installation operation, never an implicit
side effect of arming, a Zog controller RPC, or reboot recovery.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

from . import fresh_sidecar_install as sidecar

CGROUP_ROOT = Path("/sys/fs/cgroup")
SLICE = CGROUP_ROOT / sidecar.SLICE_UNIT
APPROVAL_SCHEMA = "host-deploy-fresh-hugetlb-root-approval-v1"
RECEIPT_SCHEMA = "host-deploy-fresh-hugetlb-root-activation-v1"
APPROVED_SCOPE = "dedicated-fresh-slice-with-explicit-shared-root-controller-change"
_MAX_LIMIT_FILES = 64


def _file(path, *, max_bytes=4096):
    """A fixed kernel endpoint; no symlink, arbitrary path or silent truncation."""
    if path.is_symlink():
        raise RuntimeError("HugeTLB cgroup endpoint is symlinked")
    with open(path, "rb") as source:
        payload = source.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise RuntimeError("HugeTLB cgroup endpoint oversized")
    return payload.decode("ascii")


def _tokens(path):
    value = _file(path)
    tokens = value.split()
    if (len(tokens) != len(set(tokens))
            or any(re.fullmatch(r"[a-z][a-z0-9_]*", x) is None for x in tokens)):
        raise RuntimeError("invalid HugeTLB cgroup controller inventory")
    return frozenset(tokens)


def _mountinfo():
    return Path("/proc/self/mountinfo").read_text()


def _directories():
    root = CGROUP_ROOT.lstat()
    slice_st = SLICE.lstat()
    if (not stat.S_ISDIR(root.st_mode) or not stat.S_ISDIR(slice_st.st_mode)
            or root.st_uid != 0 or slice_st.st_uid != 0
            or root.st_gid != 0 or slice_st.st_gid != 0
            or root.st_mode & 0o022 or slice_st.st_mode & 0o022
            or root.st_dev != slice_st.st_dev):
        raise RuntimeError("unprotected HugeTLB cgroup ancestor/slice")
    # The only permissible ancestor of this fixed one-level slice is the
    # cgroup2 root. No system.slice, user.slice or delegated subtree writes.
    if SLICE.parent != CGROUP_ROOT or "-" in sidecar.SLICE_UNIT:
        raise RuntimeError("fresh HugeTLB slice ancestry differs")
    # Mountinfo must identify the *actual* cgroup2 mount; stat_dev alone
    # cannot distinguish a substituted directory on an unrelated filesystem.
    raw = _mountinfo()
    matches = [line for line in raw.splitlines()
               if len(line.split(" - ", 1)) == 2
               and line.split(" - ", 1)[0].split()[4] == str(CGROUP_ROOT)]
    if (len(matches) != 1
            or matches[0].split(" - ", 1)[1].split()[0] != "cgroup2"):
        raise RuntimeError("HugeTLB is not on the kernel cgroup2 mount")
    return root, slice_st


def snapshot():
    """Read-only identity/availability. Never writes any ancestor controls."""
    root, child = _directories()
    available = _tokens(CGROUP_ROOT / "cgroup.controllers")
    enabled = _tokens(CGROUP_ROOT / "cgroup.subtree_control")
    if not enabled <= available:
        raise RuntimeError("cgroup2 root controller state is inconsistent")
    child_available = _tokens(SLICE / "cgroup.controllers")
    limits = sorted(SLICE.glob("hugetlb.*.max"))
    if len(limits) > _MAX_LIMIT_FILES or any(x.is_symlink() for x in limits):
        raise RuntimeError("HugeTLB limit path substitution")
    return {
        "root_device": root.st_dev, "root_inode": root.st_ino,
        "slice_device": child.st_dev, "slice_inode": child.st_ino,
        "root_available": sorted(available), "root_enabled": sorted(enabled),
        "slice_available": sorted(child_available),
        "limit_names": [p.name for p in limits],
        "root_subtree_sha256": hashlib.sha256(
            _file(CGROUP_ROOT / "cgroup.subtree_control").encode("ascii")).hexdigest(),
    }


def validate_approval(approval, *, host_id, boot_id, plan_sha256, before):
    """Root-protected, boot/host/plan/ancestor-specific operator decision."""
    if (type(approval) is not dict or set(approval) != {
            "schema", "status", "host_id", "boot_id", "plan_sha256",
            "slice_unit", "scope", "allow_shared_root_change",
            "root_device", "root_inode", "slice_device", "slice_inode",
            "root_subtree_sha256"}
            or approval.get("schema") != APPROVAL_SCHEMA
            or approval.get("status") != "operator-approved"
            or approval.get("host_id") != host_id
            or approval.get("boot_id") != boot_id
            or approval.get("plan_sha256") != plan_sha256
            or approval.get("slice_unit") != sidecar.SLICE_UNIT
            or approval.get("scope") != APPROVED_SCOPE
            or approval.get("allow_shared_root_change") is not True
            or not all(type(approval[k]) is int for k in (
                "root_device", "root_inode", "slice_device", "slice_inode"))
            or any(approval[k] != before[k] for k in (
                "root_device", "root_inode", "slice_device", "slice_inode",
                "root_subtree_sha256"))):
        raise PermissionError("explicit shared-root HugeTLB approval missing or drifted")


def activate_with_approval(approval, *, host_id, boot_id, plan_sha256):
    """One approved host-owner cgroup2 write, never called by arm/recover.

    The caller is the root-owned *local* installer, after checking systemd
    252 PID1, frozen installation, old workloads and the operator-approved
    0600 approval file. No arbitrary cgroup path or remote command accepted.
    """
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise PermissionError("HugeTLB activation requires native root/PID1")
    before = snapshot()
    validate_approval(approval, host_id=host_id, boot_id=boot_id,
                      plan_sha256=plan_sha256, before=before)
    if "hugetlb" not in before["root_available"]:
        raise RuntimeError("kernel cgroup2 HugeTLB controller not available")
    if "hugetlb" not in before["root_enabled"]:
        # This is a SHARED systemd-owned ancestor. Explicit approval above is
        # mandatory. Never write -hugetlb, never alter existing controllers.
        fd = os.open(CGROUP_ROOT / "cgroup.subtree_control",
                     os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if os.write(fd, b"+hugetlb") != len(b"+hugetlb"):
                raise RuntimeError("short HugeTLB ancestor activation")
        finally:
            os.close(fd)
    after = snapshot()
    if (any(after[k] != before[k] for k in (
            "root_device", "root_inode", "slice_device", "slice_inode"))
            or not set(before["root_enabled"]) <= set(after["root_enabled"])
            or "hugetlb" not in after["root_enabled"]
            or "hugetlb" not in after["slice_available"]
            or not any(x.endswith(".max") and not x.endswith(".rsvd.max")
                       for x in after["limit_names"])):
        # The kernel/systemd outcome is now UNCERTAIN. Never reverse a
        # shared-root controller under a running PID1 manager automatically.
        raise RuntimeError("HugeTLB activation outcome uncertain; no admission")
    return {
        "schema": RECEIPT_SCHEMA, "host_id": host_id, "boot_id": boot_id,
        "plan_sha256": plan_sha256, "slice_unit": sidecar.SLICE_UNIT,
        "root_device": after["root_device"], "root_inode": after["root_inode"],
        "slice_device": after["slice_device"], "slice_inode": after["slice_inode"],
        "root_enabled": after["root_enabled"], "limit_names": after["limit_names"],
        "status": "activated-needs-native-review",
    }


def recheck(receipt, *, host_id, boot_id, plan_sha256):
    """A past/root-owned receipt cannot grant admission after reboot or drift."""
    current = snapshot()
    if (type(receipt) is not dict
            or receipt.get("schema") != RECEIPT_SCHEMA
            or receipt.get("status") != "activated-needs-native-review"
            or any(receipt.get(k) != value for k, value in {
                "host_id": host_id, "boot_id": boot_id,
                "plan_sha256": plan_sha256, "slice_unit": sidecar.SLICE_UNIT,
            }.items())
            or any(receipt.get(k) != current[k] for k in (
                "root_device", "root_inode", "slice_device", "slice_inode"))
            or current["root_enabled"] != receipt.get("root_enabled")
            or "hugetlb" not in current["root_enabled"]
            or "hugetlb" not in current["slice_available"]
            or current["limit_names"] != receipt.get("limit_names")):
        raise RuntimeError("HugeTLB controller or activation receipt drifted")
    return current
