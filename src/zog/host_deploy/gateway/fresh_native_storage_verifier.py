"""Trusted fresh-only PID1/worker containment observation (never a caller receipt).

No GitHub, SSM, or controller-supplied "verified" flag is accepted.
This module reads live kernel mount namespaces, process/cgroup membership,
filesystem inodes and memory-swap limits against the exact protected fresh
Project. If no live worker is available, admission is NOT established.
It does not grant a request or write a success receipt.
"""
import os
import json
from pathlib import Path
import stat

from . import fresh_aggregate_disk as aggregate
from . import fresh_quota_volume as quota
from . import fresh_project_state as project_state
from . import fresh_journal_backing as journal_backing
from . import fresh_sidecar_install as sidecar

SCHEMA = "host-deploy-fresh-native-worker-containment-evidence-v1"
CGROUP = Path("/sys/fs/cgroup") / sidecar.SLICE_UNIT
_SAMPLES = ("/image-build/source", "/image-build/output", "/tmp",
            "/var/tmp", "/run")
_PSEUDO = {
    "/dev": frozenset({"tmpfs", "devtmpfs"}),
    "/dev/shm": frozenset({"tmpfs"}),
    "/dev/pts": frozenset({"devpts"}),
    "/dev/mqueue": frozenset({"mqueue"}),
    "/proc": frozenset({"proc"}),
    "/sys": frozenset({"sysfs"}),
    "/sys/fs/cgroup": frozenset({"cgroup2"}),
}
_MAX_PROC = 512
_MAX_MOUNTS = 512


def _one(path, *, limit=131072):
    # Fixed kernel endpoints only. No user-selected path or symlink fallback.
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError("oversized native kernel evidence")
    return raw.decode("utf-8")


def _processes():
    """Read all immediate and descendant cgroups, with no symlink descent."""
    if CGROUP.is_symlink() or not CGROUP.is_dir():
        raise RuntimeError("fresh parent cgroup is not the native slice")
    found = set()
    for parent, dirs, files in os.walk(CGROUP, followlinks=False):
        if len(found) > _MAX_PROC:
            raise RuntimeError("fresh cgroup process inventory exceeds limit")
        dirs.sort()
        if any((Path(parent) / d).is_symlink() for d in dirs):
            raise RuntimeError("fresh cgroup has symlinked descendants")
        text = _one(Path(parent) / "cgroup.procs")
        for line in text.splitlines():
            if not line.isdecimal() or int(line) < 2:
                raise RuntimeError("unparseable fresh cgroup PID")
            found.add(int(line))
    if len(found) > _MAX_PROC:
        raise RuntimeError("too many fresh compiler processes")
    return sorted(found)


def _mounts(pid):
    """Use mount IDs for stacks; retain every kernel layer for write review."""
    raw = _one(Path("/proc") / str(pid) / "mountinfo", limit=262144)
    entries = {}
    by_point = {}
    for line in raw.splitlines():
        f = line.split()
        if "-" not in f:
            raise RuntimeError("invalid worker mountinfo")
        sep = f.index("-")
        if (sep < 6 or len(f) < sep + 4
                or not f[0].isdecimal() or not f[1].isdecimal()
                or f[2].count(":") != 1
                or not f[2].replace(":", "").isdecimal()
                or not f[3].startswith("/") or "\\" in f[3]
                or not f[4].startswith("/") or "\\" in f[4]
                or int(f[0]) in entries):
            raise RuntimeError("truncated or invalid worker mountinfo")
        flags = frozenset(f[5].split(","))
        super_flags = frozenset(f[sep + 3].split(","))
        if not (flags & {"rw", "ro"}) or not (super_flags & {"rw", "ro"}):
            raise RuntimeError("worker mount flags unavailable")
        m = {"id": int(f[0]), "parent": int(f[1]), "point": f[4],
             "device": f[2], "flags": flags, "super_flags": super_flags,
             "fstype": f[sep + 1], "source": f[sep + 2]}
        entries[m["id"]] = m
        by_point.setdefault(m["point"], []).append(m)
        if len(entries) > _MAX_MOUNTS:
            raise RuntimeError("too many worker mounts")
    if "/" not in by_point:
        raise RuntimeError("worker root mount is absent")
    mounts = {}
    for point, layers in by_point.items():
        ids = {x["id"] for x in layers}
        parents = {x["parent"] for x in layers if x["parent"] in ids}
        tops = [x for x in layers if x["id"] not in parents]
        if len(tops) != 1:
            raise RuntimeError("ambiguous worker mount stack: " + point)
        visited = set()
        cursor = tops[0]
        while cursor["id"] not in visited:
            visited.add(cursor["id"])
            if cursor["parent"] not in ids:
                break
            cursor = entries[cursor["parent"]]
        if visited != ids:
            raise RuntimeError("disconnected worker mount stack: " + point)
        mounts[point] = tops[0]
    return mounts, tuple(entries.values())


def _writable(mount):
    return "rw" in mount["flags"] and "rw" in mount["super_flags"]

def _uid_gid(pid):
    status = _one(Path("/proc") / str(pid) / "status")
    vals = {}
    for row in status.splitlines():
        if row.startswith(("Uid:", "Gid:")):
            name, raw = row.split(":", 1)
            v = raw.split()
            if len(v) != 4 or any(not x.isdecimal() for x in v):
                raise RuntimeError("uncertain worker principal")
            vals[name] = tuple(map(int, v))
    if set(vals) != {"Uid", "Gid"}:
        raise RuntimeError("worker principal cannot be read")
    return vals


def _cgroup(pid):
    lines = _one(Path("/proc") / str(pid) / "cgroup").splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise RuntimeError("worker has non-unified cgroup")
    value = lines[0][3:]
    prefix = "/" + sidecar.SLICE_UNIT
    if value != prefix and not value.startswith(prefix + "/"):
        raise RuntimeError("worker escaped frozen fresh parent slice")
    return value


def _verify_worker(pid, *, build_uid, build_gid, build_device):
    cg = _cgroup(pid)
    ids = _uid_gid(pid)
    if (any(v != build_uid for v in ids["Uid"])
            or any(v != build_gid for v in ids["Gid"])):
        raise RuntimeError("non-build principal entered worker cgroup")
    if cg == "/" + sidecar.SLICE_UNIT:
        raise RuntimeError("worker is not in a finite descendant cgroup")
    mounts, all_mounts = _mounts(pid)
    root = Path("/proc") / str(pid) / "root"
    root_st = root.stat()
    # The kernel readlink names a candidate, not evidence that PID1 is
    # executing from the actual inode of that directory. Match both device
    # and inode against the immutable imported host-visible root.
    root_target = Path(os.readlink(root))
    registered = quota.MOUNT / "controller-build-resources"
    if (not root_target.is_relative_to(registered)
            or root_target.name != "root"
            or len(root_target.relative_to(registered).parts) != 3
            or ".." in root_target.parts):
        raise RuntimeError("PID1 worker RootDirectory escaped exact imported root")
    if (root_target.is_symlink()
            or not stat.S_ISDIR(root_st.st_mode)):
        raise RuntimeError("PID1 worker root inode is not a directory")
    candidate = root_target.stat()
    if (not stat.S_ISDIR(candidate.st_mode)
            or (root_st.st_dev, root_st.st_ino) !=
               (candidate.st_dev, candidate.st_ino)
            or root_st.st_dev != build_device):
        raise RuntimeError("PID1 worker RootDirectory inode differs from imported root")
    majmin = f"{os.major(build_device)}:{os.minor(build_device)}"
    # Each separately writable compiler path must be a real kernel bind.
    # Stat through the worker's root, not through the controller's namespace.
    for target in _SAMPLES:
        m = mounts.get(target)
        if (m is None or m["device"] != majmin or not _writable(m)):
            raise RuntimeError("worker writable bind not on reviewed image: " + target)
        fs = (root / target.lstrip("/")).stat()
        if not stat.S_ISDIR(fs.st_mode) or fs.st_dev != build_device:
            raise RuntimeError("worker writable path redirected: " + target)
    for m in all_mounts:
        if not _writable(m):
            continue
        target = m["point"]
        # HugeTLB pools are not charged to the 30-GiB ext4 image or proven
        # bounded by memory.max. Writable hugepage pseudo-mounts are NO-GO.
        if m["fstype"] == "hugetlbfs" or target == "/dev/hugepages" or target.startswith("/dev/hugepages/"):
            raise RuntimeError("unaccounted writable hugepage mount: " + target)
        if m["device"] != majmin and m["fstype"] not in _PSEUDO.get(target, ()):
            raise RuntimeError("worker has writable foreign mount: " + target)
    unit_cgroup = CGROUP / cg.lstrip("/").removeprefix(sidecar.SLICE_UNIT).lstrip("/")
    if unit_cgroup.is_symlink() or not unit_cgroup.is_dir():
        raise RuntimeError("worker cgroup no longer exists")
    swap = _one(unit_cgroup / "memory.swap.max").strip()
    memory = _one(unit_cgroup / "memory.max").strip()
    if swap != "0" or not memory.isdecimal() or int(memory) <= 0:
        raise RuntimeError("worker memory/swap limits not enforced")
    # A writable inherited/open file descriptor is another write route even
    # if all path-based guest bind mounts are correct. Deny any writable
    # regular/dir descriptor on foreign backing; permit only kernel memory
    # descriptors (no swap), pipes, sockets and exact harmless /dev/null.
    fd_dir = Path("/proc") / str(pid) / "fd"
    observed_fds = 0
    for fd in fd_dir.iterdir():
        if not fd.name.isdecimal():
            raise RuntimeError("non-numeric worker fd")
        info = _one(fd_dir.parent / "fdinfo" / fd.name, limit=4096)
        flags = [row.split(":", 1)[1].strip()
                 for row in info.splitlines() if row.startswith("flags:")]
        if len(flags) != 1:
            raise RuntimeError("worker fd flags unavailable")
        try:
            mode = int(flags[0], 8) & os.O_ACCMODE
        except ValueError as exc:
            raise RuntimeError("worker fd flags malformed") from exc
        if mode == os.O_RDONLY:
            continue
        st = fd.stat()
        if stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
            link = os.readlink(fd)
            if (st.st_dev != build_device
                    and not link.startswith(("memfd:", "/memfd:"))):
                raise RuntimeError("worker retained writable host file descriptor")
        elif stat.S_ISCHR(st.st_mode):
            if st.st_rdev != os.makedev(1, 3):
                raise RuntimeError("worker retained writable host device")
        elif not (stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode)):
            raise RuntimeError("worker has unaccounted writable descriptor")
        observed_fds += 1
    return {"pid": pid, "cgroup": cg, "root_dev": majmin,
            "imported_root": str(root_target), "mount_count": len(all_mounts),
            "writable_fd_count": observed_fds, "swap_max": 0,
            "memory_max": int(memory)}


def _inspect_native(*, plan, admission, controller_pid, controller_cgroup,
                    boot_id, host_id, mode):
    """Fail-closed kernel snapshot, with explicitly separate live/empty modes.

    Must be called by the root-owned fixed native owner after its independent
    installed-source, reviewed-plan, admission and old-baseline checks.
    A successful sample is not persistent authorization for later workers:
    watchdog/worker-start ownership must independently enforce the same
    restrictions and repeat the readback at runtime.
    """
    if mode not in ("live", "empty", "pending"):
        raise RuntimeError("native witness mode is not reviewed")
    if os.geteuid() != 0:
        raise PermissionError("kernel verifier requires native root")
    if (type(plan) is not dict or type(admission) is not dict
            or plan.get("host_id") != host_id
            or admission.get("host_id") != host_id
            or admission.get("plan_sha256") != plan.get("sha256")
            or admission.get("budget_scope") != aggregate.BUDGET_SCOPE
            or plan.get("installed", {}).get("boot_id") != boot_id
            or _one("/proc/sys/kernel/random/boot_id").strip() != boot_id
            or plan.get("project_root") != str(project_state.PROJECT_ROOT)):
        raise RuntimeError("host/boot/Project/storage admission identity drift")
    identity = plan["identity"]
    expected_controller = ("/" + sidecar.SLICE_UNIT + "/" + sidecar.UNIT)
    if (type(controller_pid) is not int or controller_pid < 2
            or controller_cgroup != expected_controller):
        raise RuntimeError("controller PID/cgroup identity is not verified")
    volume = quota.inspect()
    state = project_state.inspect(identity["controller_uid"])
    external = aggregate.inspect_external_native()
    aggregate.validate_pre_activation(
        volume, external, host_owner_verified=True)
    if state.get("mount_verified") is not True:
        raise RuntimeError("Project/state kernel bind not verified")
    journal = journal_backing.inspect()
    if journal.get("verified") is not True:
        raise RuntimeError("namespaced journal backing is not native verified")
    device = quota.MOUNT.stat().st_dev
    if (device == Path(aggregate.EXTERNAL_MOUNT).stat().st_dev
            or volume.get("kernel_enforced") is not True):
        raise RuntimeError("fresh build/log images not independently bounded")
    first = _processes()
    if controller_pid not in first:
        raise RuntimeError("frozen root-control sidecar left the fresh slice")
    controller = _uid_gid(controller_pid)
    if any(v != 0 for v in controller["Uid"]):
        raise RuntimeError("fresh privileged controller MainPID is not root")
    if _cgroup(controller_pid) != controller_cgroup:
        raise RuntimeError("fresh controller is outside its exact service cgroup")
    workers = [
        _verify_worker(pid, build_uid=identity["build_uid"],
                       build_gid=identity["build_gid"], build_device=device)
        for pid in first if pid != controller_pid
    ]
    if mode == "live" and not workers:
        raise RuntimeError("no live finite worker available for native witness")
    if mode in ("empty", "pending") and workers:
        raise RuntimeError("empty/pending cold-start lane contains a worker")
    if mode == "empty":
        _assert_no_unclean_starts(device)
    if first != _processes():
        raise RuntimeError("native worker changed during containment inspection")
    return {"schema": SCHEMA, "status": (
                "live-evidence-only" if mode == "live"
                else ("verified-empty-lane-not-start-authority" if mode == "empty"
                      else "verified-missing-pending-not-start-authority")),
            "host_id": host_id, "boot_id": boot_id,
            "plan_sha256": plan["sha256"],
            "project_root": plan["project_root"],
            "request_id": admission["request_id"],
            "budget_scope": aggregate.BUDGET_SCOPE,
            "build_device": f"{os.major(device)}:{os.minor(device)}",
            "controller_pid": controller_pid, "workers": workers,
            "dedicated_reserved_bytes": aggregate.TOTAL_BYTES,
            "no_future_worker_authority": True}


def _assert_no_unclean_starts(build_device):
    """Root-control job records are a VETO, never proof of absence by themselves.

    Actual emptiness is attested separately by two full kernel cgroup censuses.
    Enumerate only fixed directly nested registration job directories, not the
    potentially large imported compiler rootfs. An attempted unfinished start
    cannot silently turn into a legitimate idle interval.
    """
    registered = quota.MOUNT / "controller-build-resources"
    if registered.is_symlink() or registered.stat().st_dev != build_device:
        raise RuntimeError("root-control registration backing escaped build image")
    resources = sorted(registered.iterdir())
    if len(resources) > 256:
        raise RuntimeError("too many registered fresh resources")
    for resource in resources:
        if (resource.is_symlink() or not resource.is_dir()
                or resource.stat().st_dev != build_device):
            raise RuntimeError("unreviewed registered fresh resource")
        jobs = resource / "jobs"
        if jobs.is_symlink():
            raise RuntimeError("symlinked fresh worker job directory")
        if not jobs.exists():
            continue
        if not jobs.is_dir() or jobs.stat().st_dev != build_device:
            raise RuntimeError("fresh worker job directory escaped quota")
        entries = sorted(jobs.iterdir())
        if len(entries) > 256:
            raise RuntimeError("too many fresh worker job records")
        for entry in entries:
            if (entry.is_symlink() or not entry.is_file()
                    or entry.stat().st_dev != build_device
                    or entry.suffix != ".json"):
                raise RuntimeError("invalid registered fresh worker job")
            info = json.loads(_one(entry, limit=16384))
            if (type(info) is not dict
                    or info.get("parent_slice") != sidecar.SLICE_UNIT
                    or info.get("log_namespace") != sidecar.LOG_NAMESPACE):
                raise RuntimeError("fresh worker job binding differs")
            if (info.get("start_attempted") is True
                    and info.get("process_cleanup_complete") is not True):
                raise RuntimeError("attempted fresh worker missing without cleanup")


def inspect_live(*, plan, admission, controller_pid, controller_cgroup,
                 boot_id, host_id):
    return _inspect_native(
        plan=plan, admission=admission, controller_pid=controller_pid,
        controller_cgroup=controller_cgroup, boot_id=boot_id, host_id=host_id,
        mode="live")


def inspect_empty(*, plan, admission, controller_pid, controller_cgroup,
                  boot_id, host_id):
    """Observe a genuine empty lane BEFORE the first authorized worker.

    Evidence-only. Does NOT allow root-control to start anything, prove
    a canary, or clear DEDICATED_UNVERIFIED_WRITERS.
    """
    return _inspect_native(
        plan=plan, admission=admission, controller_pid=controller_pid,
        controller_cgroup=controller_cgroup, boot_id=boot_id, host_id=host_id,
        mode="empty")


def inspect_pending(*, plan, admission, controller_pid, controller_cgroup,
                    boot_id, host_id):
    """Read-only no-worker PID1/cgroup/quota evidence DURING a protected claim.

    Unlike inspect_empty this does not demand that no attempted job exists.
    The privileged caller MUST first match the exact one-shot claim and
    <=10s monotonic pending deadline; this never grants a worker start.
    """
    return _inspect_native(
        plan=plan, admission=admission, controller_pid=controller_pid,
        controller_cgroup=controller_cgroup, boot_id=boot_id, host_id=host_id,
        mode="pending")
