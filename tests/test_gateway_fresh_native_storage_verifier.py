"""Fail-closed native PID1 / cgroup / worker storage security contract."""
import os
from pathlib import Path
from types import SimpleNamespace
import inspect

import pytest

from zog.host_deploy.gateway import fresh_native_storage_verifier as verify
from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_quota_volume as quota


def _mountinfo(*, foreign=False, missing=None):
    points = {
        "/": ("7:5", "ro", "ext4"),
        "/image-build/source": ("7:5", "rw", "ext4"),
        "/image-build/output": ("7:5", "rw", "ext4"),
        "/tmp": ("7:5", "rw", "ext4"),
        "/var/tmp": ("7:5", "rw", "ext4"),
        "/run": ("7:5", "rw", "ext4"),
        "/dev": ("0:14", "rw", "tmpfs"),
        "/proc": ("0:15", "rw", "proc"),
    }
    if foreign:
        points["/host-escape"] = ("8:1", "rw", "ext4")
    if missing:
        del points[missing]
    return "\n".join(
        f"{20+i} 1 {dev} / {point} {flags},relatime - {fstype} source rw"
        for i,(point,(dev,flags,fstype)) in enumerate(points.items())) + "\n"


def test_actual_mountinfo_rejects_foreign_and_missing_required_bind(monkeypatch):
    monkeypatch.setattr(verify, "_one", lambda *_a, **_k: _mountinfo())
    assert set(verify._mounts(456)[0]) >= set(verify._SAMPLES)
    monkeypatch.setattr(verify, "_one",
                        lambda *_a, **_k: _mountinfo(foreign=True))
    assert "/host-escape" in verify._mounts(456)[0]
    monkeypatch.setattr(verify, "_one",
                        lambda *_a, **_k: _mountinfo(missing="/run"))
    assert "/run" not in verify._mounts(456)[0]
    monkeypatch.setattr(verify, "_one", lambda *_a, **_k: "")
    with pytest.raises(RuntimeError, match="root mount"):
        verify._mounts(456)


def test_cgroup_inventory_covers_children_and_refuses_substitution(
        tmp_path, monkeypatch):
    root = tmp_path / "fresh.slice"
    child = root / "worker.slice" / "worker.service"
    child.mkdir(parents=True)
    (root / "cgroup.procs").write_text("410\n")
    (child.parent / "cgroup.procs").write_text("")
    (child / "cgroup.procs").write_text("411\n412\n")
    monkeypatch.setattr(verify, "CGROUP", root)
    assert verify._processes() == [410, 411, 412]
    (child / "cgroup.procs").write_text("411\nnot-a-pid\n")
    with pytest.raises(RuntimeError, match="unparseable"):
        verify._processes()
    (child / "cgroup.procs").write_text("411\n")
    (child.parent / "redirect").symlink_to(child, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symlinked"):
        verify._processes()


def _simulate_worker(monkeypatch, tmp_path, *, escaped=None, fds=None):
    """Read genuine tempfile layout, mock only privileged kernel metadata."""
    image = tmp_path / "work"
    rootbase = image / "controller-build-resources" / "a" / "b" / "root"
    rootbase.mkdir(parents=True)
    for dest in verify._SAMPLES:
        (rootbase / dest.lstrip("/")).mkdir(parents=True)
    cg = tmp_path / "fake-cgroup"
    cg.mkdir()
    (cg / "memory.swap.max").write_text("0")
    (cg / "memory.max").write_text("100000000")
    monkeypatch.setattr(verify, "CGROUP", cg.parent)
    monkeypatch.setattr(verify.quota, "MOUNT", image)
    monkeypatch.setattr(verify, "_cgroup", lambda pid: "/zogfreshcrossbootstrapoct25.slice/fake-cgroup")
    monkeypatch.setattr(verify, "_uid_gid", lambda pid: {
        "Uid": (24302,)*4, "Gid": (24302,)*4})
    def mocked_mounts(pid):
        mounts = {
            p: {"device": ("8:1" if escaped == p else "7:5"),
                "point": p, "flags": frozenset({"rw"}),
                "super_flags": frozenset({"rw"}), "fstype": "ext4"}
            for p in verify._SAMPLES}
        if escaped == "/foreign":
            mounts["/foreign"] = {
                "point": "/foreign", "device": "8:1",
                "flags": frozenset({"rw"}), "super_flags": frozenset({"rw"}),
                "fstype": "ext4"}
        return mounts, tuple(mounts.values())
    monkeypatch.setattr(verify, "_mounts", mocked_mounts)
    # Simulate the real /proc/<pid>/root symlink and st_dev through a
    # controlled independent kernel model, not a controller-supplied receipt.
    from pathlib import Path
    original_stat, original_readlink = Path.stat, verify.os.readlink
    original_isdir = Path.is_dir
    original_iterdir = Path.iterdir
    def fake_stat(p, *args, **kw):
        if str(p).startswith("/proc/411/root") or str(p) == str(rootbase):
            # Model the same kernel inode mounted into the test worker and
            # visible through the host registration path on the quota image.
            return SimpleNamespace(st_dev=os.makedev(7, 5),
                                   st_ino=original_stat(rootbase).st_ino,
                                   st_mode=0o40700)
        return original_stat(p, *args, **kw)
    def fake_readlink(p, *args, **kw):
        if str(p) == "/proc/411/root":
            return str(rootbase)
        return original_readlink(p, *args, **kw)
    def fake_isdir(p):
        if str(p) == "/sys/fs/cgroup/zogfreshcrossbootstrapoct25.slice/fake-cgroup":
            return True
        return original_isdir(p)
    def fake_iterdir(p):
        if str(p) == "/proc/411/fd":
            return iter(())
        return original_iterdir(p)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(verify.os, "readlink", fake_readlink)
    monkeypatch.setattr(Path, "is_dir", fake_isdir)
    monkeypatch.setattr(Path, "iterdir", fake_iterdir)
    monkeypatch.setattr(verify, "CGROUP",
                        Path("/sys/fs/cgroup/zogfreshcrossbootstrapoct25.slice"))
    monkeypatch.setattr(verify, "_one", lambda p, **kw:
                        ("0" if str(p).endswith("memory.swap.max")
                         else "100000000"))
    return rootbase


def test_worker_writable_mount_and_root_inode_are_kernel_checked(
        tmp_path, monkeypatch):
    _simulate_worker(monkeypatch, tmp_path)
    evidence = verify._verify_worker(
        411, build_uid=24302, build_gid=24302, build_device=os.makedev(7, 5))
    assert evidence["swap_max"] == 0
    assert evidence["root_dev"] == "7:5"


@pytest.mark.parametrize("escape", ["/tmp", "/run", "/image-build/output",
                                    "/foreign"])
def test_worker_foreign_writable_mount_fails_closed(tmp_path, monkeypatch,
                                                    escape):
    _simulate_worker(monkeypatch, tmp_path, escaped=escape)
    with pytest.raises(RuntimeError, match="writable"):
        verify._verify_worker(
            411, build_uid=24302, build_gid=24302,
            build_device=os.makedev(7, 5))


def test_no_caller_evidence_can_clear_native_admission():
    own = inspect.getsource(owner.NativeOwner.verify_live_storage)
    arm = inspect.getsource(owner.arm_approved)
    watch = inspect.getsource(owner.NativeOwner.sample_exact)
    assert "storage_verifier.inspect_live(" in own
    assert "canary_owner.watch_allowed(" in watch\n    assert "native.verify_live_storage(" in inspect.getsource(owner.canary_owner.watch_allowed)
    assert "owner.verify_empty_storage(plan, a)" in arm
    assert 'unaccounted_writable_roots=[]' not in own + arm + watch
    assert "inspect-native-worker-storage" in inspect.getsource(owner.main)


def test_live_inspection_binds_host_boot_request_project_and_worker(
        monkeypatch):
    plan = {
        "host_id": "i-exact",
        "sha256": "sha256:" + "a"*64,
        "project_root": str(verify.project_state.PROJECT_ROOT),
        "identity": {"controller_uid": 24301, "build_uid": 24302,
                     "build_gid": 24302},
        "installed": {"boot_id": "boot-111"},
    }
    a = {"host_id": "i-exact", "plan_sha256": plan["sha256"],
         "budget_scope": aggregate.BUDGET_SCOPE, "request_id": "a"*32}
    monkeypatch.setattr(verify.os, "geteuid", lambda: 0)
    monkeypatch.setattr(verify, "_one", lambda p, **kw: "boot-111")
    monkeypatch.setattr(verify.quota, "inspect",
                        lambda: {"kernel_enforced": True})
    monkeypatch.setattr(verify.project_state, "inspect",
                        lambda uid: {"mount_verified": uid == 24301})
    monkeypatch.setattr(verify.aggregate, "inspect_external_native",
                        lambda: {"unaccounted_writable_roots": list(
                            aggregate.DEDICATED_UNVERIFIED_WRITERS)})
    checks = []
    monkeypatch.setattr(verify.aggregate, "validate_pre_activation",
                        lambda *args, **kwargs: checks.append("image-policy"))
    monkeypatch.setattr(verify.journal_backing, "inspect",
                        lambda: {"verified": True})
    original_stat = Path.stat
    monkeypatch.setattr(Path, "stat", lambda p, *args, **kwargs:
                        SimpleNamespace(st_dev=os.makedev(7, 5)
                        if str(p) == str(verify.quota.MOUNT)
                        else os.makedev(7, 8)) if str(p) in (
                            str(verify.quota.MOUNT),
                            aggregate.EXTERNAL_MOUNT) else
                        original_stat(p, *args, **kwargs))
    monkeypatch.setattr(verify, "_processes", lambda: [400, 411])
    monkeypatch.setattr(verify, "_uid_gid", lambda pid:
                        {"Uid": (0,)*4} if pid == 400 else
                        {"Uid": (24302,)*4})
    controller_group = ("/" + verify.sidecar.SLICE_UNIT
                        + "/" + verify.sidecar.UNIT)
    monkeypatch.setattr(verify, "_cgroup",
                        lambda pid: controller_group)
    monkeypatch.setattr(verify, "_verify_worker",
                        lambda pid, **kwargs: {"pid": pid,
                                                "root_dev": "7:5"})
    receipt = verify.inspect_live(plan=plan, admission=a, controller_pid=400,
                                  controller_cgroup=controller_group,
                                  host_id="i-exact", boot_id="boot-111")
    assert receipt["status"] == "live-evidence-only"
    assert receipt["workers"] == [{"pid": 411, "root_dev": "7:5"}]
    with pytest.raises(RuntimeError, match="controller PID/cgroup"):
        verify.inspect_live(plan=plan, admission=a, controller_pid=400,
                            controller_cgroup="/old.slice/foreign.service",
                            host_id="i-exact", boot_id="boot-111")
    assert checks == ["image-policy"]
    with pytest.raises(RuntimeError, match="identity drift"):
        verify.inspect_live(plan=plan, admission=a, controller_pid=400,
                            controller_cgroup=controller_group,
                            host_id="i-other", boot_id="boot-111")
    monkeypatch.setattr(verify, "_processes", lambda: [400])
    with pytest.raises(RuntimeError, match="no live finite worker"):
        verify.inspect_live(plan=plan, admission=a, controller_pid=400,
                            controller_cgroup=controller_group,
                            host_id="i-exact", boot_id="boot-111")


def test_worker_cannot_retain_writable_host_regular_fd(tmp_path, monkeypatch):
    _simulate_worker(monkeypatch, tmp_path)
    original_iterdir = Path.iterdir
    original_stat = Path.stat
    original_readlink = verify.os.readlink
    original_one = verify._one

    def foreign_fds(path):
        if str(path) == "/proc/411/fd":
            return iter([path / "7"])
        return original_iterdir(path)

    def foreign_stat(path, *a, **k):
        if str(path) == "/proc/411/fd/7":
            return SimpleNamespace(st_dev=os.makedev(8, 1),
                                   st_mode=0o100600)
        return original_stat(path, *a, **k)

    def foreign_readlink(path, *a, **k):
        if str(path) == "/proc/411/fd/7":
            return "/var/log/old-runner/compiler-escape.log"
        return original_readlink(path, *a, **k)

    def foreign_one(path, **k):
        if str(path) == "/proc/411/fdinfo/7":
            return "flags: 0100002"
        return original_one(path, **k)

    monkeypatch.setattr(Path, "iterdir", foreign_fds)
    monkeypatch.setattr(Path, "stat", foreign_stat)
    monkeypatch.setattr(verify.os, "readlink", foreign_readlink)
    monkeypatch.setattr(verify, "_one", foreign_one)
    with pytest.raises(RuntimeError, match="writable host file descriptor"):
        verify._verify_worker(
            411, build_uid=24302, build_gid=24302,
            build_device=os.makedev(7, 5))


def test_worker_unchanged_cgroup_census_is_required(monkeypatch):
    # Source-negative: the verifier cannot issue an admission based on one
    # snapshot of an active PID set that changed during the inspection.
    body = inspect.getsource(verify._inspect_native)
    assert "first != _processes()" in body
    assert "controller_pid not in first" in body
    assert "not workers" in body
    assert "unknown" not in verify.SCHEMA


def test_kernel_mount_stacks_are_order_independent_and_bounded(monkeypatch):
    raw = "\n".join([
        "43 42 7:5 / /tmp rw - ext4 image rw",
        "30 1 7:5 / / ro - ext4 image ro",
        "42 30 7:5 / /tmp rw - ext4 image rw",
        "47 30 0:12 / /dev rw - tmpfs tmpfs rw",
    ]) + "\n"
    monkeypatch.setattr(verify, "_one", lambda *a, **kw: raw)
    mounts, entries = verify._mounts(411)
    assert mounts["/tmp"]["id"] == 43
    assert len(entries) == 4
    assert len([x for x in entries if x["point"] == "/tmp"]) == 2
    # Duplicate mount without a well-formed stack must never be discarded.
    raw += "49 30 7:5 / /tmp rw - ext4 image rw\n"
    with pytest.raises(RuntimeError, match="ambiguous"):
        verify._mounts(411)


def test_hidden_foreign_mounts_and_hugepages_are_not_free_writes(tmp_path, monkeypatch):
    _simulate_worker(monkeypatch, tmp_path)
    original = verify._mounts
    def layered(pid):
        mounts, all_entries = original(pid)
        hidden = {"point": "/tmp", "device": "8:1", "flags": frozenset({"rw"}),
                  "super_flags": frozenset({"rw"}), "fstype": "ext4"}
        return mounts, all_entries + (hidden,)
    monkeypatch.setattr(verify, "_mounts", layered)
    with pytest.raises(RuntimeError, match="foreign"):
        verify._verify_worker(411, build_uid=24302, build_gid=24302,
                              build_device=os.makedev(7, 5))

    monkeypatch.setattr(verify, "_mounts", original)
    for path in ("/dev/hugepages", "/dev/hugepages/hugepages-2MB"):
        def huge(pid):
            mounts, rows = original(pid)
            entry = {"point": path, "device": "0:32",
                     "flags": frozenset({"rw"}), "super_flags": frozenset({"rw"}),
                     "fstype": "hugetlbfs"}
            return mounts, rows + (entry,)
        monkeypatch.setattr(verify, "_mounts", huge)
        with pytest.raises(RuntimeError, match="hugepage"):
            verify._verify_worker(411, build_uid=24302, build_gid=24302,
                                  build_device=os.makedev(7, 5))
        monkeypatch.setattr(verify, "_mounts", original)


def test_mismatched_worker_root_inode_cannot_pass_same_device(tmp_path, monkeypatch):
    _simulate_worker(monkeypatch, tmp_path)
    original = Path.stat
    def tamper(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if str(path) == "/proc/411/root":
            return SimpleNamespace(st_dev=result.st_dev,
                                   st_ino=result.st_ino + 1,
                                   st_mode=result.st_mode)
        return result
    monkeypatch.setattr(Path, "stat", tamper)
    with pytest.raises(RuntimeError, match="inode"):
        verify._verify_worker(411, build_uid=24302, build_gid=24302,
                              build_device=os.makedev(7, 5))
