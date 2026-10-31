"""Source-only protected cgroup2 HugeTLB activation tests (NO real PID1 writes)."""
from pathlib import Path

import pytest

from zog.host_deploy.gateway import fresh_hugetlb_activation as huge
from zog.host_deploy.gateway import fresh_native_owner as owner


def fixture(tmp_path, monkeypatch, *, enabled=True):
    root = tmp_path / "cgroup2"
    child = root / huge.sidecar.SLICE_UNIT
    child.mkdir(parents=True)
    (root / "cgroup.controllers").write_text("cpu hugetlb memory")
    (root / "cgroup.subtree_control").write_text(
        "cpu hugetlb" if enabled else "cpu")
    (child / "cgroup.controllers").write_text("hugetlb memory")
    (child / "hugetlb.2MB.max").write_text("max")
    (child / "hugetlb.2MB.rsvd.max").write_text("max")
    monkeypatch.setattr(huge, "CGROUP_ROOT", root)
    monkeypatch.setattr(huge, "SLICE", child)
    monkeypatch.setattr(huge, "_mountinfo", lambda:
                        f"30 1 0:40 / {root} rw - cgroup2 cgroup rw")
    # GitHub's unprivileged fixture owns only disposable test paths.
    from types import SimpleNamespace
    real_lstat = Path.lstat
    def protected_lstat(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        if path in (root, child):
            return SimpleNamespace(st_mode=st.st_mode, st_uid=0, st_gid=0,
                                   st_dev=st.st_dev, st_ino=st.st_ino)
        return st
    monkeypatch.setattr(Path, "lstat", protected_lstat)
    snap = huge.snapshot()
    approval = {
        "schema": huge.APPROVAL_SCHEMA, "status": "operator-approved",
        "host_id": "i-disposable", "boot_id": "boot-one",
        "plan_sha256": "sha256:" + "a"*64,
        "slice_unit": huge.sidecar.SLICE_UNIT,
        "scope": huge.APPROVED_SCOPE,
        "allow_shared_root_change": True,
        **{name: snap[name] for name in (
            "root_device", "root_inode", "slice_device", "slice_inode",
            "root_subtree_sha256")},
    }
    return root, child, approval


def test_approval_is_explicit_boot_and_ancestor_bound(tmp_path, monkeypatch):
    root, child, approval = fixture(tmp_path, monkeypatch)
    before = huge.snapshot()
    huge.validate_approval(approval, host_id="i-disposable",
                           boot_id="boot-one", plan_sha256="sha256:"+"a"*64,
                           before=before)
    for change in (
        {"boot_id": "boot-two"},
        {"allow_shared_root_change": False},
        {"root_inode": -1},
        {"root_subtree_sha256": "b"*64},
        {"status": "pending"},
    ):
        invalid = dict(approval, **change)
        with pytest.raises(PermissionError, match="approval"):
            huge.validate_approval(invalid, host_id="i-disposable",
                boot_id="boot-one", plan_sha256="sha256:"+"a"*64,
                before=before)


def test_source_snapshot_rejects_wrong_ancestry_and_substituted_cgroup(tmp_path, monkeypatch):
    root, child, _ = fixture(tmp_path, monkeypatch)
    assert "hugetlb" in huge.snapshot()["root_enabled"]
    monkeypatch.setattr(huge, "_mountinfo", lambda:
                        f"30 1 0:40 / {root} rw - tmpfs other rw")
    with pytest.raises(RuntimeError, match="cgroup2"):
        huge.snapshot()
    monkeypatch.setattr(huge, "_mountinfo", lambda:
                        f"30 1 0:40 / {root} rw - cgroup2 cgroup rw")
    child.chmod(0o777)
    with pytest.raises(RuntimeError, match="unprotected HugeTLB"):
        huge.snapshot()
    child.chmod(0o755)
    monkeypatch.setattr(huge, "_mountinfo", lambda:
                        f"30 1 0:40 /subtree {root} rw - cgroup2 cgroup rw")
    with pytest.raises(RuntimeError, match="PID1 root cgroup2"):
        huge.snapshot()
    monkeypatch.setattr(huge, "_mountinfo", lambda:
                        f"30 1 0:40 / {root} rw - cgroup2 cgroup rw")
    from types import SimpleNamespace
    original_stat = Path.stat
    def wrong_namespace(path, *args, **kwargs):
        if str(path).startswith("/proc/") and str(path).endswith("/ns/cgroup"):
            return SimpleNamespace(st_ino=12 if "/self/" in str(path) else 13,
                                   st_dev=4)
        return original_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", wrong_namespace)
    with pytest.raises(RuntimeError, match="outside PID1 cgroup namespace"):
        huge.snapshot()
    monkeypatch.setattr(Path, "stat", original_stat)
    child.rename(root / "moved")
    child.symlink_to(root / "moved", target_is_directory=True)
    with pytest.raises(RuntimeError, match="unprotected"):
        huge.snapshot()


def test_native_selected_activation_and_reboot_drift(tmp_path, monkeypatch):
    root, child, approval = fixture(tmp_path, monkeypatch, enabled=True)
    monkeypatch.setattr(huge.os, "geteuid", lambda: 0)
    orig = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **kw:
                        "systemd\n" if str(self) == "/proc/1/comm"
                        else orig(self, *a, **kw))
    receipt = huge.activate_with_approval(
        approval, host_id="i-disposable", boot_id="boot-one",
        plan_sha256="sha256:"+"a"*64)
    assert receipt["status"] == "activated-needs-native-review"
    huge.recheck(receipt, host_id="i-disposable", boot_id="boot-one",
                 plan_sha256="sha256:"+"a"*64)
    with pytest.raises(RuntimeError, match="drifted"):
        huge.recheck(receipt, host_id="i-disposable", boot_id="boot-two",
                     plan_sha256="sha256:"+"a"*64)
    (root / "cgroup.subtree_control").write_text("cpu")
    with pytest.raises(RuntimeError, match="drifted"):
        huge.recheck(receipt, host_id="i-disposable", boot_id="boot-one",
                     plan_sha256="sha256:"+"a"*64)
    (root / "cgroup.subtree_control").write_text("cpu hugetlb")
    old_child = root / "unloaded-old-slice"
    child.rename(old_child)
    child.mkdir()
    (child / "cgroup.controllers").write_text("hugetlb memory")
    (child / "hugetlb.2MB.max").write_text("max")
    (child / "hugetlb.2MB.rsvd.max").write_text("max")
    # Even matching restored limit filenames may not authenticate a
    # replacement PID1 slice. It is a different kernel cgroup inode.
    with pytest.raises(RuntimeError, match="drifted"):
        huge.recheck(receipt, host_id="i-disposable", boot_id="boot-one",
                     plan_sha256="sha256:"+"a"*64)


def test_explicit_root_activation_writes_only_fixed_controller(tmp_path, monkeypatch):
    root, child, approval = fixture(tmp_path, monkeypatch, enabled=False)
    monkeypatch.setattr(huge.os, "geteuid", lambda: 0)
    orig_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **kw:
                        "systemd\n" if str(self) == "/proc/1/comm"
                        else orig_text(self, *a, **kw))
    writes = []
    real_write = huge.os.write
    def kernel_write(fd, data):
        writes.append(data)
        if data == b"+hugetlb":
            (root / "cgroup.subtree_control").write_text("cpu hugetlb")
            return len(data)
        return real_write(fd, data)
    monkeypatch.setattr(huge.os, "write", kernel_write)
    receipt = huge.activate_with_approval(
        approval, host_id="i-disposable", boot_id="boot-one",
        plan_sha256="sha256:"+"a"*64)
    assert writes == [b"+hugetlb"]
    assert receipt["status"] == "activated-needs-native-review"
    assert "cpu" in huge.snapshot()["root_enabled"]


def test_host_owner_arm_never_auto_activates_and_recover_does_not_reenable():
    import inspect
    code = inspect.getsource(owner.arm_approved)
    assert "activate_with_approval(" not in code
    assert "hugetlb.recheck(" in code
    assert "seal_hugetlb_before_arm(" in code
    recovery = inspect.getsource(owner.recover)
    assert "activate_with_approval(" not in recovery
    assert "activate_hugetlb_approved(" not in recovery
