"""Fail-closed Project/state mount accounting tests; no retained host changes."""
import inspect as python_inspect
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import fresh_project_state as state
from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_quota_volume as quota


def test_fixed_controller_state_source_is_inside_build_image():
    assert state.SOURCE == quota.MOUNT / "state"
    assert state.DESTINATION == quota.MOUNT.parent / "state"
    assert state.DESTINATION != quota.MOUNT
    assert str(state.DESTINATION).endswith(
        "/fresh-cross-bootstrap-oct25/state")


def _fixture(tmp_path, monkeypatch):
    project = tmp_path / "fresh-cross-bootstrap-oct25"
    work = project / "work"
    source = work / "state"
    dest = project / "state"
    source.mkdir(parents=True, mode=0o700)
    dest.mkdir(mode=0o700)
    os.chmod(project, 0o700)
    os.chmod(work, 0o700)
    os.chmod(source, 0o700)
    os.chmod(dest, 0o700)
    monkeypatch.setattr(state, "PROJECT_ROOT", project)
    monkeypatch.setattr(state, "SOURCE", source)
    monkeypatch.setattr(state, "DESTINATION", dest)
    monkeypatch.setattr(quota, "MOUNT", work)
    monkeypatch.setattr(quota, "inspect", lambda: {
        "backing_device": "/dev/loop7", "image_bytes": 30 * 1024**3,
    })
    return project, work, source, dest


def test_same_device_is_not_a_mount_proof(tmp_path, monkeypatch):
    _, _, source, dest = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(state, "_command", lambda args: pytest.fail(
        "inode mismatch must reject before trusting mount labels"))
    with pytest.raises(RuntimeError, match="escaped"):
        state.inspect(os.getuid() or 1234)


def test_real_bind_identity_requires_loop_source_and_no_nested_mounts(
        tmp_path, monkeypatch):
    _, work, source, dest = _fixture(tmp_path, monkeypatch)
    uid = os.getuid() or 1234
    stat_result = source.stat()
    # Simulate same inode after an actual bind; retain genuine filesystem dev.
    original_directory = state._directory
    monkeypatch.setattr(state, "_directory", lambda path, x, **kwargs:
                        stat_result if Path(path) == dest
                        else original_directory(path, x, **kwargs))
    device = f"{os.major(stat_result.st_dev)}:{os.minor(stat_result.st_dev)}"
    responses = {
        "mountpoint": f"{dest} /dev/loop7[/state] ext4 {device}",
        "submounts": str(dest),
    }
    def command(args):
        return responses["mountpoint" if "--mountpoint" in args else "submounts"]
    monkeypatch.setattr(state, "_command", command)
    # A real controller UID is positive; on root CI the fixture is root-owned,
    # so fake only this positive path's owner assertion.
    if os.getuid() == 0:
        monkeypatch.setattr(state, "_directory", lambda *a, **k: stat_result)
    observed = state.inspect(uid)
    assert observed["mount_verified"] is True
    assert observed["image_bytes"] == 30 * 1024**3
    responses["submounts"] = f"{dest}\n{dest}/escape"
    with pytest.raises(RuntimeError, match="foreign nested mount"):
        state.inspect(uid)
    responses["submounts"] = str(dest)
    responses["mountpoint"] = f"{dest} /dev/loop12[/state] ext4 {device}"
    with pytest.raises(RuntimeError, match="no exact kernel quota bind"):
        state.inspect(uid)


def test_protected_install_fs_syncs_intent_before_fixed_mount(tmp_path, monkeypatch):
    project, work, source, dest = _fixture(tmp_path, monkeypatch)
    source.rmdir()
    log = []
    protected = tmp_path / "owner-state"
    protected.mkdir()
    marker = protected / state.ATTEMPT
    monkeypatch.setattr(state.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state.os, "chown", lambda *a: None)
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "STATE", protected)
    monkeypatch.setattr(owner, "_boot", lambda: "boot-fresh")
    monkeypatch.setattr(owner, "_show", lambda unit: {"LoadState": "not-found"})
    monkeypatch.setattr(state, "_directory", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(owner, "_store", lambda p, x, **kw:
                        log.append(("durable", str(p), x, kw)))
    monkeypatch.setattr(state, "_command", lambda args:
                        log.append(("mount", args)))
    monkeypatch.setattr(state, "inspect", lambda uid: {"mount_verified": True})
    assert state.install_bind(24301)["mount_verified"] is True
    assert log[0][0] == "durable"
    assert log[0][1] == str(marker)
    assert log[0][2]["state"] == "attempted"
    assert log[0][3]["exclusive"] is True
    assert log[1] == ("mount", [
        "/usr/bin/mount", "--bind", str(source), str(dest),
    ])


def test_active_sidecar_is_rejected_before_mount(tmp_path, monkeypatch):
    _, _, source, _ = _fixture(tmp_path, monkeypatch)
    source.rmdir()
    monkeypatch.setattr(state.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(state, "_directory", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(owner, "_show", lambda unit: {"LoadState": "loaded"})
    monkeypatch.setattr(state, "_command", lambda args: pytest.fail(
        "active sidecar may not cause bind mount"))
    with pytest.raises(RuntimeError, match="active/uncertain"):
        state.install_bind(24301)


def test_budget_owner_inspects_bind_before_watching_or_arming():
    sample = python_inspect.getsource(owner.NativeOwner.sample_exact)
    install = python_inspect.getsource(owner.install_approved)
    arm = python_inspect.getsource(owner.arm_approved)
    recovery = python_inspect.getsource(owner.recover)
    assert "project_state.inspect(" in sample
    assert "project_state.install_bind(" in install
    assert install.index("project_state.install_bind(") < install.index(
        "sidecar.install(")
    assert "project_state.inspect(" in arm
    assert "project-state-bind-unverified-no-replay" in recovery
