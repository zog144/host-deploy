"""Disposable Linux-owner tests. Never run real mkfs, mount, PID1 or cron.

The production implementation performs real syscalls, not fake interfaces;
native Stage A subsequently proves those effects on a disposable host.
"""
from copy import deepcopy
from pathlib import Path

import pytest

from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_quota_volume as quota
from zog.host_deploy.gateway import fresh_budget_guard as budget
from zog.host_deploy.gateway import fresh_sidecar_install as sidecar


def test_cron_contains_fixed_watch_and_boot_hooks(monkeypatch):
    plan = {
        "identity": {"python_executable": "/usr/bin/python3"},
        "installed": {"host_deploy_python_root": "/opt/zog/accepted/host-deploy/src"},
    }
    monkeypatch.setattr(owner, "_read_json", lambda path: plan)
    contents = owner.schedule_text()
    assert "* * * * * root PYTHONPATH=/opt/zog/accepted/host-deploy/src" in contents
    assert " -B -m zog.host_deploy.gateway.fresh_native_owner watch\n" in contents
    assert "@reboot root " in contents
    assert contents.count("root ") == 2
    assert "daemon-reload" not in contents
    plan["installed"]["host_deploy_python_root"] = "/tmp/invalid path"
    with pytest.raises(PermissionError, match="unreviewed scheduler"):
        owner.schedule_text()


def test_quota_refuses_extra_mutable_root_or_unapproved_disk(monkeypatch):
    monkeypatch.setattr(quota.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="capacity or mutable"):
        quota.provision(
            available_after_reservations_bytes=budget.ADDITIONAL_DISK_BYTES - 1,
            mounted_writable_roots=[str(quota.MOUNT)])
    with pytest.raises(RuntimeError, match="capacity or mutable"):
        quota.provision(
            available_after_reservations_bytes=budget.ADDITIONAL_DISK_BYTES,
            mounted_writable_roots=[str(quota.MOUNT), "/var/lib/zog/shared"])
    with pytest.raises(RuntimeError, match="capacity or mutable"):
        quota.provision(
            available_after_reservations_bytes=budget.ADDITIONAL_DISK_BYTES,
            mounted_writable_roots=[])


def test_fixed_slice_matches_start_transient_and_scoped_kernel_target():
    assert sidecar.SLICE_UNIT == owner.SLICE_UNIT
    assert owner.CGROUP == Path("/sys/fs/cgroup") / sidecar.SLICE_UNIT
    assert not "-" in sidecar.SLICE_UNIT  # no systemd slice-name hierarchy
    assert str(owner.CGROUP / "cgroup.kill").startswith(
        "/sys/fs/cgroup/zogfreshcrossbootstrapoct25.slice/")


def test_cancel_only_frozen_fresh_cgroup_and_original_cancellation_id(tmp_path, monkeypatch):
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "_slice_identity", lambda: {"ActiveState": "active"})
    monkeypatch.setattr(owner, "CGROUP", tmp_path)
    (tmp_path / "cgroup.kill").write_text("")
    x = budget.begin(
        request_id="f"*32, host_id="i-fresh", project_root="/home/zog-cross-owner/fresh-cross-bootstrap-oct25",
        boot_id="boot", now_seconds=100, monotonic_seconds=30,
        used_bytes=0, sidecar_plan_sha256="sha256:"+"a"*64,
        monitor_receipt_sha256="sha256:"+"b"*64,
    )
    x["status"] = "stop_attempted"
    x["stop_reason"] = "aggregate-budget-uncertain"
    monkeypatch.setattr(owner.budget, "read", lambda directory, request: x)
    # Simulate the kernel populated flag readback before and after cgroup.kill.
    count = {"read": 0}
    def events():
        count["read"] += 1
        return {"populated": "1" if count["read"] == 1 else "0"}
    monkeypatch.setattr(owner, "_events", events)
    native = owner.NativeOwner()
    with pytest.raises(PermissionError, match="grant differs"):
        native.cancel_exact_project(x["project_root"], x["request_id"],
                                    reason=x["stop_reason"], cancellation_id="0"*64)
    answer = native.cancel_exact_project(
        x["project_root"], x["request_id"], reason=x["stop_reason"],
        cancellation_id=x["cancellation_id"])
    assert (tmp_path / "cgroup.kill").read_text() == "1\n"
    assert answer["confirmed"] is True
    assert answer["request_id"] == x["request_id"]
    assert answer["cancellation_id"] == x["cancellation_id"]


def test_reboot_reconciles_quota_and_stores_blocked_receipt_without_submit(tmp_path, monkeypatch):
    boot = "03fecc0f-boot"
    monkeypatch.setattr(owner, "STATE", tmp_path)
    monkeypatch.setattr(owner, "_boot", lambda: boot)
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "verify_schedule", lambda: True)
    monkeypatch.setattr(owner.quota, "reattach_after_boot", lambda: {
        "capacity_bytes": budget.ADDITIONAL_DISK_BYTES - 1,
    })
    recorded = {}
    def store(path, value, *, exclusive=False):
        assert exclusive is True
        recorded[str(path)] = value
        path.write_text(owner._bytes(value).decode())
    monkeypatch.setattr(owner, "_store", store)
    monkeypatch.setattr(owner, "_read_json", lambda path: recorded[str(path)])
    calls = []
    monkeypatch.setattr(owner, "watch", lambda: calls.append("watch"))
    owner.recover()
    assert calls == ["watch"]
    assert recorded[str(tmp_path / ("reboot-" + boot + ".json"))]["status"] == (
        "observed-reboot-needs-fresh-controller-attestation")
    owner.recover()
    assert calls == ["watch", "watch"]
    assert len(recorded) == 1


def test_admission_freezes_unique_request_and_mount_under_approved_plan(monkeypatch):
    plan = {"sha256": "sha256:"+"a"*64, "host_id": "i-new"}
    receipt = {
        "schema": "host-deploy-fresh-native-admission-v1",
        "plan_sha256": plan["sha256"], "host_id": "i-new",
        "request_id": "f"*32, "seed_generation": "new-immutable",
        "seed_manifest_sha256": "sha256:"+"c"*64,
        "capabilities_sha256": "sha256:"+"d"*64,
        "available_after_reservations_bytes": budget.ADDITIONAL_DISK_BYTES,
        "writable_roots": [str(quota.MOUNT)], "fresh_slice": sidecar.SLICE_UNIT,
    }
    monkeypatch.setattr(owner, "_read_json", lambda path: receipt)
    assert owner._admission(plan) == receipt
    bad = deepcopy(receipt)
    bad["writable_roots"] = ["/state/old-root"]
    monkeypatch.setattr(owner, "_read_json", lambda path: bad)
    with pytest.raises(RuntimeError, match="native admission differs"):
        owner._admission(plan)
    bad = deepcopy(receipt)
    bad["request_id"] = "371da99f23764180aad37d8e4e83595b"
    # Historical request must also be excluded by original request-specific
    # host owner; this scope only proves syntax and new/old separate binding.
    monkeypatch.setattr(owner, "_read_json", lambda path: bad)
    assert owner._admission(plan)["request_id"] == bad["request_id"]
