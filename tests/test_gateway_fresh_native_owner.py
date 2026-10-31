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
from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_sidecar_install as sidecar


def test_cron_contains_fixed_watch_and_boot_hooks(monkeypatch):
    plan = {
        "identity": {"python_executable": "/usr/bin/python3"},
        "installed": {"host_deploy_python_root": "/opt/zog/accepted/host-deploy/src"},
    }
    monkeypatch.setattr(owner, "_read_json", lambda path: plan)
    contents = owner.schedule_text()
    assert "* * * * * root PYTHONPATH=/opt/zog/accepted/host-deploy/src" in contents
    assert " -B -m zog.host_deploy.gateway.fresh_native_owner watch >>" in contents
    assert contents.count(">>" + owner.CRON_LOG + " 2>&1") == 2
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
            available_after_reservations_bytes=aggregate.BUILD_BYTES - 1,
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
    # Native sealing is independently tested with a temporary cgroup tree.
    monkeypatch.setattr(owner.storage_verifier, "seal_hugetlb_before_arm",
                        lambda pid: None if pid == 123 else pytest.fail("wrong controller"))
    monkeypatch.setattr(owner.project_state, "inspect",
                        lambda uid: {"mount_verified": True} if uid == 24301
                        else pytest.fail("wrong reviewed controller UID"))
    monkeypatch.setattr(owner.project_state, "inspect",
                        lambda uid: {"mount_verified": True} if uid == 24301
                        else pytest.fail("wrong controller UID"))
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
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner.aggregate, "reattach_external_after_boot",
                        lambda: {"limit_bytes": aggregate.EXTERNAL_BYTES})
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
        "schema": "host-deploy-fresh-native-admission-dedicated-v2",
        "budget_scope": aggregate.BUDGET_SCOPE,
        "plan_sha256": plan["sha256"], "host_id": "i-new",
        "request_id": "f"*32, "seed_generation": "new-immutable",
        "seed_manifest_sha256": "sha256:"+"c"*64,
        "capabilities_sha256": "sha256:"+"d"*64,
        "available_after_reservations_bytes": budget.ADDITIONAL_DISK_BYTES,
        "writable_roots": [str(quota.MOUNT)], "fresh_slice": sidecar.SLICE_UNIT,
    }
    monkeypatch.setattr(owner, "_read_json", lambda path: receipt)
    assert owner._admission(plan) == receipt
    old_policy = deepcopy(receipt)
    old_policy["schema"] = "host-deploy-fresh-native-admission-v1"
    monkeypatch.setattr(owner, "_read_json", lambda path: old_policy)
    with pytest.raises(RuntimeError, match="native admission differs"):
        owner._admission(plan)
    changed_scope = deepcopy(receipt)
    changed_scope["budget_scope"] = "strict-total-host-writes"
    monkeypatch.setattr(owner, "_read_json", lambda path: changed_scope)
    with pytest.raises(RuntimeError, match="native admission differs"):
        owner._admission(plan)
    monkeypatch.setattr(owner, "_read_json", lambda path: receipt)
    bad = deepcopy(receipt)
    bad["writable_roots"] = ["/state/old-root"]
    monkeypatch.setattr(owner, "_read_json", lambda path: bad)
    with pytest.raises(RuntimeError, match="native admission differs"):
        owner._admission(plan)
    bad = deepcopy(receipt)
    bad["request_id"] = "371da99f23764180aad37d8e4e83595b"
    monkeypatch.setattr(owner, "_read_json", lambda path: bad)
    with pytest.raises(RuntimeError, match="native admission differs"):
        owner._admission(plan)



def test_storage_preparation_before_installer_and_pid1(tmp_path, monkeypatch):
    """Exercise install orchestrator through fixed root-owned syscall adapters."""
    calls = []
    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(owner, "STATE", state)
    monkeypatch.setattr(owner, "BUDGET_DIR", state / "budget")
    monkeypatch.setattr(owner, "_budget_directory_prepared",
                        lambda *, require_empty: calls.append(
                            "budget-ready" if require_empty else "budget-observe"))
    (state / "budget").mkdir(mode=0o700)
    monkeypatch.setattr(owner.budget, "_protected_root", lambda path: Path(path))
    monkeypatch.setattr(owner, "_root", lambda: None)
    plan = {
        "host_id": "test-host",
        "sha256": "sha256:"+"a"*64, "identity": {
            "build_uid": 24302, "build_gid": 24302,
            "controller_uid": 24301,
        }, "installed": {"legacy_baseline_sha256": "sha256:"+"b"*64,
                         "watchdog_receipt_sha256": owner._sha(b"fixed cron")},
    }
    monkeypatch.setattr(owner, "_read_json", lambda path: plan)
    monkeypatch.setattr(sidecar, "review_plan", lambda *_: plan)
    monkeypatch.setattr(owner, "_admission", lambda plan: {
        "available_after_reservations_bytes": budget.ADDITIONAL_DISK_BYTES,
        "writable_roots": [str(quota.MOUNT)],
    })
    class Back:
        def verify_source_and_nss(self, plan): calls.append("native-attest")
        def validate_old_baseline(self, digest): calls.append("old-baseline")
        def is_trusted_native_owner(self): return True
    monkeypatch.setattr(owner, "NativeOwner", Back)
    monkeypatch.setattr(owner, "schedule_text", lambda: "fixed cron")
    monkeypatch.setattr(owner, "install_schedule",
                        lambda: calls.append("persistent-cron"))
    monkeypatch.setattr(owner, "_show", lambda unit: {
        "LoadState": "not-found" if unit == owner.independent_watchdog.UNIT
        and "pid1-watchdog" not in calls else "loaded",
        "ActiveState": "active", "MainPID": "123",
        "ControlGroup": "/system.slice/" + owner.independent_watchdog.UNIT,
    })
    monkeypatch.setattr(owner, "WATCHDOG_ATTEMPT",
                        state / "watchdog-attempt.json")
    monkeypatch.setattr(owner.independent_watchdog, "start",
                        lambda plan, *, on_ack: (
                            on_ack("/org/freedesktop/systemd1/job/42"),
                            calls.append("pid1-watchdog"),
                            {"job_path": "/org/freedesktop/systemd1/job/42",
                             "job_result": "done"})[-1])
    monkeypatch.setattr(owner.independent_watchdog, "properties",
                        lambda plan: {"ExecStart": ["fixed-watch"], "Environment": []})
    monkeypatch.setattr(owner, "_wait_exact_watchdog", lambda plan: {
        "LoadState": "loaded", "ActiveState": "active",
        "MainPID": "123", "InvocationID": "a"*32,
        "ControlGroup": "/system.slice/" + owner.independent_watchdog.UNIT,
    })
    monkeypatch.setattr(owner, "_boot", lambda: "test-boot")
    def provision(**kwargs):
        calls.append("kernel-quota")
        assert kwargs["mounted_writable_roots"] == [str(quota.MOUNT)]
        return {"capacity_bytes": aggregate.BUILD_BYTES}
    monkeypatch.setattr(quota, "provision", provision)
    monkeypatch.setattr(owner.project_state, "install_bind",
                        lambda uid: calls.append("project-state-bind") if uid == 24301
                        else pytest.fail("wrong controller UID"))
    # This fixture exercises ordering; aggregate kernel proof has separate
    # real policy/negative tests in test_gateway_aggregate_budget.py.
    monkeypatch.setattr(owner.aggregate, "inspect_external_native", lambda: {})
    monkeypatch.setattr(owner.aggregate, "inspect_external_pool_native", lambda: {})
    monkeypatch.setattr(owner.aggregate, "validate", lambda *a, **k: True)
    monkeypatch.setattr(owner.aggregate, "validate_pre_activation", lambda *a, **k: True)
    monkeypatch.setattr(quota, "inspect", lambda: {"capacity_bytes": aggregate.BUILD_BYTES})
    monkeypatch.setattr(owner.project_state, "inspect", lambda uid: {"mount_verified": True})
    monkeypatch.setattr(owner.os, "chown", lambda *a: calls.append("quota-owner"))
    monkeypatch.setattr(owner.os, "chmod", lambda *a: calls.append("quota-mode"))
    monkeypatch.setattr(sidecar, "install", lambda p, *, host_owner:
                        (calls.append("pid1-start") or {
                            "plan_sha256": p["sha256"], "invocation_id": "new-only",
                        }))
    saved = {}
    def store(path, item, *, exclusive):
        saved[path] = owner._bytes(item)
        calls.append("watchdog-attempt" if path == owner.WATCHDOG_ATTEMPT
                     else "activation-checkpoint")
    monkeypatch.setattr(owner, "_store", store)
    monkeypatch.setattr(owner, "_file", lambda path: saved[path])
    prepared = owner.prepare_work()
    assert prepared["compiler_authorized"] is False
    result = owner.install_approved()
    assert result["invocation_id"] == "new-only"
    assert calls.index("budget-ready") < calls.index("kernel-quota")
    assert calls.index("kernel-quota") < calls.index("persistent-cron")
    assert calls.index("kernel-quota") < calls.index("project-state-bind")
    assert calls.index("project-state-bind") < calls.index("pid1-watchdog")
    assert calls.index("kernel-quota") < calls.index("pid1-watchdog")
    assert calls.index("watchdog-attempt") < calls.index("pid1-watchdog")
    assert calls.index("pid1-watchdog") < calls.index("pid1-start")
    assert calls.index("kernel-quota") < calls.index("pid1-start")
    assert calls.index("pid1-start") < len(calls)-1
    assert calls[-1] == "activation-checkpoint"
    assert calls.count("old-baseline") == 4


def test_concrete_arm_freezes_one_request_after_live_quota_and_slice(tmp_path, monkeypatch):
    x = {
        "sha256": "sha256:"+"a"*64, "host_id": "i-fresh",
        "project_root": "/home/zog-cross-owner/fresh-cross-bootstrap-oct25",
        "identity": {"controller_uid": 24301},
        "installed": {"legacy_baseline_sha256": "sha256:"+"b"*64,
                     "watchdog_receipt_sha256": "sha256:"+"c"*64},
    }
    original = "f"*32
    monkeypatch.setattr(owner.canary_owner, "require_gate_source",
                        lambda plan: None)
    monkeypatch.setattr(owner, "_budget_directory_prepared",
                        lambda *, require_empty: True)
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "_read_json", lambda path:
                        {"plan_sha256": x["sha256"]} if path in (
                            owner.STATE / "activation.json", owner.WATCHDOG_ATTEMPT)
                        else x)
    monkeypatch.setattr(owner, "_admission", lambda plan: {
        "request_id": original, "host_id": x["host_id"],
    })
    class Native:
        def validate_old_baseline(self, digest): assert digest == "sha256:"+"b"*64
        def observe_unit(self, unit): return {"active": True}
        def is_trusted_native_owner(self): return True
        def verify_empty_storage(self, plan, admission):
            assert admission["request_id"] == original
            return {"status": "verified-empty-lane-not-start-authority"}
    monkeypatch.setattr(owner, "NativeOwner", Native)
    monkeypatch.setattr(owner, "verify_schedule", lambda: True)
    monkeypatch.setattr(owner, "_show", lambda unit: {
        "ActiveState": "active", "MainPID": "123",
        "LoadState": "not-found" if unit == owner.hard_deadline.UNIT else "loaded",
        "Unit": owner.hard_deadline.STOP_UNIT,
        "NextElapseUSecMonotonic": "999999999999",
    })
    monkeypatch.setattr(owner, "DEADLINE_ATTEMPT", tmp_path / "deadline.json")
    monkeypatch.setattr(owner, "_store", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner.hard_deadline, "start", lambda plan: None)
    # The service becomes visible after the simulated PID1 call.
    timer_started = {"value": False}
    monkeypatch.setattr(owner.hard_deadline, "start",
                        lambda plan: timer_started.update(value=True))
    monkeypatch.setattr(owner, "_show", lambda unit: {
        "ActiveState": "active", "MainPID": "123",
        "LoadState": ("loaded" if timer_started["value"] else "not-found")
                     if unit == owner.hard_deadline.UNIT else "loaded",
        "Unit": owner.hard_deadline.STOP_UNIT,
        "NextElapseUSecMonotonic": "999999999999",
    })
    monkeypatch.setattr(owner.aggregate, "inspect_external_native", lambda: {})
    monkeypatch.setattr(owner.aggregate, "validate", lambda *a, **k: True)
    monkeypatch.setattr(owner, "_slice_identity", lambda: {"ActiveState": "active"})
    x["installed"]["host_id"] = "i-fresh"
    monkeypatch.setattr(owner.hugetlb, "recheck",
                        lambda receipt, *, host_id, boot_id, plan_sha256:
                        True if (host_id, boot_id, plan_sha256) ==
                        ("i-fresh", "fresh-boot", x["sha256"])
                        else pytest.fail("HugeTLB reboot/identity drift"))
    monkeypatch.setattr(owner.storage_verifier, "seal_hugetlb_before_arm",
                        lambda pid: None if pid == 123 else pytest.fail("wrong controller"))
    monkeypatch.setattr(owner.project_state, "inspect",
                        lambda uid: {"mount_verified": True} if uid == 24301
                        else pytest.fail("wrong controller UID"))
    monkeypatch.setattr(owner, "_boot", lambda: "fresh-boot")
    monkeypatch.setattr(quota, "inspect", lambda: {
        "capacity_bytes": aggregate.BUILD_BYTES,
        "image_bytes": aggregate.BUILD_BYTES,
        "used_bytes": 4096, "kernel_enforced": True,
        "mount": str(quota.MOUNT),
    })
    monkeypatch.setattr(owner.time, "time", lambda: 100000)
    monkeypatch.setattr(owner.time, "monotonic", lambda: 1000)
    record = []
    monkeypatch.setattr(owner.budget, "write_once",
                        lambda path, value: record.append(value))
    armed = []
    monkeypatch.setattr(owner.canary_owner, "arm_empty",
                        lambda host, native, plan, admission: armed.append(
                            admission["request_id"]))
    result = owner.arm_approved()
    assert result["request_id"] == original
    assert result["dedicated_build_capacity_bytes"] == aggregate.BUILD_BYTES
    assert len(record) == 1 and record[0]["request_id"] == original
    assert record[0]["status"] == "active"
    assert armed == [original]



def test_actual_shared_and_historical_bad_setting_observation_is_frozen(monkeypatch):
    shared = {"LoadState": "loaded", "ActiveState": "active",
              "MainPID": "1234", "InvocationID": "old-accepted-invocation",
              "FragmentPath": "/run/systemd/transient/root-control.service"}
    historical = {"LoadState": "bad-setting", "ActiveState": "inactive",
                  "MainPID": "0", "InvocationID": "",
                  "FragmentPath": "/run/systemd/transient/old-build.service"}
    receipt = {"shared_unit": "zog-root-control.service",
               "root_control_show": shared,
               "historical_unit": "old-build.service",
               "historical_show": historical,
               "historical_bad_setting_sha256": owner._sha(owner._bytes(historical))}
    monkeypatch.setattr(owner, "_read_json", lambda path: receipt)
    observed = {"zog-root-control.service": shared, "old-build.service": historical}
    def inspect(unit):
        return observed[unit]
    monkeypatch.setattr(owner, "_show", inspect)
    digest = owner._legacy()
    assert digest == owner._sha(owner._bytes(receipt))
    observed["old-build.service"] = dict(historical, LoadState="not-found")
    with pytest.raises(RuntimeError, match="bad-setting PID1 evidence"):
        owner._legacy()
    observed["old-build.service"] = historical
    observed["zog-root-control.service"] = dict(shared, InvocationID="changed")
    with pytest.raises(RuntimeError, match="shared controller"):
        owner._legacy()



def test_f1_real_root_owned_directory_can_have_multiple_links():
    import os
    from zog.host_deploy.gateway import fresh_quota_volume as quota
    directory = Path("/usr")
    st = directory.lstat()
    if st.st_uid != 0 or st.st_nlink <= 1:
        pytest.skip("CI host has no suitable real protected root-owned directory")
    assert quota._private(directory) == directory
    assert st.st_nlink > 1


def test_f4_real_mkfs_nodiscard_preserves_preallocation(tmp_path):
    import os
    import shutil
    import subprocess
    from zog.host_deploy.gateway import fresh_quota_volume as quota
    mkfs = shutil.which("mkfs.ext4")
    if mkfs is None or not hasattr(os, "posix_fallocate"):
        pytest.skip("real mke2fs/posix_fallocate unavailable")
    image = tmp_path / "disposable-64MiB.img"
    with image.open("xb") as out:
        os.posix_fallocate(out.fileno(), 0, 64*1024**2)
        os.fsync(out.fileno())
    before = image.stat()
    assert before.st_blocks*512 >= before.st_size
    assert image.stat().st_size == 64*1024**2
    assert "nodiscard" in quota.provision.__code__.co_consts.__repr__()
    result = subprocess.run([mkfs, "-F", "-m", "0", "-E", "nodiscard",
                             str(image)], capture_output=True, text=True,
                            timeout=30)
    assert result.returncode == 0, result.stderr
    after = image.stat()
    assert after.st_size == before.st_size
    assert after.st_blocks*512 >= after.st_size


def test_f2_historical_unit_readback_uses_real_regex_and_systemctl_adapter(monkeypatch):
    commands = []
    def command(args, *, timeout=15):
        commands.append(args)
        return ("LoadState=bad-setting\nActiveState=inactive\n"
                "MainPID=0\nInvocationID=\nControlGroup=\nEnvironment=\n"
                "FragmentPath=/run/systemd/transient/old-build.service")
    monkeypatch.setattr(owner, "_read_json", lambda path: {
        "historical_unit": "zog-image-build-original@build.service",
    })
    monkeypatch.setattr(owner, "_command", command)
    result = owner._show("zog-image-build-original@build.service")
    assert result["LoadState"] == "bad-setting"
    assert commands[0][2] == "zog-image-build-original@build.service"
    with pytest.raises(ValueError, match="unapproved"):
        owner._show("unreviewed.service")
    with pytest.raises(ValueError, match="unapproved"):
        owner._show("zog-image-build-original@buildXservice")


def test_f3_retained_certbot_seed_root_is_preserved_without_rename(monkeypatch):
    shared = {
        "LoadState": "loaded", "ActiveState": "active", "MainPID": "31242",
        "InvocationID": "original-invocation-not-to-restart",
        "FragmentPath": "/run/systemd/transient/zog-certbot-seed-root.service",
    }
    historical = {"LoadState": "bad-setting", "ActiveState": "inactive",
                  "MainPID": "0", "InvocationID": ""}
    receipt = {"shared_unit": "zog-certbot-seed-root.service",
               "root_control_show": shared,
               "historical_unit": "zog-image-build-original@build.service",
               "historical_show": historical,
               "historical_bad_setting_sha256": owner._sha(owner._bytes(historical))}
    seen = []
    monkeypatch.setattr(owner, "_read_json", lambda path: receipt)
    def command(args, *, timeout=15):
        seen.append(args[2])
        return "\n".join(f"{k}={v}" for k,v in (
            shared if args[2] == receipt["shared_unit"] else historical).items())
    monkeypatch.setattr(owner, "_command", command)
    assert owner._legacy() == owner._sha(owner._bytes(receipt))
    assert seen == [receipt["shared_unit"], receipt["historical_unit"]]
    assert all(arg[0] == "/usr/bin/systemctl" for arg in (
        ["/usr/bin/systemctl", "show", x] for x in seen))


def test_f5_cron_loss_does_not_short_circuit_budget_cancellation(monkeypatch):
    from zog.host_deploy.gateway import fresh_watchdog_service as independent
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner.budget, "_protected_root", lambda path: Path(path))
    monkeypatch.setattr(owner, "BUDGET_DIR", Path("/ignored/disposable"))
    monkeypatch.setattr(Path, "glob", lambda *args: iter([Path("f"*32+".json")]))
    observed = []
    monkeypatch.setattr(owner.budget, "watch_once",
                        lambda path, request, *, native_owner:
                        observed.append((request, native_owner)))
    monkeypatch.setattr(owner, "_show",
                        lambda unit: {"ActiveState": "inactive" if unit ==
                                    owner.CRON_SERVICE else "active"})
    monkeypatch.setattr(owner, "verify_schedule", lambda: True)
    monkeypatch.setattr(quota, "inspect", lambda: {"used_bytes": 100})
    monkeypatch.setattr(owner.aggregate, "inspect_external_native", lambda: {})
    monkeypatch.setattr(owner.aggregate, "validate", lambda *a, **k: True)
    monkeypatch.setattr(owner, "_boot", lambda: "boot")
    monkeypatch.setattr(owner, "_read_json", lambda path: {
        "identity": {"controller_uid": 24301},
        "host_id": "i-fresh", "project_root": "/reviewed-project"})
    monkeypatch.setattr(owner, "_admission", lambda plan: {
        "request_id": "f"*32, "host_id": "i-fresh",
    })
    monkeypatch.setattr(owner.NativeOwner, "verify_live_storage",
                        lambda self, plan, admission: {"status": "live-evidence-only"})
    monkeypatch.setattr(owner.project_state, "inspect",
                        lambda uid: {"mount_verified": True} if uid == 24301
                        else pytest.fail("wrong controller UID"))
    from contextlib import nullcontext
    monkeypatch.setattr(owner.canary_owner, "locked", lambda host: nullcontext())
    monkeypatch.setattr(owner.canary_owner, "watch_allowed",
                        lambda **kw: {"status": "native-idle-only"})
    sample = owner.NativeOwner().sample_exact({
        "request_id": "f"*32,
        "host_id": "i-fresh", "project_root": "/reviewed-project",
        "monitor_receipt_sha256": "sha256:"+"a"*64,
    })
    assert sample["watchdog_active"] is False
    owner.watch()
    assert len(observed) == 1
    assert observed[0][0] == "f"*32
    monkeypatch.setattr(owner, "watch", lambda: observed.append("independent"))
    def halt(seconds):
        assert seconds == independent.INTERVAL_SECONDS
        raise InterruptedError("simulated watchdog service restart")
    monkeypatch.setattr(owner.time, "sleep", halt)
    with pytest.raises(InterruptedError):
        owner.watch_loop()
    assert observed[-1] == "independent"


def test_f5_independent_watchdog_message_is_real_wire_serializable():
    import io
    from dbus_next._private.unmarshaller import Unmarshaller
    from zog.host_deploy.gateway import fresh_watchdog_service as independent
    plan = {
        "schema": sidecar.SCHEMA, "unit": sidecar.UNIT,
        "installed": {"python_executable": "/usr/bin/python3",
                      "host_deploy_python_root": "/opt/zog/accepted/host-deploy/src"},
    }
    message = independent.message(plan)
    message.serial = 1
    decoded = Unmarshaller(io.BytesIO(message._marshall())).unmarshall()
    assert decoded.body[0] == independent.UNIT
    assert decoded.body[1] == "fail"
    props = dict(decoded.body[2])
    assert props["Restart"].value == "always"
    assert props["ExecStart"].value[0][1][-1] == "watch-loop"
    assert props["Slice"].value == "system.slice"
    assert props["NoNewPrivileges"].value is True
    assert props["RestartUSec"].value == 1_000_000
