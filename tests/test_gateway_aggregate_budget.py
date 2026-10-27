"""Source security contract for 6h PID1 timer and 30+2 GiB TOTAL pool."""
from copy import deepcopy
import io

import pytest
from dbus_next._private.unmarshaller import Unmarshaller

from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_budget_guard as budget
from zog.host_deploy.gateway import fresh_deadline_timer as deadline
from zog.host_deploy.gateway import fresh_quota_volume as quota
from zog.host_deploy.gateway import fresh_sidecar_install as sidecar
from zog.host_deploy.gateway import compiler_execution_identity as identity


def external():
    return {
        "schema": aggregate.SCHEMA,
        "mount": aggregate.EXTERNAL_MOUNT,
        "limit_bytes": aggregate.EXTERNAL_BYTES,
        "kernel_enforced": True, "mount_verified": True,
        "allocation_verified": True,
        "class_roots": {
            key: aggregate.EXTERNAL_MOUNT + "/" + key
            for key in aggregate.REQUIRED_CLASSES
        },
        "unaccounted_writable_roots": [],
    }


def work():
    return {"image_bytes": aggregate.BUILD_BYTES,
            "capacity_bytes": aggregate.BUILD_BYTES-8192,
            "kernel_enforced": True, "mount": str(quota.MOUNT)}


def plan():
    return {
        "schema": sidecar.SCHEMA, "unit": sidecar.UNIT,
        "installed": {
            "python_executable": "/usr/bin/python3",
            "host_deploy_python_root": "/opt/zog/accepted/host-deploy/src",
        },
    }


def test_total_disk_source_policy_and_separate_build_quota():
    assert aggregate.BUILD_BYTES == 30*1024**3
    assert aggregate.EXTERNAL_BYTES == 2*1024**3
    assert aggregate.TOTAL_BYTES == budget.ADDITIONAL_DISK_BYTES
    assert aggregate.BUILD_BYTES + aggregate.EXTERNAL_BYTES == aggregate.TOTAL_BYTES
    assert quota.BUILD_BYTES == aggregate.BUILD_BYTES
    result = aggregate.validate(work(), external(), host_owner_verified=True)
    assert result["aggregate_max_bytes"] == aggregate.TOTAL_BYTES
    assert "systemd-journal" in result["bounded_classes"]


@pytest.mark.parametrize("change", [
    "no-native-owner", "no-accounting-quota", "wrong-cap",
    "unaccounted-journal", "outside-host-state", "outside-compiler-logs",
    "wrong-dev", "not-preallocated", "oversized",
])
def test_total_budget_rejects_uncounted_or_unbounded_external_disk(change):
    item = external()
    wk = work()
    trusted = True
    if change == "no-native-owner":
        trusted = False
    elif change == "no-accounting-quota":
        item["kernel_enforced"] = False
    elif change == "wrong-cap":
        wk["image_bytes"] = aggregate.TOTAL_BYTES
    elif change == "unaccounted-journal":
        item["unaccounted_writable_roots"] = ["/var/log/journal"]
    elif change == "outside-host-state":
        item["class_roots"]["owner-state"] = "/var/lib/zog/host-deploy/unbounded"
    elif change == "outside-compiler-logs":
        item["class_roots"]["compiler-logs"] = "/var/log/journal/old"
    elif change == "wrong-dev":
        item["mount_verified"] = False
    elif change == "not-preallocated":
        item["allocation_verified"] = False
    else:
        item["limit_bytes"] += 1
    with pytest.raises((RuntimeError, PermissionError)):
        aggregate.validate(wk, item, host_owner_verified=trusted)


def test_no_unreviewed_pid1_deadline_override():
    message = deadline.message(plan())
    message.serial = 1
    frame = message._marshall()
    read = Unmarshaller(io.BytesIO(frame)).unmarshall()
    assert read.signature == "ssa(sv)a(sa(sv))"
    assert read.body[0:2] == [deadline.UNIT, "fail"]
    props = dict(read.body[2])
    aux = read.body[3]
    assert len(aux) == 1 and aux[0][0] == deadline.STOP_UNIT
    assert props["Unit"].value == deadline.STOP_UNIT
    assert props["OnActiveUSec"].value == (
        budget.DEADLINE_SECONDS - deadline.MARGIN_SECONDS)*1_000_000
    assert props["AccuracyUSec"].value == 1_000_000
    service = dict(aux[0][1])
    assert service["ExecStart"].value[0][1][-1] == "hard-stop"
    assert service["Restart"].value if "Restart" in service else True
    assert service["Slice"].value == "system.slice"
    assert message.member == "StartTransientUnit"
    assert 0 < deadline.TRIGGER_SECONDS < budget.DEADLINE_SECONDS
    assert identity.FRESH_ROOT_CONTROL_REVISION == (
        "c03815b18efc96797ba868f2412f073f758a6cad")


def test_deadline_source_does_not_accept_other_unit_or_untrusted_path():
    bad = plan()
    bad["unit"] = "root-control.service"
    with pytest.raises(ValueError):
        deadline.message(bad)
    bad = deepcopy(plan())
    bad["installed"]["python_executable"] = "/tmp/foreign root.py"
    with pytest.raises(ValueError):
        deadline.message(bad)


def test_external_preparation_does_not_pretend_journal_is_installed(monkeypatch):
    """Initial pool setup and post-reboot image reattach precede bind mounts."""
    calls = []
    monkeypatch.setattr(aggregate, "inspect_external_pool_native",
                        lambda: calls.append("pool") or {"mount": aggregate.EXTERNAL_MOUNT,
                                                          "unaccounted_writable_roots": [
                                                              "worker-mounts-unverified"]})
    from zog.host_deploy.gateway import fresh_journal_backing as journal
    monkeypatch.setattr(journal, "inspect",
                        lambda: (_ for _ in ()).throw(RuntimeError("journal absent")))
    prepared = aggregate.inspect_external_pool_native()
    assert prepared["unaccounted_writable_roots"]
    assert calls == ["pool"]
    with pytest.raises(RuntimeError, match="journal absent"):
        aggregate.inspect_external_native()


def test_external_provision_returns_preparation_not_final_attestation():
    """Source contract: no first-install circular dependency on bind mounts."""
    import inspect
    source = inspect.getsource(aggregate.provision_external)
    recovery = inspect.getsource(aggregate.reattach_external_after_boot)
    assert "return inspect_external_pool_native()" in source
    assert "return inspect_external_pool_native()" in recovery
    assert "return inspect_external_native()" not in source
    assert "return inspect_external_native()" not in recovery


def test_preactivation_allows_only_fixed_unresolved_classes_without_arming():
    external_pool = external()
    expected = [
        "worker-mounts-unverified",
        "root-control-registration-unverified",
        "default-journal-and-pid1-unverified",
    ]
    external_pool["unaccounted_writable_roots"] = expected
    preparation = aggregate.validate_pre_activation(
        work(), external_pool, host_owner_verified=True)
    assert preparation["status"] == "preactivation-only"
    assert preparation["outstanding_classes"] == expected
    assert external_pool["unaccounted_writable_roots"] == expected
    # No caller may use the relaxed preparation result as final admission.
    with pytest.raises(RuntimeError):
        aggregate.validate(work(), external_pool, host_owner_verified=True)
    for bad in ([], expected[:-1], list(reversed(expected)),
                expected + ["new-unaccounted-writer"]):
        changed = deepcopy(external_pool)
        changed["unaccounted_writable_roots"] = bad
        with pytest.raises(RuntimeError):
            aggregate.validate_pre_activation(
                work(), changed, host_owner_verified=True)
    with pytest.raises(PermissionError):
        aggregate.validate_pre_activation(work(), external_pool)
