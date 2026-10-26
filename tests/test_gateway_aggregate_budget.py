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
        "97481da26ae1294c9bf474f93f2ed90b4512b9b1")


def test_deadline_source_does_not_accept_other_unit_or_untrusted_path():
    bad = plan()
    bad["unit"] = "root-control.service"
    with pytest.raises(ValueError):
        deadline.message(bad)
    bad = deepcopy(plan())
    bad["installed"]["python_executable"] = "/tmp/foreign root.py"
    with pytest.raises(ValueError):
        deadline.message(bad)
