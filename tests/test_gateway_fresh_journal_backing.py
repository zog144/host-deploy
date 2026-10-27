"""Source-only negative tests of exact worker log namespace mounts and hard-stop."""
from copy import deepcopy
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import fresh_budget_guard as budget
from zog.host_deploy.gateway import fresh_journal_backing as journal
from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_sidecar_install as sidecar
from zog.host_deploy.gateway import fresh_sidecar_dbus as sidecar_wire
from zog.host_deploy.gateway import fresh_deadline_timer as timer
from zog.host_deploy.gateway import fresh_watchdog_service as watchdog


def test_persistent_and_volatile_namespace_are_fixed():
    assert sidecar.LOG_NAMESPACE == "zogfreshcrossbootstrapoct25"
    assert journal.JOURNAL_SERVICE == "systemd-journald@zogfreshcrossbootstrapoct25.service"
    assert len(journal.JOURNAL_SOCKETS) == 2
    assert journal.JOURNAL_SOURCE != journal.VOLATILE_SOURCE
    assert "/systemd-journal" in str(journal.VOLATILE_SOURCE)
    assert timer.message({
        "schema": sidecar.SCHEMA, "unit": sidecar.UNIT,
        "installed": {"python_executable": "/usr/bin/python3",
                      "host_deploy_python_root": "/opt/readonly/zog"},
    }).body[3][0][1][-1][1].value == sidecar.LOG_NAMESPACE
    assert watchdog.message({
        "schema": sidecar.SCHEMA, "unit": sidecar.UNIT,
        "installed": {"python_executable": "/usr/bin/python3",
                      "host_deploy_python_root": "/opt/readonly/zog"},
    }).body[2][-1][1].value == sidecar.LOG_NAMESPACE


def test_namespace_inspector_refuses_same_device_without_bind(tmp_path, monkeypatch):
    pool = tmp_path / "pool"
    store = pool / "systemd-journal"
    volatile = store / "volatile"
    persistent_dest = tmp_path / "var-journal"
    volatile_dest = tmp_path / "run-journal"
    volatile.mkdir(parents=True)
    persistent_dest.mkdir()
    volatile_dest.mkdir()
    monkeypatch.setattr(journal, "EXTERNAL_MOUNT", str(pool))
    monkeypatch.setattr(journal, "JOURNAL_SOURCE", store)
    monkeypatch.setattr(journal, "VOLATILE_SOURCE", volatile)
    monkeypatch.setattr(journal, "targets", lambda: (persistent_dest, volatile_dest))
    monkeypatch.setattr(journal, "_mount_points", lambda: {
        str(pool): ["/dev/loop99", "ext4", "7:99"],
        str(persistent_dest): ["/dev/loop99[/systemd-journal]", "ext4", "7:99"],
        str(volatile_dest): ["/dev/loop99[/systemd-journal/volatile]", "ext4", "7:99"],
    })
    # All four directories share st_dev on this CI filesystem, but without
    # an actual bind st_ino differs. This MUST fail (directory-name check).
    with pytest.raises(RuntimeError, match="unbounded fallback"):
        journal.inspect()


def test_journal_mount_setup_refuses_live_namespace_unit(tmp_path, monkeypatch):
    monkeypatch.setattr(journal.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "_show", lambda unit: {
        "ActiveState": "active" if unit == journal.JOURNAL_SERVICE else "inactive"
    })
    with pytest.raises(RuntimeError, match="already active"):
        journal.install_binds_before_activation()


def test_hard_deadline_enospc_uses_exact_kernel_parent_without_replay(tmp_path, monkeypatch):
    marker = tmp_path / "deadline.json"
    cg = tmp_path / sidecar.SLICE_UNIT
    cg.mkdir()
    (cg / "cgroup.kill").write_text("")
    monkeypatch.setattr(owner, "CGROUP", cg)
    monkeypatch.setattr(owner, "_root", lambda: None)
    monkeypatch.setattr(owner, "_boot", lambda: "boot-fixed")
    monkeypatch.setattr(owner, "DEADLINE_ATTEMPT", marker)
    plan = {"sha256": "sha256:" + "a"*64, "project_root": "/fresh/new"}
    admitted = {"request_id": "f"*32, "host_id": "new-host"}
    cancellation = budget._digest({
        "schema": budget.SCHEMA, "request_id": admitted["request_id"],
        "host_id": admitted["host_id"], "project_root": plan["project_root"],
    })
    auth = {
        "schema": "host-deploy-fresh-hard-deadline-attempt-v1",
        "plan_sha256": plan["sha256"], "request_id": admitted["request_id"],
        "host_id": admitted["host_id"], "project_root": plan["project_root"],
        "cancellation_id": cancellation, "boot_id": "boot-fixed",
        "state": "attempted",
    }
    monkeypatch.setattr(owner, "_admission", lambda _: admitted)
    monkeypatch.setattr(owner, "_read_json", lambda path: auth if path == marker else plan)
    monkeypatch.setattr(owner.budget, "read", lambda path, request: {
        "request_id": admitted["request_id"], "cancellation_id": cancellation,
        "boot_id": "boot-fixed",
    })
    monkeypatch.setattr(owner.budget, "watch_once", lambda *a, **k:
                        (_ for _ in ()).throw(OSError(28, "ENOSPC")))
    monkeypatch.setattr(owner, "_events", lambda: {"populated": "1"})
    with pytest.raises(RuntimeError, match="ledger requires native reconciliation"):
        owner.hard_stop()
    assert (cg / "cgroup.kill").read_text() == "1\n"
    (cg / "cgroup.kill").write_text("")
    auth["cancellation_id"] = "1"*64
    with pytest.raises(RuntimeError, match="authority changed"):
        owner.hard_stop()
    assert (cg / "cgroup.kill").read_text() == ""


def test_fixed_registrations_are_not_proven_by_log_namespace():
    # Backend source currently chooses /var/lib/zog/build-resources by default.
    # Changing a worker's LogNamespace cannot transparently relocate its
    # root-owned registration records, nor can a shared bind overlay be used.
    assert "root-control-registration-unverified" in (
        "worker-mounts-unverified",
        "root-control-registration-unverified",
        "default-journal-and-pid1-unverified",
    )
