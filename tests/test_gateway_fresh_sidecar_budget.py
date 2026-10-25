"""Source-only protected no-reload sidecar and durable overall watchdog gates."""
from copy import deepcopy

import pytest

from zog.host_deploy.gateway import fresh_sidecar_install as sidecar
from zog.host_deploy.gateway import fresh_budget_guard as guard
from zog.host_deploy.gateway import compiler_execution_identity as identity
from zog.host_deploy.gateway import toolchain_supervisor as supervisor

REQ = "f" * 32
SHA = "sha256:" + "a" * 64


def fixture_identity():
    return {
        "schema": identity.FRESH_SCHEMA,
        "controller_uid": 24301, "controller_gid": 24301,
        "controller_home": "/home/zog-cross-owner",
        "project_root": "/home/zog-cross-owner/fresh-cross-bootstrap-oct25",
        "build_uid": 24302, "build_gid": 24302,
        "socket_path": sidecar.SOCKET,
        "source_revision": identity.FRESH_PRODUCER_REVISION,
        "box_control_revision": identity.FRESH_BOX_CONTROL_REVISION,
        "root_control_revision": identity.FRESH_ROOT_CONTROL_REVISION,
        "build_record_revision": identity.FRESH_BUILD_RECORD_REVISION,
        "python_executable": "/usr/bin/python3",
        "task_catalogue_identity": SHA,
        "fresh_scope": {
            "schema": identity.FRESH_SCOPE, "phase": "cross-bootstrap",
            "execution_limit_seconds": 21600,
            "additional_disk_bytes": 34359738368,
            "existing_host_only": True, "automatic_later_phases": False,
        },
    }


def installed():
    return {
        "root_control_revision": identity.FRESH_ROOT_CONTROL_REVISION,
        "root_control_tree_sha256": SHA,
        "root_control_python_root": "/opt/zog/accepted/root-control/src",
        "python_executable": "/usr/bin/python3",
        "installer_receipt_sha256": SHA,
        "host_id": "i-0123456789abcdef0",
        "boot_id": "test-fresh-boot",
        "legacy_baseline_sha256": SHA,
        "reactivation_receipt_sha256": SHA,
        "watchdog_receipt_sha256": SHA,
    }


def test_exact_build_only_sidecar_start_transient_specification():
    plan = sidecar.review_plan(fixture_identity(), installed())
    assert plan["root_control_revision"] == (
        "19d423cdf16531474de5680117867e12b5bb0620")
    assert plan["unit"] == sidecar.UNIT
    assert plan["mode"] == "replace-irrelevant-only-if-absent"
    assert plan["properties"]["Type"] == "exec"
    assert plan["properties"]["ExecStart"] == [
        "/usr/bin/python3", "-B", "-m", "zog.root_control"]
    env = dict(item.split("=", 1) for item in plan["properties"]["Environment"])
    assert env["ROOT_CONTROL_ROLE"] == "build-only-project-v1"
    assert env["ROOT_CONTROL_AUTHORIZED_PROJECT"] == fixture_identity()["project_root"]
    assert env["ROOT_CONTROL_SOCKET"] == sidecar.SOCKET
    assert env["ROOT_CONTROL_CONTROLLER_UID"] == "24301"
    assert env["ROOT_CONTROL_SOCKET_GID"] == "24301"
    assert all("ExecStartEx" not in k and "daemon-reload" not in str(v)
               for k, v in plan["properties"].items())
    assert "root-control.sock" not in env["ROOT_CONTROL_SOCKET"]


@pytest.mark.parametrize("mutate", [
    lambda x: x.update(root_control_revision="bc52f2e9e8696acaef15db09e50bec21b084248a"),
    lambda x: x.update(socket_path="/run/zog/root-control.sock"),
    lambda x: x.update(project_root="/home/zog-cross-owner/foreign-project"),
    lambda x: x.update(build_uid=24301),
    lambda x: x.update(controller_gid=24302),
])
def test_sidecar_rejects_old_revision_and_wrong_project_or_grant(mutate):
    x = fixture_identity()
    mutate(x)
    with pytest.raises(ValueError):
        sidecar.review_plan(x, installed())


def test_trusted_sidecar_backend_is_single_shot_and_never_reloads(monkeypatch):
    plan = sidecar.review_plan(fixture_identity(), installed())
    monkeypatch.setattr(sidecar.os, "geteuid", lambda: 0)

    class Trusted:
        exists = False
        actions = []
        def validate_old_baseline(self, sha):
            assert sha == SHA
        def verify_source_and_nss(self, value):
            assert value["properties"]["Type"] == "exec"
        def read_unit(self, unit):
            assert unit == sidecar.UNIT
            return {} if self.exists else None
        def socket_exists(self, socket):
            assert socket == sidecar.SOCKET
            return False
        def start_transient(self, unit, mode, properties):
            self.actions.append((unit, mode, properties))
            return {"job": "new-only-job"}
        def observe_unit(self, unit):
            return {
                "active": True, "invocation_id": "new-invocation",
                "unit": sidecar.UNIT, "socket": sidecar.SOCKET,
                "role": sidecar.ROLE,
                "project_root": fixture_identity()["project_root"],
            }
    back = Trusted()
    receipt = sidecar.install(plan, host_owner=back)
    assert receipt["invocation_id"] == "new-invocation"
    assert len(back.actions) == 1
    assert back.actions[0][:2] == (sidecar.UNIT, "fail")
    back.exists = True
    with pytest.raises(RuntimeError, match="already exists"):
        sidecar.install(plan, host_owner=back)
    assert len(back.actions) == 1
    altered = deepcopy(plan)
    altered["properties"]["ExecStart"].append("--arbitrary")
    with pytest.raises(ValueError, match="digest"):
        sidecar.install(altered, host_owner=back)
    assert len(back.actions) == 1


def original_budget():
    return guard.begin(
        request_id=REQ, host_id="i-0123456789abcdef0",
        project_root=fixture_identity()["project_root"],
        boot_id="test-fresh-boot", now_seconds=1_000_000,
        monotonic_seconds=100, used_bytes=200,
        sidecar_plan_sha256=SHA, monitor_receipt_sha256=SHA,
    )


def telemetry():
    return {
        "host_id": "i-0123456789abcdef0",
        "project_root": fixture_identity()["project_root"],
        "boot_id": "test-fresh-boot",
        "now_seconds": 1_000_015,
        "monotonic_seconds": 115, "used_bytes": 250,
        "monitor_receipt_sha256": SHA,
        "watchdog_active": True, "sidecar_active": True,
    }


def test_aggregate_guard_counts_elapsed_and_bytes_across_repeated_jobs():
    x = original_budget()
    t = telemetry()
    assert guard.evaluate(x, **t) == "active"
    x = guard.tick(x, telemetry=t, host_owner=None)
    assert x["last_tick_seconds"] == 1_000_015
    t["now_seconds"] = 1_000_030
    t["monotonic_seconds"] = 130
    t["used_bytes"] = x["baseline_disk_used_bytes"] + guard.ADDITIONAL_DISK_BYTES - 1
    assert guard.evaluate(x, **t) == "active"
    t["used_bytes"] += 1
    assert guard.evaluate(x, **t) == "stop"


@pytest.mark.parametrize("field,bad", [
    ("boot_id", "new-boot"),
    ("now_seconds", 999999),
    ("monotonic_seconds", 99),
    ("watchdog_active", False),
    ("sidecar_active", False),
    ("monitor_receipt_sha256", "sha256:" + "f"*64),
])
def test_budget_fails_closed_on_reboot_regression_or_unattested_guard(field,bad):
    t = telemetry()
    t[field] = bad
    assert guard.evaluate(original_budget(), **t) == "uncertain"


def test_total_deadline_and_watchdog_interruption_block():
    x = original_budget()
    t = telemetry()
    t["now_seconds"] = x["deadline_seconds"]
    t["monotonic_seconds"] = x["started_monotonic_seconds"] + guard.DEADLINE_SECONDS
    assert guard.evaluate(x, **t) == "uncertain"  # missing intermediate ticks
    x["last_tick_seconds"] = t["now_seconds"] - 20
    x["last_monotonic_seconds"] = t["monotonic_seconds"] - 20
    assert guard.evaluate(x, **t) == "stop"


def test_scope_cancel_only_exact_new_project_and_blocks_uncertain_stop():
    class Owner:
        def __init__(self, confirmed):
            self.confirmed = confirmed
            self.calls = []
        def cancel_exact_project(self, project, request, *, reason):
            self.calls.append((project, request, reason))
            return {"confirmed": self.confirmed, "job_id": "new-job"}
    x = original_budget()
    t = telemetry()
    t["used_bytes"] = 200 + guard.ADDITIONAL_DISK_BYTES
    owner = Owner(True)
    stopped = guard.tick(x, telemetry=t, host_owner=owner)
    assert stopped["status"] == "stopped"
    assert owner.calls == [(fixture_identity()["project_root"], REQ,
                            "aggregate-budget-stop")]
    owner = Owner(False)
    uncertain = guard.tick(x, telemetry=t, host_owner=owner)
    assert uncertain["status"] == "uncertain"
    assert uncertain["stop_receipt"] is None
    assert guard.evaluate(uncertain, **t) == "stop"


def test_supervisor_refuses_v3_without_native_owner(monkeypatch):
    bound = {
        "compiler_execution_identity": fixture_identity(),
        "request_id": REQ,
        "project_root": fixture_identity()["project_root"],
        "target": {"instance_id": "i-0123456789abcdef0"},
    }
    monkeypatch.setattr(supervisor, "binding", lambda *_: bound)
    with pytest.raises(RuntimeError, match="native host-owned aggregate watchdog"):
        supervisor.advance("unused", REQ)


def test_live_attestation_checks_request_plan_and_heartbeat():
    bound = {
        "compiler_execution_identity": fixture_identity(),
        "request_id": REQ,
        "project_root": fixture_identity()["project_root"],
        "target": {"instance_id": "i-0123456789abcdef0"},
    }
    state = original_budget()
    sample = telemetry()
    sample["sidecar_plan_sha256"] = SHA
    assert guard.attest_live(bound, state, sample, root_owner_verified=True)
    with pytest.raises(PermissionError):
        guard.attest_live(bound, state, sample, root_owner_verified=False)
    sample["project_root"] = "/home/foreign"
    with pytest.raises(RuntimeError):
        guard.attest_live(bound, state, sample, root_owner_verified=True)
