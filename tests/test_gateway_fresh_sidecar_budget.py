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
        "host_deploy_python_root": "/opt/zog/accepted/host-deploy/src",
        "host_deploy_tree_sha256": SHA,
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
        "c03815b18efc96797ba868f2412f073f758a6cad")
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
        def prepare_once(self, value):
            assert value["sha256"] == plan["sha256"]
            return {"plan_sha256": value["sha256"],
                    "state": "prepared", "durable": True}
        def mark_start_attempt(self, digest):
            assert digest == plan["sha256"]
            return {"plan_sha256": digest,
                    "state": "attempted", "durable": True}
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
    class MissingAttempt(Trusted):
        actions = []
        def mark_start_attempt(self, digest):
            return {"state": "uncertain", "plan_sha256": digest, "durable": False}
    with pytest.raises(RuntimeError, match="attempted-start marker"):
        sidecar.install(plan, host_owner=MissingAttempt())
    assert MissingAttempt.actions == []
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


def test_stop_intent_is_pure_and_never_mutates_before_journal():
    class Owner:
        def cancel_exact_project(self, *args, **kwargs):
            pytest.fail("cancellation before durable intent is forbidden")
    x = original_budget()
    t = telemetry()
    t["used_bytes"] = 200 + guard.ADDITIONAL_DISK_BYTES
    pending = guard.tick(x, telemetry=t, host_owner=Owner())
    assert pending["status"] == "stop_requested"
    assert pending["stop_reason"] == "aggregate-budget-stop"
    assert pending["stop_receipt"] is None
    assert pending["cancellation_id"] == x["cancellation_id"]
    assert guard.evaluate(pending, **t) == "stop"


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


def test_native_transient_transport_encodes_exact_pid1_properties(monkeypatch):
    from zog.host_deploy.gateway import fresh_sidecar_dbus as native
    p = sidecar.review_plan(fixture_identity(), installed())
    variants = native._checked_properties(
        sidecar.UNIT, "fail", p["properties"])
    properties = {name: (signature, value) for name, signature, value in variants}
    assert properties["ExecStart"] == (
        "a(sasb)", [["/usr/bin/python3",
                    ["/usr/bin/python3", "-B", "-m", "zog.root_control"],
                    False]])
    assert properties["RestartUSec"] == ("t", 0)
    assert properties["Restart"] == ("s", "no")
    assert properties["StartLimitBurst"] == ("u", 1)
    assert properties["StartLimitIntervalUSec"] == ("t", 60_000_000)
    assert properties["Environment"][0] == "as"
    assert properties["NoNewPrivileges"] == ("b", True)
    assert properties["LogNamespace"] == ("s", sidecar.LOG_NAMESPACE)
    assert properties["BindPaths"] == (
        "a(ssbt)", [[sidecar.REGISTRATION_SOURCE,
                     sidecar.REGISTRATION_DEST, False, 0]])
    bad_mount = deepcopy(p["properties"])
    bad_mount["BindPaths"] = [[sidecar.REGISTRATION_SOURCE,
                              "/var/lib/zog/other", False, 0]]
    with pytest.raises(ValueError):
        native._checked_properties(sidecar.UNIT, "fail", bad_mount)
    with pytest.raises(ValueError, match="only one absent"):
        native._checked_properties(
            sidecar.UNIT, "replace", p["properties"])
    with pytest.raises(ValueError):
        native._checked_properties(
            "root-control.service", "fail", p["properties"])
    tampered = deepcopy(p["properties"])
    tampered["Environment"] = [
        item.replace("build-only-project-v1", "unrestricted")
        for item in tampered["Environment"]]
    with pytest.raises(ValueError, match="startup role"):
        native._checked_properties(sidecar.UNIT, "fail", tampered)
    monkeypatch.setattr(native.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="privileged installer"):
        native.start_exact_sidecar(sidecar.UNIT, "fail", p["properties"])


def test_dbus_next_real_wire_serialization_and_roundtrip():
    """Actual dbus-next 0.2.3 signature verification, not mock properties."""
    import io
    from dbus_next._private.unmarshaller import Unmarshaller
    from zog.host_deploy.gateway import fresh_sidecar_dbus as native
    plan = sidecar.review_plan(fixture_identity(), installed())
    typed = native._checked_properties(sidecar.UNIT, "fail", plan["properties"])
    message = native._message(sidecar.UNIT, typed)
    message.serial = 1
    frame = message._marshall()
    assert isinstance(frame, (bytes, bytearray)) and len(frame) > 100
    unpacked = Unmarshaller(io.BytesIO(frame)).unmarshall()
    assert unpacked is not None
    assert unpacked.signature == "ssa(sv)a(sa(sv))"
    assert unpacked.member == "StartTransientUnit"
    assert unpacked.body[0:2] == [sidecar.UNIT, "fail"]
    props = dict(unpacked.body[2])
    assert props["ExecStart"].signature == "a(sasb)"
    assert props["ExecStart"].value == [
        ["/usr/bin/python3",
         ["/usr/bin/python3", "-B", "-m", "zog.root_control"], False]
    ]
    assert props["Environment"].signature == "as"
    assert props["NoNewPrivileges"].value is True
    assert props["LogNamespace"].value == sidecar.LOG_NAMESPACE
    assert props["BindPaths"].signature == "a(ssbt)"
    assert props["BindPaths"].value == [[sidecar.REGISTRATION_SOURCE,
                                         sidecar.REGISTRATION_DEST, False, 0]]

def test_budget_crash_safe_cancel_once_and_read_only_recovery(tmp_path, monkeypatch):
    from pathlib import Path
    import os
    import pytest
    root = tmp_path / "budget"
    root.mkdir()
    root.chmod(0o700)
    # CI exercises real fsync/rename/lock on disposable files, not root NSS.
    monkeypatch.setattr(guard.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guard, "_protected_root", lambda directory: Path(directory))
    real_lstat = Path.lstat
    real_stat = guard.os.fstat
    def fake_lstat(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        # Real protected pathname and modes; CI runner is not root.
        return type("Stat", (), {"st_mode": st.st_mode, "st_uid": 0})()
    def fake_fstat(fd):
        st = real_stat(fd)
        return type("Stat", (), {
            "st_mode": st.st_mode, "st_uid": 0, "st_size": st.st_size,
            "st_nlink": st.st_nlink,
        })()
    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(guard.os, "fstat", fake_fstat)
    guard.write_once(root, original_budget())
    class Owner:
        def __init__(self):
            self.calls = []
            self.replies = []
            self.fail = False
        def is_trusted_native_owner(self):
            return True
        def sample_exact(self, before):
            d = telemetry()
            d["used_bytes"] = before["baseline_disk_used_bytes"] + guard.ADDITIONAL_DISK_BYTES
            return d
        def cancel_exact_project(self, project, request, *, reason, cancellation_id):
            # Read DURABLY written attempted state before the only mutation.
            state = guard.read(root, request)
            assert state["status"] == "stop_attempted"
            assert state["cancellation_id"] == cancellation_id
            self.calls.append((project, request, reason, cancellation_id))
            if self.fail:
                raise ConnectionError("ack lost after kernel cancellation")
            return {"confirmed": True, "cancellation_id": cancellation_id,
                    "request_id": request, "project_root": project}
        def inspect_cancel_exact_project(self, project, request, *, cancellation_id):
            self.replies.append(cancellation_id)
            return {"confirmed": True, "cancellation_id": cancellation_id,
                    "request_id": request, "project_root": project}
    owner = Owner()
    owner.fail = True
    with pytest.raises(ConnectionError):
        guard.watch_once(root, REQ, native_owner=owner)
    assert guard.read(root, REQ)["status"] == "stop_attempted"
    assert len(owner.calls) == 1
    # Restart MUST NOT make another cancellation call, only inspect same ID.
    observed = guard.watch_once(root, REQ, native_owner=owner)
    assert observed["status"] == "stopped"
    assert observed["stop_receipt"]["cancellation_id"] == owner.calls[0][3]
    assert owner.replies == [owner.calls[0][3]]
    assert len(owner.calls) == 1
    # Terminal state is durable and never changes to active or attempts again.
    assert guard.watch_once(root, REQ, native_owner=owner)["status"] == "stopped"
    assert len(owner.calls) == 1


def test_watchdog_unknown_cancel_readback_remains_frozen(tmp_path, monkeypatch):
    from pathlib import Path
    import os
    import stat
    monkeypatch.setattr(guard.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guard, "_protected_root", lambda directory: Path(directory))
    real_lstat = Path.lstat
    real_fstat = os.fstat
    def ownership(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        return type("Stat", (), {"st_mode": st.st_mode, "st_uid": 0})()
    def ownership_fd(fd):
        st = real_fstat(fd)
        return type("Stat", (), {"st_mode": st.st_mode, "st_uid": 0,
                                "st_size": st.st_size, "st_nlink": st.st_nlink})()
    monkeypatch.setattr(Path, "lstat", ownership)
    monkeypatch.setattr(os, "fstat", ownership_fd)
    root = tmp_path / "budget"
    root.mkdir(mode=0o700)
    guard.write_once(root, original_budget())
    class Owner:
        cancels = 0
        reads = 0
        def is_trusted_native_owner(self): return True
        def sample_exact(self, x):
            return dict(telemetry(), used_bytes=guard.ADDITIONAL_DISK_BYTES + 200)
        def cancel_exact_project(self, project, request, *, reason, cancellation_id):
            self.cancels += 1
            return {"confirmed": False}
        def inspect_cancel_exact_project(self, project, request, *, cancellation_id):
            self.reads += 1
            return None
    owner = Owner()
    assert guard.watch_once(root, REQ, native_owner=owner)["status"] == "stop_attempted"
    assert guard.watch_once(root, REQ, native_owner=owner)["status"] == "stop_attempted"
    assert owner.cancels == 1
    assert owner.reads == 1


def test_watchdog_telemetry_failure_is_durable_uncertain_stop(tmp_path, monkeypatch):
    from pathlib import Path
    import os
    root = tmp_path / "budget"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(guard.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guard, "_protected_root", lambda directory: Path(directory))
    real_fstat = os.fstat
    def fake_fstat(fd):
        st = real_fstat(fd)
        return type("Stat", (), {"st_mode": st.st_mode, "st_uid": 0,
                                 "st_size": st.st_size, "st_nlink": st.st_nlink})()
    monkeypatch.setattr(os, "fstat", fake_fstat)
    guard.write_once(root, original_budget())
    class Owner:
        cancels = 0
        def is_trusted_native_owner(self): return True
        def sample_exact(self, before):
            raise OSError("quota evidence unavailable")
        def cancel_exact_project(self, project, request, *, reason, cancellation_id):
            state = guard.read(root, request)
            assert state["status"] == "stop_attempted"
            assert state["stop_reason"] == "aggregate-budget-uncertain"
            self.cancels += 1
            return {"confirmed": False}
        def inspect_cancel_exact_project(self, project, request, *, cancellation_id):
            return None
    owner = Owner()
    assert guard.watch_once(root, REQ, native_owner=owner)["status"] == "stop_attempted"
    assert guard.read(root, REQ)["stop_reason"] == "aggregate-budget-uncertain"
    assert guard.watch_once(root, REQ, native_owner=owner)["status"] == "stop_attempted"
    assert owner.cancels == 1
