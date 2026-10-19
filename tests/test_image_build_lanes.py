import json
from pathlib import Path

import pytest

from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy.workspace import initialize


def spec(name="rebuild-oct1", root=None, memory=2_000_000_000, disk=10_000_000_000, observed=None):
    return lanes.specification(
        name,
        source_repository="zog144/image-build",
        source_revision="a" * 40,
        monthly_pin_repository_path="project/pins/2026-10-01/commit-pin.py",
        monthly_pin_identity="sha256:" + "b" * 64,
        provenance_host_id="host-fixture",
        provenance_project_id="zog-compiler-view",
        memory_maximum_bytes=memory,
        thread_count_maximum=64,
        cpu_weight=50,
        disk_reservation_bytes=disk,
        execution_user_id=1001,
        execution_group_id=1001,
        project_root=root,
        observed_state_dir=observed,
    )


def workspace(tmp_path):
    root = tmp_path / "workspace"
    initialize(root, "image-build-host", "zog-development", "us-east-1")
    return root


def test_prepare_is_idempotent_and_binds_exact_source(tmp_path):
    root = workspace(tmp_path)
    first = lanes.prepare(root, spec())
    second = lanes.prepare(root, spec())
    assert first == second
    assert first["specification"]["source_revision"] == "a" * 40
    changed = spec()
    changed["source_revision"] = "c" * 40
    with pytest.raises(ValueError, match="different inputs"):
        lanes.prepare(root, changed)


def test_project_basename_is_lane_identity(tmp_path):
    root = workspace(tmp_path)
    record = lanes.prepare(root, spec("first", "/var/lib/zog/lanes/first"))
    assert Path(record["specification"]["project_root"]).name == "first"


def test_lane_root_must_end_in_lane_name():
    with pytest.raises(ValueError, match="end with"):
        spec("rebuild-oct1", "/var/lib/zog/wrong-name")


def test_resource_policy_and_cpu_weight_are_bounded():
    with pytest.raises(ValueError, match="cpu_weight"):
        lanes.specification(
            "bad",
            source_repository="zog144/image-build",
            source_revision="a" * 40,
            monthly_pin_repository_path="project/pins/2026-10-01/commit-pin.py",
        monthly_pin_identity="sha256:" + "b" * 64,
            provenance_host_id="host",
            provenance_project_id="project",
            memory_maximum_bytes=1,
            thread_count_maximum=1,
            cpu_weight=10001,
            disk_reservation_bytes=1,
            execution_user_id=1001,
            execution_group_id=1001,
        )


def test_remote_operation_argv_is_lane_bound(tmp_path):
    root = workspace(tmp_path)
    record = lanes.prepare(root, spec())
    record.update(
        state="active",
        source_root="/var/lib/zog/image-build-lanes/rebuild-oct1/source",
        package_dir="/var/lib/zog/image-build-lanes/rebuild-oct1/source/project/package",
        state_dir="/var/lib/zog/image-build-lanes/rebuild-oct1/state",
        controller_config="/var/lib/zog/image-build-lanes/rebuild-oct1/controller.json",
    )
    argv = lanes.remote_operation_argv(record, "/run/zog/request.json")
    assert argv[:4] == ["env", "PYTHONPATH=/var/lib/zog/image-build-lanes/rebuild-oct1/source/src", "python3", "-m"]
    assert argv[4] == "zog.image_build.remote_operations"
    assert "a" * 40 in argv
    assert "--provenance-host-id" in argv and "host-fixture" in argv
    assert "--provenance-project-id" in argv and "zog-compiler-view" in argv
    assert "--provenance-pin" in argv
    provenance_pin = argv[argv.index("--provenance-pin") + 1]
    assert provenance_pin == (
        "/var/lib/zog/image-build-lanes/rebuild-oct1/source/"
        "project/pins/2026-10-01/commit-pin.py"
    )
    assert "--expected-pin-digest" in argv and "sha256:" + "b" * 64 in argv
    assert argv[-1] == "/run/zog/request.json"


def test_retire_keeps_record_and_disables_remote_commands(tmp_path):
    root = workspace(tmp_path)
    lanes.prepare(root, spec())
    retired = lanes.retire(root, "rebuild-oct1")
    assert retired["state"] == "retired"
    with pytest.raises(RuntimeError, match="not active"):
        lanes.remote_operation_argv(retired, "/run/request.json")


def test_validate_rejects_mutable_or_malformed_revision():
    value = spec()
    value["source_revision"] = "unstable"
    with pytest.raises(ValueError, match="immutable commit"):
        lanes.validate(value)


def test_activate_admission_and_controller_policy_without_aws(tmp_path, monkeypatch):
    root = workspace(tmp_path)
    prepared = lanes.prepare(
        root,
        spec(
            "rebuild-oct1",
            "/var/lib/zog/image-build-lanes/rebuild-oct1",
            memory=2_000_000_000,
            disk=10_000_000_000,
        ),
    )
    host_config = {"instance_id": "i-test"}
    monkeypatch.setattr(lanes, "configuration", lambda directory: ({}, host_config))
    monkeypatch.setattr(
        lanes,
        "_capacity",
        lambda host, project_root: {
            "memory_bytes": 8_000_000_000,
            "disk_free_bytes": 100_000_000_000,
        },
    )

    uploads = {}
    commands = []
    class FakeHost:
        def __init__(self, config):
            assert config == host_config
        def command(self, command, **kwargs):
            commands.append(command)
            return ""
        def upload(self, data, path):
            uploads[path] = data

    monkeypatch.setattr(lanes, "Host", FakeHost)
    active = lanes.activate(root, "rebuild-oct1")
    assert active["state"] == "active"
    controller = json.loads(uploads[active["controller_config"]])
    assert controller["project_root"].endswith("/rebuild-oct1")
    assert controller["resource_limits"]["cpu-weight"] == 50
    assert controller["resource_limits"]["memory-maximum-bytes"] == 2_000_000_000
    assert controller["resource_limits"]["thread-count-maximum"] == 64
    assert any("install -d" in command for command in commands)


def test_activate_rejects_overcommitted_memory(tmp_path, monkeypatch):
    root = workspace(tmp_path)
    lanes.prepare(root, spec(memory=7_000_000_000))
    monkeypatch.setattr(lanes, "configuration", lambda directory: ({}, {"instance_id": "i-test"}))
    monkeypatch.setattr(
        lanes,
        "_capacity",
        lambda host, project_root: {
            "memory_bytes": 4_000_000_000,
            "disk_free_bytes": 100_000_000_000,
        },
    )
    monkeypatch.setattr(lanes, "Host", lambda config: object())
    with pytest.raises(RuntimeError, match="memory reservations"):
        lanes.activate(root, "rebuild-oct1")


def test_reservation_lane_accounts_for_existing_work_without_remote_mutation(tmp_path, monkeypatch):
    root = workspace(tmp_path)
    work = lanes.specification(
        "work-leading",
        mode="reservation",
        source_repository="zog144/image-build",
        source_revision="c" * 40,
        monthly_pin_repository_path="project/pins/2026-10-01/commit-pin.py",
        monthly_pin_identity="sha256:" + "d" * 64,
        provenance_host_id="host-fixture",
        provenance_project_id="zog-compiler-view",
        memory_maximum_bytes=3_000_000_000,
        thread_count_maximum=128,
        cpu_weight=200,
        disk_reservation_bytes=20_000_000_000,
        execution_user_id=1001,
        execution_group_id=1001,
        project_root="/var/lib/station-access/zog-compiler-view",
    )
    lanes.prepare(root, work)
    monkeypatch.setattr(lanes, "configuration", lambda directory: ({}, {"instance_id": "i-test"}))
    monkeypatch.setattr(
        lanes,
        "_capacity",
        lambda host, project_root: {
            "memory_bytes": 16_000_000_000,
            "disk_free_bytes": 200_000_000_000,
        },
    )
    class NoMutationHost:
        def __init__(self, config): pass
        def command(self, command, **kwargs):
            raise AssertionError("reservation activation must not mutate the existing project")
        def upload(self, data, path):
            raise AssertionError("reservation activation must not upload into the existing project")
    monkeypatch.setattr(lanes, "Host", NoMutationHost)
    active = lanes.activate(root, "work-leading")
    assert active["state"] == "active"
    assert "controller_config" not in active
    with pytest.raises(RuntimeError, match="reservation-only"):
        lanes.remote_operation_argv(active, "/run/request.json")


def test_new_lane_schema_binds_explicit_monthly_pin_descriptor():
    value = spec()
    assert value["schema"] == 3
    assert value["monthly_pin_repository_path"] == "project/pins/2026-10-01/commit-pin.py"
    assert value["monthly_pin_identity"] == "sha256:" + "b" * 64
    assert "pin_identity" not in value


@pytest.mark.parametrize(
    "path",
    [
        "/absolute/commit-pin.py",
        "../pins/commit-pin.py",
        "project/../pins/commit-pin.py",
        ".git/commit-pin.py",
        "",
    ],
)
def test_monthly_pin_path_must_be_safe_repository_relative(path):
    with pytest.raises(ValueError, match="monthly"):
        lanes.specification(
            "bad-pin",
            source_repository="zog144/image-build",
            source_revision="a" * 40,
            monthly_pin_repository_path=path,
            monthly_pin_identity="sha256:" + "b" * 64,
            provenance_host_id="host",
            provenance_project_id="project",
            memory_maximum_bytes=1,
            thread_count_maximum=1,
            cpu_weight=100,
            disk_reservation_bytes=1,
            execution_user_id=1001,
            execution_group_id=1001,
        )


def test_legacy_lane_can_be_inspected_but_not_remote_executed():
    value = spec()
    legacy = dict(value)
    legacy["schema"] = 1
    legacy["pin_identity"] = legacy.pop("monthly_pin_identity")
    legacy.pop("monthly_pin_repository_path")
    legacy.pop("observed_state_dir")
    assert lanes.validate(legacy) == legacy
    record = {
        "schema": 1,
        "lane": legacy["lane"],
        "specification": legacy,
        "state": "active",
        "source_root": "/var/lib/zog/image-build-lanes/rebuild-oct1/source",
        "package_dir": "/var/lib/zog/image-build-lanes/rebuild-oct1/source/project/package",
        "state_dir": "/var/lib/zog/image-build-lanes/rebuild-oct1/state",
        "controller_config": "/var/lib/zog/image-build-lanes/rebuild-oct1/controller.json",
    }
    with pytest.raises(RuntimeError, match="legacy image-build lane"):
        lanes.remote_operation_argv(record, "/run/request.json")


def test_observation_lane_argv_binds_external_state_and_omits_controller():
    record = {
        "schema": 3,
        "lane": "gateway-pass4-readonly",
        "specification": spec(
            "gateway-pass4-readonly",
            observed="/var/lib/station-access/zog-compiler-view/state",
        ),
        "state": "active",
        "source_root": "/var/lib/zog/image-build-lanes/gateway-pass4-readonly/source",
        "package_dir": "/var/lib/zog/image-build-lanes/gateway-pass4-readonly/source/project/package",
        "state_dir": "/var/lib/zog/image-build-lanes/gateway-pass4-readonly/state",
        "controller_config": "/var/lib/zog/image-build-lanes/gateway-pass4-readonly/controller.json",
    }
    argv = lanes.remote_operation_argv(record, "/run/request.json")
    assert "--observed-state-dir" in argv
    assert argv[argv.index("--observed-state-dir") + 1] == "/var/lib/station-access/zog-compiler-view/state"
    assert "--controller-config" not in argv


def test_observed_state_must_be_absolute_and_distinct_from_control_state():
    with pytest.raises(ValueError, match="absolute"):
        spec(observed="relative/state")
    with pytest.raises(ValueError, match="differ from control state"):
        spec(
            "same-state",
            root="/var/lib/zog/image-build-lanes/same-state",
            observed="/var/lib/zog/image-build-lanes/same-state/state",
        )


def test_schema2_lane_remains_remote_executable_without_observed_state():
    value = spec()
    value["schema"] = 2
    value.pop("observed_state_dir")
    assert lanes.validate(value) == value
    record = {
        "schema": 2,
        "lane": value["lane"],
        "specification": value,
        "state": "active",
        "source_root": "/var/lib/zog/image-build-lanes/rebuild-oct1/source",
        "package_dir": "/var/lib/zog/image-build-lanes/rebuild-oct1/source/project/package",
        "state_dir": "/var/lib/zog/image-build-lanes/rebuild-oct1/state",
        "controller_config": "/var/lib/zog/image-build-lanes/rebuild-oct1/controller.json",
    }
    argv = lanes.remote_operation_argv(record, "/run/request.json")
    assert "--observed-state-dir" not in argv
    assert "--controller-config" in argv

def test_python_interpreter_path_validation():
    for value in ("python3", "/usr/bin/../bin/python3.12", "/usr/bin/python 3",
                  "/usr/bin//python3.12", "/usr/bin/python3.12\n", "", None):
        with pytest.raises(ValueError, match="python_executable"):
            lanes.validate_python_executable(value)
    assert lanes.validate_python_executable("/usr/bin/python3.12") == "/usr/bin/python3.12"


def test_schema_four_requires_explicit_runtime_and_preserves_schema_three():
    old = spec()
    assert old["schema"] == 3
    assert lanes.validate(old) == old
    versioned = json.loads(json.dumps(old))
    versioned["schema"] = 4
    with pytest.raises(ValueError, match="unsupported image-build lane"):
        lanes.validate(versioned)
    versioned["python_executable"] = "/usr/bin/python3.12"
    assert lanes.validate(versioned) == versioned


def test_bind_python_runtime_upgrades_prepared_lane_once_with_audit(tmp_path):
    root = workspace(tmp_path)
    before = lanes.prepare(root, spec(observed="/var/lib/existing/state"))
    digest = lanes.specification_sha256(before["specification"])
    original = json.loads(json.dumps(before))
    upgraded = lanes.bind_python_runtime(
        root, "rebuild-oct1", "/usr/bin/python3.12",
        expected_specification_sha256=digest,
    )
    assert upgraded["schema"] == 4
    assert upgraded["state"] == "prepared"
    assert upgraded["specification"] == {
        **original["specification"],
        "schema": 4,
        "python_executable": "/usr/bin/python3.12",
    }
    assert upgraded["runtime_binding_upgrade"] == {
        "schema": 1,
        "previous_schema": 3,
        "previous_specification_sha256": digest,
        "python_executable": "/usr/bin/python3.12",
    }
    assert lanes.inspect(root, "rebuild-oct1") == upgraded
    assert lanes.bind_python_runtime(
        root, "rebuild-oct1", "/usr/bin/python3.12",
        expected_specification_sha256=digest,
    ) == upgraded


def test_bind_python_runtime_refuses_stale_specification_and_conflicting_retry(tmp_path):
    root = workspace(tmp_path)
    before = lanes.prepare(root, spec())
    digest = lanes.specification_sha256(before["specification"])
    with pytest.raises(ValueError, match="digest differs"):
        lanes.bind_python_runtime(
            root, "rebuild-oct1", "/usr/bin/python3.12",
            expected_specification_sha256="sha256:" + "f" * 64,
        )
    assert lanes.inspect(root, "rebuild-oct1") == before
    lanes.bind_python_runtime(
        root, "rebuild-oct1", "/usr/bin/python3.12",
        expected_specification_sha256=digest,
    )
    upgraded = lanes.inspect(root, "rebuild-oct1")
    with pytest.raises(ValueError, match="already bound differently"):
        lanes.bind_python_runtime(
            root, "rebuild-oct1", "/usr/bin/python3.11",
            expected_specification_sha256=digest,
        )
    with pytest.raises(ValueError, match="already bound differently"):
        lanes.bind_python_runtime(
            root, "rebuild-oct1", "/usr/bin/python3.12",
            expected_specification_sha256="sha256:" + "f" * 64,
        )
    assert lanes.inspect(root, "rebuild-oct1") == upgraded


@pytest.mark.parametrize("state", ["active", "retired"])
def test_bind_python_runtime_refuses_nonprepared_lane(tmp_path, state):
    root = workspace(tmp_path)
    prepared = lanes.prepare(root, spec())
    digest = lanes.specification_sha256(prepared["specification"])
    path = root / "image-build-lanes" / "rebuild-oct1.json"
    changed = {**prepared, "state": state}
    path.write_text(json.dumps(changed))
    with pytest.raises(RuntimeError, match="unactivated prepared"):
        lanes.bind_python_runtime(
            root, "rebuild-oct1", "/usr/bin/python3.12",
            expected_specification_sha256=digest,
        )
    assert json.loads(path.read_text()) == changed


def test_bind_python_runtime_refuses_nonmanaged_and_partial_records(tmp_path):
    root = workspace(tmp_path)
    reservation = lanes.specification(
        "reserved", mode="reservation",
        source_repository="zog144/image-build", source_revision="a"*40,
        monthly_pin_repository_path="project/pins/commit-pin.py",
        monthly_pin_identity="sha256:"+"b"*64,
        provenance_host_id="host", provenance_project_id="project",
        memory_maximum_bytes=100, thread_count_maximum=1,
        cpu_weight=100, disk_reservation_bytes=100,
        execution_user_id=1000, execution_group_id=1000,
    )
    lane = lanes.prepare(root, reservation)
    digest = lanes.specification_sha256(lane["specification"])
    with pytest.raises(RuntimeError, match="managed lane"):
        lanes.bind_python_runtime(
            root, "reserved", "/usr/bin/python3.12",
            expected_specification_sha256=digest,
        )
    ordinary = lanes.prepare(root, spec())
    ordinary_digest = lanes.specification_sha256(ordinary["specification"])
    path = root / "image-build-lanes" / "rebuild-oct1.json"
    ordinary["source_root"] = "/var/lib/example"
    path.write_text(json.dumps(ordinary))
    with pytest.raises(RuntimeError, match="unactivated prepared"):
        lanes.bind_python_runtime(
            root, "rebuild-oct1", "/usr/bin/python3.12",
            expected_specification_sha256=ordinary_digest,
        )
    assert json.loads(path.read_text()) == ordinary


def test_bind_python_runtime_rejects_symlinked_lane_record(tmp_path):
    root = workspace(tmp_path)
    before = lanes.prepare(root, spec())
    digest = lanes.specification_sha256(before["specification"])
    path = root / "image-build-lanes" / "rebuild-oct1.json"
    destination = tmp_path / "external-lane.json"
    destination.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(destination)
    with pytest.raises(RuntimeError, match="regular file"):
        lanes.bind_python_runtime(
            root, "rebuild-oct1", "/usr/bin/python3.12",
            expected_specification_sha256=digest,
        )
    assert json.loads(destination.read_text()) == before


def test_bind_python_runtime_cli_command_requires_explicit_contract(tmp_path, monkeypatch, capsys):
    import sys
    from zog.host_deploy.cli import main

    root = workspace(tmp_path)
    before = lanes.prepare(root, spec())
    digest = lanes.specification_sha256(before["specification"])
    monkeypatch.setattr(sys, "argv", [
        "host-deploy", "lane-bind-python",
        "--workspace", str(root), "--lane", "rebuild-oct1",
        "--python-executable", "/usr/bin/python3.12",
        "--expected-specification-sha256", digest,
    ])
    main()
    result = json.loads(capsys.readouterr().out)
    assert result["specification"]["python_executable"] == "/usr/bin/python3.12"
    assert result["runtime_binding_upgrade"]["previous_specification_sha256"] == digest



def test_real_runtime_preflight_requires_provenance_dependency_before_cli_execution(tmp_path):
    """A real interpreter must discover build-record, without invoking the CLI."""
    import os
    import subprocess
    import sys

    source = tmp_path / "source"
    pkg = source / "src" / "zog"
    (pkg / "image_build").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "image_build" / "__init__.py").write_text("")
    (pkg / "image_build" / "remote_operations.py").write_text("READY = True\n")
    python_executable = os.path.realpath(sys.executable)

    class LocalHost:
        def command(self, script, seconds):
            result = subprocess.run(
                script, shell=True, capture_output=True, text=True,
                timeout=seconds,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())
            return result.stdout

    host = LocalHost()
    with pytest.raises(RuntimeError, match="zog.build_record"):
        lanes.runtime_preflight(
            host, python_executable, source,
            required_capabilities=("provenance",),
        )
    assert not list(source.rglob("__pycache__"))

    record = pkg / "build_record"
    record.mkdir()
    (record / "__init__.py").write_text(
        "def make_record(*args, **kwargs): return {}\n"
        "class Store: pass\n"
    )
    (record / "model.py").write_text("def digest(value): return value\n")
    evidence = lanes.runtime_preflight(
        host, python_executable, source,
        required_capabilities=("provenance",),
    )
    assert evidence["source_module"] == str(
        pkg / "image_build" / "remote_operations.py"
    )
    assert evidence["capabilities"]["provenance"]["module"] == "zog.build_record"
    assert evidence["python_executable"] == python_executable
    assert evidence["python_version"][:2] >= [3, 11]
    assert not list(source.rglob("__pycache__"))


def test_preflight_refuses_request_controlled_capability_names():
    with pytest.raises(ValueError, match="unsupported"):
        lanes.runtime_preflight(
            object(), "/usr/bin/python3.12", "/some/source",
            required_capabilities=("arbitrary.module",),
        )


def test_active_schema_four_lane_binds_reviewed_companion_once(tmp_path):
    root = workspace(tmp_path)
    original = spec()
    original["schema"] = 4
    original["python_executable"] = "/usr/bin/python3.12"
    prepared = lanes.prepare(root, original)
    path = root / "image-build-lanes" / "rebuild-oct1.json"
    prepared["state"] = "active"
    path.write_text(json.dumps(prepared))
    digest = lanes.specification_sha256(original)
    kw = {
        "producer_revision": original["source_revision"],
        "repository": "zog144/build-record",
        "revision": lanes.BUILD_RECORD_COMPATIBILITY,
        "source_root": original["project_root"] + "/companions/build-record",
        "expected_specification_sha256": digest,
    }
    first = lanes.bind_runtime_companion(root, "rebuild-oct1", **kw)
    assert first["runtime_companion"]["revision"] == lanes.BUILD_RECORD_COMPATIBILITY
    assert first["specification"] == original
    assert lanes.bind_runtime_companion(root, "rebuild-oct1", **kw) == first
    with pytest.raises(ValueError, match="already bound differently"):
        lanes.bind_runtime_companion(
            root, "rebuild-oct1", **{**kw, "revision": "f"*40},
        )
    with pytest.raises(ValueError, match="exact lane source specification"):
        lanes.bind_runtime_companion(
            root, "rebuild-oct1",
            **{**kw, "expected_specification_sha256": "sha256:"+"f"*64},
        )
    assert lanes.inspect(root, "rebuild-oct1") == first


def test_companion_binding_requires_active_managed_immutable_source(tmp_path):
    root = workspace(tmp_path)
    before = lanes.prepare(root, spec())
    kw = {
        "producer_revision": before["specification"]["source_revision"],
        "repository": "zog144/build-record",
        "revision": lanes.BUILD_RECORD_COMPATIBILITY,
        "source_root": before["specification"]["project_root"]
            + "/companions/build-record",
        "expected_specification_sha256": lanes.specification_sha256(
            before["specification"]
        ),
    }
    with pytest.raises(RuntimeError, match="active managed schema-4"):
        lanes.bind_runtime_companion(root, before["lane"], **kw)
    with pytest.raises(ValueError, match="owned lane companions"):
        lanes.validate_runtime_companion(
            {
                "schema": 1,
                "repository": "zog144/build-record",
                "revision": lanes.BUILD_RECORD_COMPATIBILITY,
                "source_root": "/tmp/arbitrary",
                "producer_revision": "a"*40,
            }, project_root="/var/lib/zog/image-build-lanes/rebuild-oct1"
        )
