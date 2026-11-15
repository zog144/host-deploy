"""Existing Projects are selected, verified, and used without re-creation."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import existing_project_runtime as runtime
from zog.host_deploy.workspace import initialize


def git(path, *args):
    result = subprocess.run(["git", "-C", str(path), *args],
                            capture_output=True, text=True, check=True)
    return result.stdout.strip()


class NativeHost:
    def __init__(self):
        self.commands = []
        self.writes = 0
        self.lose_next_ack = False

    def command(self, command, **kwargs):
        self.commands.append(command)
        if "INSTALL=True" in command:
            self.writes += 1
        process = subprocess.run(command, shell=True, text=True,
                                 capture_output=True, check=False)
        if process.returncode:
            raise RuntimeError("Host command failed: " + process.stderr[-1200:])
        if "INSTALL=True" in command and self.lose_next_ack:
            self.lose_next_ack = False
            raise RuntimeError("lost remote SSM acknowledgement")
        return process.stdout

    def upload(self, *_):
        raise AssertionError("existing Project activation cannot upload files")


@pytest.fixture
def existing(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    initialize(workspace, "host", "profile", "us-east-1")
    project = tmp_path / "existing-seed"
    for name in ("package", "application", "catalogue", "state", "source"):
        (project / name).mkdir(parents=True)
    (project / "controller.json").write_bytes(b"historical-controller-unaltered")
    (project / "state" / "existing-output").write_bytes(b"retained-generation-data")
    (project / "source" / "tracked.py").write_text("print('reviewed')\n")
    git(project / "source", "init", "-q")
    git(project / "source", "config", "user.email", "zog@example.invalid")
    git(project / "source", "config", "user.name", "Source Check")
    git(project / "source", "add", "tracked.py")
    git(project / "source", "commit", "-qm", "reviewed source")
    revision = git(project / "source", "rev-parse", "HEAD")
    sock = socket.socket(socket.AF_UNIX)
    sock_path = tmp_path / "s"
    sock.bind(str(sock_path))
    sock.listen(1)
    native = NativeHost()
    monkeypatch.setattr(lanes, "Host", lambda config: native)
    monkeypatch.setattr(lanes, "configuration",
                        lambda root: ({"workspace_id": "verified"}, {"instance_id": "i-test"}))
    specification = lanes.specification(
        "fonts-selected", mode="managed", existing_project=True,
        source_repository="zog144/image-build", source_revision=revision,
        monthly_pin_repository_path="project/pins/2026-10-01/commit-pin.py",
        monthly_pin_identity="sha256:" + "b" * 64,
        provenance_host_id="host-fixture",
        provenance_project_id="retained-project-identity",
        project_root=str(project),
        memory_maximum_bytes=1024**3, thread_count_maximum=4,
        cpu_weight=100, disk_reservation_bytes=1,
        python_executable=str(Path(sys.executable).resolve()),
        socket_path=str(sock_path),
    )
    try:
        yield workspace, project, specification, native
    finally:
        sock.close()


def test_prepare_existing_project_then_activate_without_recreating_it(existing):
    workspace, project, selected, native = existing
    initial = {(project / name).stat().st_ino
               for name in ("package", "application", "catalogue", "state", "source")}
    original = (project / "controller.json").read_bytes()
    record = lanes.prepare(workspace, selected)
    assert record["state"] == "prepared"
    assert record["project_inspection"]["status"] == "prepared"
    assert record["project_inspection"]["project_identity"] == project.name
    assert record["project_inspection"]["source_revision"] == selected["source_revision"]
    assert lanes.prepare(workspace, selected) == record
    digest = lanes.specification_sha256(selected)
    active = lanes.activate(workspace, selected["lane"],
                            expected_specification_sha256=digest)
    assert active["state"] == "active"
    config = project / runtime.controller_file(selected)
    assert config.is_file()
    assert active["controller_config"] == str(config)
    assert json.loads(config.read_text()) == lanes._controller(selected)
    assert (project / "controller.json").read_bytes() == original
    assert (project / "state" / "existing-output").read_bytes() == b"retained-generation-data"
    assert initial == {(project / name).stat().st_ino
                       for name in ("package", "application", "catalogue", "state", "source")}
    saved_ino = config.stat().st_ino
    again = lanes.activate(workspace, selected["lane"],
                           expected_specification_sha256=digest)
    assert again == active
    assert config.stat().st_ino == saved_ino
    assert native.writes == 1


def test_selected_existing_project_must_be_explicitly_verified(existing):
    workspace, project, spec, native = existing
    ordinary = copy.deepcopy(spec)
    ordinary.pop("project_selection")
    with pytest.raises(ValueError, match="end with"):
        lanes.validate(ordinary)
    bad = copy.deepcopy(spec)
    bad["project_selection"] = "unchecked"
    with pytest.raises(ValueError, match="unsupported"):
        lanes.validate(bad)
    bad = copy.deepcopy(spec)
    bad["controller"]["execution_user_id"] = 1001
    with pytest.raises(ValueError, match="controller policy"):
        lanes.validate(bad)
    bad = copy.deepcopy(spec)
    bad["project_root"] += "/../redirect"
    with pytest.raises(ValueError, match="normalized"):
        lanes.validate(bad)
    assert not list((workspace / "image-build-lanes").glob("*.json"))


def test_preparation_does_not_create_missing_or_inaccessible_project(existing):
    workspace, project, spec, native = existing
    (project / "application").rmdir()
    with pytest.raises(RuntimeError, match="existing Project"):
        lanes.prepare(workspace, spec)
    assert not (project / "application").exists()
    assert not (workspace / "image-build-lanes" / "fonts-selected.json").exists()


def test_preparation_rejects_unreviewed_source(existing):
    workspace, project, spec, native = existing
    (project / "source" / "tracked.py").write_text("changed source\n")
    with pytest.raises(RuntimeError, match="clean reviewed checkout"):
        lanes.prepare(workspace, spec)
    assert not (workspace / "image-build-lanes" / "fonts-selected.json").exists()


def test_project_remains_owned_by_one_active_lane(existing):
    workspace, project, spec, native = existing
    lanes.prepare(workspace, spec)
    conflicting = copy.deepcopy(spec)
    conflicting["lane"] = "second-lane"
    with pytest.raises(ValueError, match="already owned"):
        lanes.prepare(workspace, conflicting)
    assert not (workspace / "image-build-lanes" / "second-lane.json").exists()


def test_existing_controller_conflict_is_never_overwritten(existing):
    workspace, project, spec, native = existing
    lanes.prepare(workspace, spec)
    controller = project / runtime.controller_file(spec)
    controller.write_text('{"foreign":true}')
    with pytest.raises(RuntimeError, match="controller differs"):
        lanes.activate(workspace, spec["lane"])
    assert controller.read_text() == '{"foreign":true}'
    assert lanes.inspect(workspace, spec["lane"])["state"] == "prepared"
    assert native.writes == 0


def test_lost_remote_ack_recovers_only_by_readback(existing):
    workspace, project, spec, native = existing
    lanes.prepare(workspace, spec)
    native.lose_next_ack = True
    with pytest.raises(RuntimeError, match="lost remote"):
        lanes.activate(workspace, spec["lane"])
    assert lanes.inspect(workspace, spec["lane"])["state"] == "prepared"
    assert (project / runtime.controller_file(spec)).exists()
    assert native.writes == 1
    active = lanes.activate(workspace, spec["lane"])
    assert active["state"] == "active"
    assert native.writes == 1


def test_unresolved_controller_intent_never_resubmits_write(existing):
    workspace, project, spec, native = existing
    lanes.prepare(workspace, spec)
    original = native.command
    def interrupted(command, **kw):
        if "INSTALL=True" in command:
            raise RuntimeError("failed before controller write")
        return original(command, **kw)
    native.command = interrupted
    with pytest.raises(RuntimeError, match="failed before"):
        lanes.activate(workspace, spec["lane"])
    native.command = original
    with pytest.raises(RuntimeError, match="unresolved"):
        lanes.activate(workspace, spec["lane"])
    assert not (project / runtime.controller_file(spec)).exists()


def test_activated_existing_project_rejects_changed_source(existing):
    workspace, project, spec, native = existing
    lanes.prepare(workspace, spec)
    lanes.activate(workspace, spec["lane"])
    (project / "source" / "tracked.py").write_text("changed\n")
    with pytest.raises(RuntimeError, match="clean reviewed checkout"):
        lanes.activate(workspace, spec["lane"])
