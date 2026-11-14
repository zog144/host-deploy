"""Real disposable Project: verified init -> recovered layout -> stage -> activation.

Uses the selected host-install module from ONE checkout and the three actual
immutable source Git checkouts in the existing cross-owner CI. Simulated Host
command execution translates only the filesystem root, Python and Unix socket
into the disposable test namespace; the host-deploy runtime generates and
executes its actual controller inspection/installation Python bytes. No AWS,
SSM, systemd or compiler is contacted.
"""
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys

import pytest

from zog.host_deploy import fonts_lane_migration as migration
from zog.host_deploy import image_build_lanes as lanes
from test_fonts_lane_profile import workspace
from zog.host_install import fonts_project_initialization as initializer
from zog.host_install import fonts_project_migration as storage


def _checkouts():
    base = Path.cwd()
    inputs = {
        "source": base / "companions/image-build-inherited",
        "companions/box-control": base / "companions/box-control-inherited",
        "companions/build-record": base / "companions/build-record",
    }
    if any(not path.joinpath(".git").is_dir() for path in inputs.values()):
        pytest.skip("integration requires three exact source checkouts from cross-owner CI")
    return inputs


def test_committed_original_initializer_recovers_to_real_activation(
        tmp_path, monkeypatch):
    sources = _checkouts()
    disk = tmp_path / "compiler-root"
    (disk / "var/lib").mkdir(parents=True)
    initializer.operation("stage", root=disk, source_checkouts=sources)
    initial = initializer.operation("commit", root=disk)
    assert initial["layout_complete"] is True

    physical = storage._map(disk, storage.NEW)
    manifest = physical / initializer.MANIFEST
    manifest_bytes = manifest.read_bytes()
    # The real first native initializer omitted exactly these three entries.
    for directory in initializer.LAYOUT_DIRECTORIES:
        (physical / directory).rmdir()
    partial = initializer.operation("verify", root=disk)
    assert partial["layout_complete"] is False
    assert partial["missing_layout_directories"] == [
        "package", "application", "catalogue"]
    assert partial["manifest_sha256"] == initial["manifest_sha256"]

    root, workspace_id, configuration, lane_path, old, original_digest = workspace(
        tmp_path, monkeypatch)
    original_bytes = lane_path.read_bytes()
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    digest = lanes.specification_sha256(corrected)
    sock_path = tmp_path / "controller.sock"

    class FilesystemHost:
        def __init__(self, _):
            self.commands = []

        def command(self, command):
            self.commands.append(command)
            if command == "host-install-fonts-project-init --verify":
                return json.dumps(initializer.operation("verify", root=disk))
            if command == "host-install-fonts-project-migrate --verify":
                raise AssertionError("never copy a non-existent historical Project")
            if "disk_free_bytes" in command:
                return json.dumps({"disk_free_bytes": 2**44})
            argv = shlex.split(command)
            assert argv[:2] == ["python3", "-c"], command[:180]
            code = argv[2]
            code = code.replace(
                "root=Path(spec['project_root'])",
                "root=Path(" + repr(str(physical)) + ")")
            code = code.replace(
                "python=Path(spec['python_executable'])",
                "python=Path(" + repr(os.path.realpath(sys.executable)) + ")")
            code = code.replace(
                "socket=Path(spec['controller']['socket_path'])",
                "socket=Path(" + repr(str(sock_path)) + ")")
            code = code.replace("observed=spec['observed_state_dir']",
                                "observed=None")
            run = subprocess.run(
                [sys.executable, "-c", code], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=25, check=False)
            if run.returncode:
                raise RuntimeError("real controller runtime failed: " + run.stderr)
            return run.stdout

    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(sock_path))
        os.chmod(sock_path, 0o600)
        # Before recovery, the report MUST NOT be accepted as activation
        # stage evidence and real controller inspection is partial.
        with pytest.raises(RuntimeError, match="initialization is not verified"):
            migration.stage(
                root, expected_original_specification_sha256=original_digest,
                expected_corrected_specification_sha256=digest,
                prepared_initialize=True, host_factory=FilesystemHost)
        assert not (root / migration.INTENT).exists()
        before = migration.runtime.inspect(FilesystemHost(configuration), corrected)
        assert before["status"] == "partial"
        assert before["effective_user_id"] == os.geteuid()

        recovered = initializer.operation("complete-layout", root=disk)
        assert recovered["layout_complete"] is True
        assert recovered["manifest_sha256"] == initial["manifest_sha256"]
        assert manifest.read_bytes() == manifest_bytes
        assert initializer.operation("complete-layout", root=disk) == recovered

        intent = migration.stage(
            root, expected_original_specification_sha256=original_digest,
            expected_corrected_specification_sha256=digest,
            prepared_initialize=True, host_factory=FilesystemHost)
        assert intent["source_method"] == "prepared-first-initialization"
        assert intent["initialization_manifest_sha256"] == initial["manifest_sha256"]
        assert lane_path.read_bytes() == original_bytes
        # Preserve the existing source/pin selector's separate authorization
        # boundary: only the controller filesystem lifecycle is tested here.
        monkeypatch.setattr(migration, "_source_selection",
                            lambda _host, _spec: {"filesystem_test": True})
        ready = migration.runtime.inspect(FilesystemHost(configuration), corrected)
        assert ready["status"] == "prepared"
        record = migration.activate(
            root, expected_corrected_specification_sha256=digest,
            host_factory=FilesystemHost)
        assert record["state"] == "active"
        assert record["fonts_migration"]["source_method"] == "prepared-first-initialization"
        assert (physical / "controller-inherited-v1.json").is_file()
        assert migration.runtime.inspect(
            FilesystemHost(configuration), corrected)["status"] == "complete"
        assert (Path(record["fonts_migration"]["historical_record_path"]).
                read_bytes()) == original_bytes
        assert manifest.read_bytes() == manifest_bytes
        assert not storage._map(disk, storage.OLD).exists()
        assert migration.activate(
            root, expected_corrected_specification_sha256=digest,
            host_factory=FilesystemHost) == record
