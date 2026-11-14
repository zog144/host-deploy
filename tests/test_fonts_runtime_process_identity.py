"""Run the schema-5 controller probe as the *current* effective principal.

Only synthetic filesystem/socket fixtures are created. No real Host, SSM,
controller service or account change is needed. This test also runs as UID 0
when the disposable test process already has UID 0.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from zog.host_deploy import fonts_lane_runtime as runtime
from zog.host_deploy import image_build_lanes as lanes


def _spec(tmp_path):
    return lanes.specification(
        "local-fixture", source_repository="zog144/image-build",
        source_revision="a" * 40,
        monthly_pin_repository_path="project/pins/2026-10-01/commit-pin.py",
        monthly_pin_identity="sha256:" + "b" * 64,
        provenance_host_id="fixture-host", provenance_project_id="fixture-project",
        memory_maximum_bytes=1024, thread_count_maximum=1, cpu_weight=100,
        disk_reservation_bytes=1024,
        project_root=str(tmp_path / "local-fixture"),
        python_executable=str(Path(sys.executable).resolve()),
        socket_path=str(tmp_path / "root-control.sock"),
    )


class _ExecutingHost:
    """Run generated command without User/Group overrides or impersonation."""
    def command(self, command):
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout


def test_local_probe_and_install_keep_existing_effective_credentials(tmp_path):
    spec = _spec(tmp_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
        endpoint.bind(spec["controller"]["socket_path"])
        before = runtime.inspect(_ExecutingHost(), spec)
        assert before["status"] == "absent"
        assert (before["effective_user_id"], before["effective_group_id"]) == (os.geteuid(), os.getegid())
        assert "getpwuid" not in runtime.script(spec)
        assert "uid==0 or gid==0" not in runtime.script(spec)
        assert "os.chown" not in runtime.script(spec)
        installed = runtime.install(_ExecutingHost(), spec)
        assert installed["status"] == "complete"
        assert (installed["effective_user_id"], installed["effective_group_id"]) == (os.geteuid(), os.getegid())
        assert json.loads((tmp_path / "local-fixture/controller.json").read_text()) == lanes._controller(spec)
        assert runtime.install(_ExecutingHost(), spec) == installed


def test_existing_archival_controller_file_is_not_replaced(tmp_path):
    spec = _spec(tmp_path)
    root = tmp_path / "local-fixture"
    root.mkdir()
    archival = b'{"historical":"controller, not yet rebound"}\n'
    (root / "controller.json").write_bytes(archival)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
        endpoint.bind(spec["controller"]["socket_path"])
        with pytest.raises(RuntimeError, match="differs from corrected specification"):
            runtime.install(_ExecutingHost(), spec)
    assert (root / "controller.json").read_bytes() == archival


def test_missing_parent_reports_access_failure_without_switching_identities(tmp_path):
    spec = _spec(tmp_path)
    spec["project_root"] = str(tmp_path / "nonexistent" / "local-fixture")
    lanes.validate(spec)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
        endpoint.bind(spec["controller"]["socket_path"])
        with pytest.raises(RuntimeError, match="application data parent is missing"):
            runtime.inspect(_ExecutingHost(), spec)
