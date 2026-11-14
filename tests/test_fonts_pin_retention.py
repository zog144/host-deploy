"""Source-only original October pin retention; no Host or compilation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import fonts_pin_retention as retention
from zog.host_deploy.gateway.image_build_execution import _WRAPPER


def _git(source, *args):
    return subprocess.run(["git", "-C", str(source), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def copied_project(tmp_path, monkeypatch):
    project = tmp_path / retention.PROJECT.lstrip("/")
    source = project / "source"
    pin = source / retention.RELATIVE_PIN
    pin.parent.mkdir(parents=True)
    raw = repr({"schema": 1, "date": "2026-10-01", "packages": {}}).encode()
    pin.write_bytes(raw)
    (project / "state").mkdir()
    monkeypatch.setattr(retention, "PIN_SHA256", hashlib.sha256(raw).hexdigest())
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "fixture original pinned source")
    return tmp_path, project, source, pin, raw, _git(source, "rev-parse", "HEAD")


def test_retained_original_pin_captured_in_application_state_without_copying_source(copied_project):
    root, project, source, pin, raw, commit = copied_project
    before = pin.read_bytes()
    inspection = retention.operation("inspect", filesystem_root=root, source_revision=commit)
    assert inspection["artifact_present"] is False
    assert inspection["compilation_authorized"] is False
    first = retention.operation("retain", filesystem_root=root, source_revision=commit)
    dest = project / "state/image-build/build-record/artifacts" / hashlib.sha256(raw).hexdigest()
    assert first["artifact_path"] == str(dest)
    assert dest.read_bytes() == raw
    assert dest.stat().st_mode & 0o777 == 0o600
    assert first["already_present"] is False
    assert pin.read_bytes() == before
    assert _git(source, "status", "--porcelain=v1", "--untracked-files=all") == ""
    second = retention.operation("retain", filesystem_root=root, source_revision=commit)
    assert second["already_present"] is True
    dest.write_bytes(raw + b"tampered")
    with pytest.raises(RuntimeError, match="digest mismatch"):
        retention.operation("retain", filesystem_root=root, source_revision=commit)


def test_pin_retention_rejects_original_source_changes_and_symlinks(copied_project):
    root, project, source, pin, raw, commit = copied_project
    with pytest.raises(RuntimeError, match="revision differs"):
        retention.operation("retain", filesystem_root=root, source_revision="f"*40)
    pin.write_bytes(raw + b"bad")
    with pytest.raises(RuntimeError, match="uncommitted changes"):
        retention.operation("retain", filesystem_root=root, source_revision=commit)
    pin.write_bytes(raw)
    pin.unlink()
    outside = root / "elsewhere"
    outside.write_bytes(raw)
    pin.symlink_to(outside)
    with pytest.raises(RuntimeError, match="symlink"):
        retention.operation("retain", filesystem_root=root, source_revision=commit)


def test_inherited_fonts_argv_uses_only_existing_retained_state_artifact():
    from zog.host_deploy import image_build_lanes as lanes
    historical = dict(
        schema=4, lane="gateway-first-fonts-runtime", mode="managed",
        source_repository="zog144/image-build",
        source_revision=lanes.FIRST_FONTS_PRODUCER_REVISION,
        monthly_pin_repository_path=lanes.FIRST_FONTS_ORIGINAL_PIN_PATH,
        monthly_pin_identity=lanes.FIRST_FONTS_ORIGINAL_PIN_IDENTITY,
        observed_state_dir=None, python_executable="/usr/bin/python3",
        provenance_host_id="host", provenance_project_id="project",
        project_root="/home/certbot-build-owner/gateway-first-fonts-runtime",
        resource_policy={"memory_maximum_bytes":2**30,"thread_count_maximum":64,
                         "cpu_weight":100,"disk_reservation_bytes":2**30},
        controller=dict(socket_path="/run/zog/root-control.sock",
                        execution_user_id=24202,execution_group_id=24202,
                        startup_timeout_seconds=30,execution_timeout_seconds=3600,
                        termination_grace_seconds=10,wait_timeout_seconds=0,
                        transport_timeout_seconds=45),
    )
    candidate = lanes.corrected_first_fonts_specification(historical)
    root = Path(candidate["project_root"])
    record = dict(specification=candidate, state="active",
                  source_root=str(root/"source"),
                  state_dir=str(root/"state"), package_dir=str(root/"source/project/package"),
                  controller_config=str(root/"controller.json"))
    argv = lanes.remote_operation_argv(record, str(root/"gateway-requests/job/request.json"))
    artifact = root/"state/image-build/build-record/artifacts"/lanes.FIRST_FONTS_ORIGINAL_PIN_IDENTITY[7:]
    assert argv[argv.index("--provenance-pin")+1] == str(artifact)
    assert argv[argv.index("--retained-pin-source-revision")+1] == lanes.FIRST_FONTS_PRODUCER_REVISION
    assert argv[argv.index("--retained-pin-repository-path")+1] == lanes.FIRST_FONTS_ORIGINAL_PIN_PATH
    assert argv[argv.index("--repository-root")+1] == str(root/"source")
    assert argv[argv.index("--source-revision")+1] == lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION
    assert "certbot-build-worker" not in repr(argv)
    incorrect = json.loads(json.dumps(record))
    incorrect["specification"]["monthly_pin_identity"] = "sha256:"+"b"*64
    with pytest.raises(RuntimeError, match="approved source binding"):
        lanes.remote_operation_argv(incorrect, str(root/"gateway-requests/job/request.json"))


def test_remote_wrapper_checks_retained_artifact_before_running_child(copied_project):
    root, project, source, pin, raw, commit = copied_project
    # The real production CLI remains pinned to original 1f07...; this
    # disposable fixture tests wrapper I/O with a clean source checkout.
    digest = hashlib.sha256(raw).hexdigest()
    artifact = project/"state/image-build/build-record/artifacts"/digest
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(raw)
    artifact.chmod(0o600)
    payload=b"{}"
    command=[sys.executable,"-c",_WRAPPER,
             str(project/"gateway-requests/job/request.json"),
             str(project/"gateway-requests/job/result.json"),str(source),commit,
             retention.RELATIVE_PIN, "sha256:"+digest,hashlib.sha256(payload).hexdigest(),
             base64.b64encode(payload).decode(),
             sys.executable,"-c","raise SystemExit(71)",
             "--retained-pin-source-revision",retention.ORIGINAL_SOURCE,
             "--retained-pin-repository-path",retention.RELATIVE_PIN,
             "--provenance-pin",str(artifact)]
    completed=subprocess.run(command, text=True, capture_output=True, timeout=30)
    assert completed.returncode != 0
    assert "image-build remote operation command failed" in completed.stderr
    artifact.write_bytes(raw+b"altered")
    denied=subprocess.run(command, text=True, capture_output=True, timeout=30)
    assert denied.returncode != 0
    assert "monthly pin digest differs" in denied.stderr
