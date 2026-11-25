"""The supersession audit is strictly local and can never authorize work."""
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from test_fonts_lane_mixed_recovery import fixture as _mixed_state_fixture
from zog.host_deploy import (
    fonts_lane_supersession_audit as audit,
    fonts_lane_recovery as recovery,
    fonts_lane_migration as migration,
    image_build_lanes as lanes,
)
from zog.host_deploy.workspace import save


def fixture(tmp_path):
    root, workspace, host, record, spec, approvals = _mixed_state_fixture(tmp_path)
    path = root / migration.INTENT
    intent = json.loads(path.read_text())
    intent["initialization_manifest_sha256"] = audit.EXPECTED_INITIALIZATION_MANIFEST
    save(path, intent)
    return root, workspace, host, record, spec, approvals


def _expect(root, approvals):
    return audit.inspect(root, **approvals)


def _snapshot(root):
    values = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            values[relative] = ("symlink", os.readlink(path))
        elif path.is_file():
            values[relative] = ("file", path.read_bytes(), path.stat().st_ino)
        else:
            values[relative] = ("dir", path.stat().st_ino)
    return values


def test_supersession_audit_preserves_certbot_seed_and_unresolved_history(tmp_path, monkeypatch):
    root, workspace, host, record, spec, approvals = fixture(tmp_path)
    before = _snapshot(root)
    def forbidden(*_args, **_kwargs):
        pytest.fail("supersession audit contacted a Host or wrote evidence")
    from zog.host_deploy import runner, fonts_lane_recovery
    monkeypatch.setattr(runner, "Host", forbidden)
    monkeypatch.setattr(fonts_lane_recovery, "inspect", forbidden)
    monkeypatch.setattr(fonts_lane_recovery, "publish", forbidden)
    result = _expect(root, approvals)
    assert result == _expect(root, approvals)
    assert _snapshot(root) == before
    assert result["schema"] == audit.SCHEMA
    assert result["status"] == "supersession-unproven"
    assert result["selected_project_root"] == recovery.EXISTING_EXECUTION_PROJECT
    assert result["prior_initialization_project_root"] == str(lanes.FIRST_FONTS_MIGRATED_ROOT)
    assert result["selected_project_root"] != result["prior_initialization_project_root"]
    assert result["selected_controller_path"] == record["controller_config"]
    assert result["selected_specification_sha256"] == approvals[
        "expected_selected_specification_sha256"]
    assert result["selected_lane_record_sha256"] == "sha256:" + hashlib.sha256(
        (root / "image-build-lanes" / (recovery.LANE + ".json")).read_bytes()).hexdigest()
    assert result["compiler_target"]["instance_id"] == recovery.COMPILER_INSTANCE
    assert result["original_archive_status"] == "missing"
    assert result["original_archive_raw_sha256"] is None
    assert result["pending_intent_phase"] == "installing"
    assert result["historical_ssm_result_status"] == "not-authenticated"
    assert result["selected_controller_observation"] == "not-authenticated"
    assert result["initialized_destination_controller_observation"] == "not-authenticated"
    assert result["superseding_writer"] is None
    assert result["evidence_transition_verified"] is False
    for field in ("mutation", "ssm_send_authorized", "execution_authorized",
                  "compilation_authorized"):
        assert result[field] is False


def test_untrusted_successful_migration_output_never_proves_supersession(tmp_path):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    # An externally provided text result is not authenticated SSM/record
    # history and never grants a replacement writer or replay permission.
    (root / "old-migration-command-output.json").write_text(json.dumps({
        "Status": "Success", "fonts_migration": {"original_record_sha256": "f"*64},
        "project_root": str(lanes.FIRST_FONTS_MIGRATED_ROOT),
        "superseded_by": recovery.EXISTING_EXECUTION_PROJECT,
    }))
    before = _snapshot(root)
    result = _expect(root, approvals)
    assert result["status"] == "supersession-unproven"
    assert result["historical_ssm_result_status"] == "not-authenticated"
    assert _snapshot(root) == before


@pytest.mark.parametrize("field,value", [
    ("project_root", "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"),
    ("project_selection", "new"),
    ("lane", "another-lane"),
])
def test_altered_active_selection_cannot_be_read_as_certbot_seed(tmp_path, field, value):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    path = root / "image-build-lanes" / (recovery.LANE + ".json")
    record["specification"][field] = value
    save(path, record)
    before = _snapshot(root)
    with pytest.raises(audit.AuditHold):
        _expect(root, approvals)
    assert _snapshot(root) == before


@pytest.mark.parametrize("field,value", [
    ("phase", "staged"),
    ("compiler_authorized", True),
    ("project_root", "/home/certbot-build-owner/certbot-seed"),
    ("initialization_manifest_sha256", "0"*64),
    ("new_specification_sha256", "sha256:" + "0"*64),
    ("source_revision", "0"*40),
])
def test_prior_initialization_conflict_is_held_without_writes(tmp_path, field, value):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    path = root / migration.INTENT
    intent = json.loads(path.read_text())
    intent[field] = value
    save(path, intent)
    before = _snapshot(root)
    with pytest.raises(audit.AuditHold, match="initializer intent"):
        _expect(root, approvals)
    assert _snapshot(root) == before


def test_missing_schema4_archive_does_not_invent_one(tmp_path):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    assert not (root / recovery.ARCHIVE).exists()
    result = _expect(root, approvals)
    assert result["original_archive_status"] == "missing"
    assert not (root / recovery.ARCHIVE).exists()
    (root / recovery.ARCHIVE).mkdir()
    result = _expect(root, approvals)
    assert result["original_archive_status"] == "missing"
    assert list((root / recovery.ARCHIVE).iterdir()) == []
    (root / recovery.ARCHIVE / "foreign.json").write_text("{}")
    with pytest.raises(audit.AuditHold, match="archive"):
        _expect(root, approvals)


@pytest.mark.parametrize("damage", ["symlink-file", "linked-file", "writable-file",
                                    "linked-archive", "symlink-ancestor",
                                    "missing-lock"])
def test_custody_fails_closed_and_never_repairs(tmp_path, damage):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    lane = root / "image-build-lanes" / (recovery.LANE + ".json")
    if damage == "symlink-file":
        saved = lane.with_suffix(".original")
        lane.rename(saved)
        lane.symlink_to(saved)
    elif damage == "linked-file":
        os.link(lane, lane.with_suffix(".linked"))
    elif damage == "writable-file":
        lane.chmod(0o666)
    elif damage == "linked-archive":
        (root / recovery.ARCHIVE).symlink_to(tmp_path, target_is_directory=True)
    elif damage == "symlink-ancestor":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    else:
        (root / "workspace.lock").unlink()
    before = _snapshot(root)
    with pytest.raises((audit.AuditHold, OSError)):
        _expect(root, approvals)
    assert _snapshot(root) == before


@pytest.mark.parametrize("name", [
    "expected_original_specification_sha256",
    "expected_corrected_specification_sha256",
    "expected_selected_specification_sha256",
])
def test_wrong_digest_does_not_inspect_or_mutate(tmp_path, name):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    approvals[name] = "sha256:" + "f"*64
    before = _snapshot(root)
    with pytest.raises(audit.AuditHold):
        _expect(root, approvals)
    assert _snapshot(root) == before


def test_compiler_host_or_workspace_identity_conflict(tmp_path):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    host["instance_id"] = "i-aaaaaaaaaaaaaaaaa"
    save(root / "host.json", host)
    with pytest.raises(audit.AuditHold, match="compiler target"):
        _expect(root, approvals)


def test_cli_supersession_inspect_is_nonauthorizing(tmp_path, monkeypatch, capsys):
    from zog.host_deploy import cli
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    before = _snapshot(root)
    monkeypatch.setattr(sys, "argv", [
        "host-deploy", "fonts-lane-supersession-inspect",
        "--workspace", str(root),
        "--expected-original-specification-sha256",
        approvals["expected_original_specification_sha256"],
        "--expected-corrected-specification-sha256",
        approvals["expected_corrected_specification_sha256"],
        "--expected-selected-specification-sha256",
        approvals["expected_selected_specification_sha256"],
    ])
    cli.main()
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "supersession-unproven"
    assert report["mutation"] is False
    assert report["ssm_send_authorized"] is False
    assert _snapshot(root) == before



def test_native_pair_inventory_command_is_only_a_candidate(tmp_path):
    from zog.host_deploy import fonts_lane_supersession_native as native
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    report = _expect(root, approvals)
    script = native.native_read_only_script(report)
    assert "python3 -I -B -c " in script
    assert "source" in script
    assert "controller-inherited-v1.json" in script
    assert "pipeline.submit" not in script
    assert "pipeline.resume" not in script
    assert "send_command" not in script
    assert "subprocess.run(command" in script  # fixed Git rev-parse only
    assert native.candidate_script_sha256(report) == hashlib.sha256(
        script.encode("utf-8")).hexdigest()
    changed = dict(report, selected_controller_path="/tmp/injected.py")
    with pytest.raises(ValueError):
        native.native_read_only_script(changed)
    changed = dict(report, execution_authorized=True)
    with pytest.raises(ValueError):
        native.native_read_only_script(changed)


def test_native_pair_observer_runs_on_disposable_projects_without_any_write(tmp_path):
    """The separate native source inspection returns conflicts as diagnostics."""
    import shlex
    import subprocess
    from zog.host_deploy import fonts_lane_supersession_native as native
    current = tmp_path / "certbot-seed"
    prior = tmp_path / "initialized-original"
    for project in (current, prior):
        source = project / "source"
        source.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Test",
                        "-c", "user.email=example@example.org",
                        "commit", "--allow-empty", "-qm", "fixture"], check=True)
    (current / "controller-gateway-first-fonts-runtime-inherited-v1.json").write_bytes(
        b'{"selected":"certbot-seed"}\n')
    (prior / "controller-inherited-v1.json").write_bytes(
        b'{"historical":"different-controller"}\n')
    (prior / ".first-fonts-initialization-v1.json").write_bytes(
        b'{"manifest":"prior-revision"}\n')
    initial = _snapshot(tmp_path)
    values = (
        "ACTIVE=" + repr(str(current)) + "\n"
        "DESTINATION=" + repr(str(prior)) + "\n"
        "ACTIVE_CONTROLLER=" +
        repr("controller-gateway-first-fonts-runtime-inherited-v1.json") + "\n"
        "EXPECTED_ACTIVE_CONTROLLER=" + repr("a" * 64) + "\n"
        "EXPECTED_MANIFEST=" + repr("b" * 64) + "\n"
        "COMPILER_INSTANCE=" + repr(recovery.COMPILER_INSTANCE) + "\n"
        "WORKSPACE_ID=" + repr("e"*32) + "\n"
    )
    command = "python3 -I -B -c " + shlex.quote(values + native._OBSERVER)
    done = subprocess.run(command, shell=True, capture_output=True,
                          text=True, timeout=15)
    assert done.returncode == 0, done.stderr
    observed = json.loads(done.stdout)
    assert observed["status"] == "diagnostic-only"
    assert observed["active"]["project_root"] == str(current)
    assert observed["active"]["controller_present"] is True
    assert observed["initialized_destination"]["controller_present"] is True
    assert observed["active"]["controller_sha256"] != (
        observed["initialized_destination"]["controller_sha256"])
    assert observed["initialized_destination"]["manifest_sha256"] == hashlib.sha256(
        (prior / ".first-fonts-initialization-v1.json").read_bytes()).hexdigest()
    assert len(observed["active"]["source_head"]) == 40
    assert observed["compilation_authorized"] is False
    assert observed["ssm_send_authorized"] is False
    assert _snapshot(tmp_path) == initial

    parent = tmp_path / "redirect"
    parent.symlink_to(current, target_is_directory=True)
    altered = values.replace(repr(str(current)), repr(str(parent)))
    nofollow = subprocess.run("python3 -I -B -c " +
                              shlex.quote(altered + native._OBSERVER),
                              shell=True, capture_output=True, text=True, timeout=15)
    assert nofollow.returncode != 0
    assert "symlink or foreign Project ancestry" in nofollow.stderr
