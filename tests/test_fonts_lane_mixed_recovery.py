"""Schema-5 existing Project recovery; no fabricated schema-4 lane/archive."""
import json
import os

import pytest

from zog.host_deploy import (
    fonts_lane_recovery as recovery, fonts_lane_migration as migration,
    image_build_lanes as lanes, existing_project_runtime as existing,
)
from zog.host_deploy.workspace import initialize, save
from zog.host_deploy.gateway.project_current import verify_approved_lane

CORRECTED = "sha256:" + "8" * 64
TREES = {"source": "a"*64, "companions/build-record": "b"*64,
         "companions/box-control": "c"*64}
MANIFEST = "d"*64


class Host:
    calls = []
    corrupt = None
    selected = None

    def __init__(self, config):
        assert config["instance_id"] == recovery.COMPILER_INSTANCE

    def command(self, script):
        Host.calls.append(script)
        if script == "host-install-fonts-project-init --verify":
            checkouts = {
                "source": {"repository": "zog144/image-build",
                           "revision": lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION},
                "companions/box-control": {
                    "repository": lanes.BOX_CONTROL_REPOSITORY,
                    "revision": lanes.FIRST_FONTS_INHERITED_BOX_CONTROL_REVISION},
                "companions/build-record": {
                    "repository": lanes.BUILD_RECORD_REPOSITORY,
                    "revision": lanes.expected_build_record_revision(
                        lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION)},
            }
            result = {
                "schema": "zog-fonts-project-first-initialization-v1",
                "action": "verify",
                "old_project": "/home/certbot-build-owner/gateway-first-fonts-runtime",
                "new_project": str(lanes.FIRST_FONTS_MIGRATED_ROOT),
                "historical_project_materialized": False, "copy_performed": False,
                "initialized_source_verified": True, "layout_complete": True,
                "missing_layout_directories": [],
                "runtime_layout": {"status": "ready", "missing": []},
                "controllers_present": [], "controller_installed": False,
                "compilation_authorized": False,
                "source_checkouts": checkouts, "source_tree_sha256": TREES,
                "manifest_sha256": MANIFEST,
                "destination": {"read_write_traverse": True,
                                "state_accessible": True, "source_accessible": True},
            }
        else:
            spec = Host.selected
            assert "pipeline.submit" not in script and "pipeline.resume" not in script
            result = {
                "project_root": recovery.EXISTING_EXECUTION_PROJECT,
                "project_identity": "certbot-seed", "status": "complete",
                "controller_file": recovery.EXISTING_EXECUTION_PROJECT + "/" +
                    existing.controller_file(spec),
                "controller_sha256": __import__("hashlib").sha256(
                    existing.expected_bytes(spec)).hexdigest(),
                "source_revision": "bce80b258e445191248d9998620884a79f029013",
                "effective_user_id": 0, "effective_group_id": 0,
            }
        if Host.corrupt:
            Host.corrupt(result)
        return json.dumps(result)


def fixture(tmp_path):
    root = tmp_path / "gateway-workspace"
    workspace = initialize(root, "compiler", "zog-development", "us-east-1")
    host = {"instance_id": recovery.COMPILER_INSTANCE,
            "workspace_id": workspace["workspace_id"], "account_id": "123456789012",
            "region": workspace["region"], "profile": workspace["profile"]}
    save(root / "host.json", host)
    spec = lanes.specification(
        recovery.LANE, existing_project=True,
        project_root=recovery.EXISTING_EXECUTION_PROJECT,
        source_repository="zog144/image-build",
        source_revision="bce80b258e445191248d9998620884a79f029013",
        memory_maximum_bytes=2**30, thread_count_maximum=16, cpu_weight=100,
        disk_reservation_bytes=2**30, python_executable="/usr/bin/python3.12")
    project = recovery.EXISTING_EXECUTION_PROJECT
    record = {
        "schema": 5, "lane": recovery.LANE, "state": "active",
        "specification": spec,
        "controller_config": project + "/" + existing.controller_file(spec),
        "source_root": project + "/source", "state_dir": project + "/state",
        "package_dir": project + "/source/project/package",
    }
    save(root / "image-build-lanes" / (recovery.LANE + ".json"), record)
    intent = {
        "schema": migration.INITIALIZATION_SCHEMA, "phase": "installing",
        "source_method": "prepared-first-initialization",
        "binding": {k: host[k] for k in
                    ("workspace_id", "account_id", "region", "instance_id")},
        "old_specification_sha256": recovery.RETAINED_OLD_SPEC_SHA,
        "new_specification_sha256": CORRECTED,
        "project_root": str(lanes.FIRST_FONTS_MIGRATED_ROOT),
        "source_revision": lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
        "compiler_authorized": False, "historical_project_materialized": False,
        "copy_performed": False, "initialization_manifest_sha256": MANIFEST,
        "initialized_source_tree_sha256": TREES,
    }
    save(root / migration.INTENT, intent)
    Host.calls, Host.corrupt, Host.selected = [], None, spec
    approvals = dict(
        expected_original_specification_sha256=recovery.RETAINED_OLD_SPEC_SHA,
        expected_corrected_specification_sha256=CORRECTED,
        expected_selected_specification_sha256=lanes.specification_sha256(spec))
    return root, workspace, host, record, spec, approvals


def test_mixed_active_certbot_seed_needs_no_schema4_and_never_restores_lane(tmp_path):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    lane = root / "image-build-lanes" / (recovery.LANE + ".json")
    intent = root / migration.INTENT
    originals = (lane.read_bytes(), intent.read_bytes())
    with pytest.raises(RuntimeError, match="evidence missing"):
        verify_approved_lane(root, ws, host, record, spec)
    viewed = recovery.inspect(root, **approvals, host_factory=Host)
    assert viewed["selected_project_root"] == recovery.EXISTING_EXECUTION_PROJECT
    assert viewed["initialized_project_root"] != viewed["selected_project_root"]
    assert viewed["execution_authorized"] is False and viewed["mutation"] is False
    assert len(Host.calls) == 2
    assert originals == (lane.read_bytes(), intent.read_bytes())
    assert not (root / migration.HISTORY).exists()
    published = recovery.publish(root, **approvals, host_factory=Host)
    assert viewed == published
    assert (root / recovery.RECEIPT).stat().st_mode & 0o777 == 0o600
    assert verify_approved_lane(root, ws, host, record, spec) == viewed
    assert originals == (lane.read_bytes(), intent.read_bytes())
    assert not (root / migration.HISTORY).exists()


@pytest.mark.parametrize("name", [
    "expected_original_specification_sha256",
    "expected_corrected_specification_sha256",
    "expected_selected_specification_sha256",
])
def test_unapproved_digest_blocks_before_any_host_call(tmp_path, name):
    root, _, _, _, _, approvals = fixture(tmp_path)
    approvals[name] = "sha256:" + "f"*64
    with pytest.raises(RuntimeError, match="digest|specification"):
        recovery.publish(root, **approvals, host_factory=Host)
    assert not Host.calls and not (root / recovery.RECEIPT).exists()


@pytest.mark.parametrize("field,value", [
    ("phase", "staged"), ("compiler_authorized", True),
    ("old_specification_sha256", "sha256:" + "0"*64),
    ("new_specification_sha256", "sha256:" + "0"*64),
    ("initialization_manifest_sha256", "0"*64),
    ("project_root", "/home/certbot-build-owner/certbot-seed"),
    ("source_revision", "0"*40),
])
def test_mixed_intent_mismatch_never_publishes(tmp_path, field, value):
    root, _, _, _, _, approvals = fixture(tmp_path)
    path = root / migration.INTENT
    updated = json.loads(path.read_text())
    updated[field] = value
    save(path, updated)
    with pytest.raises(RuntimeError, match="intent|provenance"):
        recovery.publish(root, **approvals, host_factory=Host)
    assert not Host.calls and not (root / recovery.RECEIPT).exists()


def test_compiler_or_initializer_mismatch_holds(tmp_path):
    root, _, host, _, _, approvals = fixture(tmp_path)
    Host.corrupt = lambda report: (
        report["source_checkouts"]["source"].update(
            revision="bce80b258e445191248d9998620884a79f029013")
        if "source_checkouts" in report else None)
    with pytest.raises(RuntimeError, match="initialization is not verified"):
        recovery.publish(root, **approvals, host_factory=Host)
    assert len(Host.calls) == 1 and not (root / recovery.RECEIPT).exists()
    Host.corrupt = None
    host["instance_id"] = "i-aaaaaaaaaaaaaaaaa"
    save(root / "host.json", host)
    with pytest.raises(RuntimeError, match="workspace/compiler"):
        recovery.inspect(root, **approvals, host_factory=Host)


def test_record_drift_or_missing_archive_conflict_cannot_be_silenced(tmp_path):
    root, ws, host, record, spec, approvals = fixture(tmp_path)
    recovery.publish(root, **approvals, host_factory=Host)
    record["state"] = "retired"
    save(root / "image-build-lanes" / (recovery.LANE + ".json"), record)
    with pytest.raises(RuntimeError):
        recovery.verify_published(root, ws, host, record, spec)
    root2, _, _, _, _, approvals2 = fixture(tmp_path / "other")
    archive = (root2 / migration.HISTORY /
               (recovery.RETAINED_OLD_SPEC_SHA[7:] + ".json"))
    archive.parent.mkdir()
    archive.write_text('{"foreign":"archive"}')
    with pytest.raises(RuntimeError, match="history|archive"):
        recovery.inspect(root2, **approvals2, host_factory=Host)
