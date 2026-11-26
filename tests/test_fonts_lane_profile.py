"""Historical first Fonts evidence and held inherited-identity migration.

Schema-4 UID/GID fields are created here only to represent an EXISTING record;
no public constructor or execution request can select an alternate account.
"""
import copy
import json
from pathlib import Path

import pytest

from zog.host_deploy import fonts_lane_profile as fonts
from zog.host_deploy import fonts_lane_runtime as runtime
from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import runner
from zog.host_deploy.workspace import initialize, save


def historical_specification():
    # First construct a valid identity-free candidate, then represent the old
    # serialized on-disk record explicitly. No new build request uses it.
    previous = lanes.specification(
        fonts.LANE, mode="managed", project_root=fonts.RETAINED_PROJECT_ROOT,
        source_repository=fonts.fonts.REPOSITORY,
        source_revision=fonts.fonts.SOURCE,
        monthly_pin_repository_path=fonts.fonts.PIN_PATH,
        monthly_pin_identity="sha256:" + fonts.fonts.PIN_SHA256,
        provenance_host_id="existing-verified-host-uuid",
        provenance_project_id="existing-verified-project-id",
        memory_maximum_bytes=2 * 1024**3, thread_count_maximum=16,
        cpu_weight=100, disk_reservation_bytes=1024**3,
        startup_timeout_seconds=30, execution_timeout_seconds=14400,
        python_executable="/usr/bin/python3.12",
    )
    previous["schema"] = lanes.SCHEMA
    previous["controller"].update(execution_user_id=24202, execution_group_id=24202)
    return lanes.validate(previous)


def workspace(tmp_path, monkeypatch):
    root = tmp_path / "owner"
    w = initialize(root, "image-build-toolchain", "zog-development", "us-east-1")
    host = {
        "region": w["region"], "profile": w["profile"],
        "instance_id": fonts.COMPILER_INSTANCE, "workspace_id": w["workspace_id"],
        "account_id": "123456789012",
    }
    save(root / "host.json", host)
    historic = historical_specification()
    digest = lanes.specification_sha256(historic)
    # Synthetic fixture, NOT the actual accepted historical record/digest.
    monkeypatch.setattr(fonts, "RETAINED_SPECIFICATION_SHA256", digest)
    path = root / "image-build-lanes" / (fonts.LANE + ".json")
    record = {"schema": lanes.SCHEMA, "lane": fonts.LANE,
              "specification": historic, "state": "prepared"}
    save(path, record)
    return root, w, host, path, record, digest


def deny_remote(monkeypatch):
    monkeypatch.setattr(runner, "Host", lambda *_: pytest.fail("read-only history must not contact Host"))
    monkeypatch.setattr(lanes, "Host", lambda *_: pytest.fail("historical lane must not activate"))


def test_profile_identifies_historical_source_and_does_not_reintroduce_envelope():
    p = fonts.profile()
    assert p["schema"] == "host-deploy-first-fonts-retained-lane-v3"
    assert p["retained_project_root"] == "/home/certbot-build-owner/gateway-first-fonts-runtime"
    assert p["retained_specification_sha256"] == fonts.RETAINED_SPECIFICATION_SHA256
    assert p["compiler_instance_id"] == "i-00ad300038a599044"
    assert p["source_revision"] == "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert p["monthly_pin_identity"] == "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert p["build_record_revision"] == "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
    assert "worker_resource_gate" not in p
    assert "remote_configuration" not in p


def test_historical_verify_and_prepare_are_read_only_with_no_installed_claim(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    before = path.read_bytes()
    deny_remote(monkeypatch)
    verified = fonts.verify(root)
    assert verified["historical_state"] == "prepared"
    assert verified["historical_specification_sha256"] == digest
    assert verified["historical_project_root"] == fonts.RETAINED_PROJECT_ROOT
    assert verified["execution_authorized"] is False
    assert verified["migration_required"] is True
    assert verified["binding"] == fonts._binding(w, host)
    assert fonts.prepare(root) == record
    assert fonts.verify(root) == verified
    assert path.read_bytes() == before
    assert not (root / fonts.FACTS_FILE).exists()
    assert not (root / fonts.INTENT_FILE).exists()


def test_migration_plan_only_previews_a_distinct_nonexecutable_schema_five(tmp_path, monkeypatch):
    root, _, _, path, record, digest = workspace(tmp_path, monkeypatch)
    before = path.read_bytes()
    deny_remote(monkeypatch)
    plan = fonts.migration_plan(root)
    assert plan["schema"] == "host-deploy-first-fonts-identity-migration-plan-v2"
    assert plan == fonts.migration_plan(root)
    assert plan["original_specification_sha256"] == digest
    assert plan["original_project_root"] == fonts.RETAINED_PROJECT_ROOT
    assert plan["original_state"] == "prepared"
    assert plan["execution_authorized"] is False
    assert plan["corrected_specification_is_executable"] is False
    assert "compatible-producer" in plan["status"]
    candidate = plan["corrected_specification"]
    assert candidate["schema"] == lanes.INHERITED_SCHEMA
    assert candidate["source_revision"] == lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION
    assert candidate["source_revision"] != record["specification"]["source_revision"]
    assert candidate["project_root"] == "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
    assert "execution_user_id" not in candidate["controller"]
    assert "execution_group_id" not in candidate["controller"]
    assert plan["corrected_specification_sha256"] == lanes.specification_sha256(candidate)
    assert plan["corrected_specification_sha256"] != digest
    assert plan["corrected_project_root"] == str(lanes.FIRST_FONTS_MIGRATED_ROOT)
    assert plan["migration_producer"] == "host-install-fonts-project-migrate"
    assert plan["migration_copy_verified"] is False
    assert plan["controller_rebinding_verified"] is False
    assert plan["compiler_child_identity_verified"] is False
    assert path.read_bytes() == before
    assert not (root / "image-build-lanes" / "new.json").exists()


@pytest.mark.parametrize("mutation", [
    lambda r: r["specification"]["resource_policy"].update(cpu_weight=101),
    lambda r: r["specification"].update(project_root="/var/lib/zog/image-build-lanes/gateway-first-fonts-runtime"),
    lambda r: r["specification"].update(source_revision="a" * 40),
    lambda r: r["specification"]["controller"].update(execution_user_id=24444),
    lambda r: r["specification"].update(provenance_project_id="other-project"),
    lambda r: r.update(fonts_lane_profile={"schema": "unreviewed"}),
])
def test_conflicting_historical_record_is_never_accepted_or_rewritten(tmp_path, monkeypatch, mutation):
    root, _, _, path, record, _ = workspace(tmp_path, monkeypatch)
    mutation(record)
    save(path, record)
    before = path.read_bytes()
    deny_remote(monkeypatch)
    for operation in (fonts.verify, fonts.prepare, fonts.migration_plan):
        with pytest.raises(RuntimeError):
            operation(root)
    assert path.read_bytes() == before


def test_foreign_workspace_or_compiler_host_holds_before_remote_contact(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    host["instance_id"] = "i-aaaaaaaaaaaaaaaaa"
    save(root / "host.json", host)
    deny_remote(monkeypatch)
    for op in (fonts.verify, fonts.prepare, fonts.migration_plan):
        with pytest.raises(RuntimeError, match="original workspace-owned compiler Host"):
            op(root)


def test_retained_lane_collision_in_other_record_is_rejected(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    foreign = lanes.specification(
        "foreign", mode="reservation", source_repository="zog144/image-build",
        source_revision="a" * 40, monthly_pin_repository_path="pin/path.py",
        monthly_pin_identity="sha256:" + "b" * 64,
        provenance_host_id="other",
        provenance_project_id=record["specification"]["provenance_project_id"],
        project_root="/srv/foreign", memory_maximum_bytes=1024,
        thread_count_maximum=2, cpu_weight=100, disk_reservation_bytes=1024,
        python_executable="/usr/bin/python3.12",
    )
    save(root / "image-build-lanes" / "foreign.json",
         {"schema": foreign["schema"], "lane": "foreign",
          "state": "retired", "specification": foreign})
    deny_remote(monkeypatch)
    with pytest.raises((RuntimeError, fonts.fonts_lane_review.FontsLaneHeld)):
        fonts.verify(root)


@pytest.mark.parametrize("state", ["prepared", "active"])
def test_historical_activation_refused_without_remote_install_or_rewriting(tmp_path, monkeypatch, state):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    record["state"] = state
    save(path, record)
    before = path.read_bytes()
    deny_remote(monkeypatch)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="historical account-selecting"):
            lanes.activate(root, fonts.LANE, expected_specification_sha256=digest)
    assert path.read_bytes() == before
    assert not (root / fonts.INTENT_FILE).exists()


def test_manual_legacy_activation_intent_is_not_authorized(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match="obsolete"):
        fonts.activation_intent(root, w, host, record["specification"])
    assert not (root / fonts.INTENT_FILE).exists()


def test_historical_retired_record_is_not_eligible_for_migration(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    record["state"] = "retired"
    save(path, record)
    with pytest.raises(RuntimeError, match="approval"):
        fonts.migration_plan(root)


def test_missing_original_lane_is_never_reconstructed(tmp_path):
    root = tmp_path / "owner"
    w = initialize(root, "image-build-toolchain", "zog-development", "us-east-1")
    save(root / "host.json", {"instance_id": fonts.COMPILER_INSTANCE,
         "account_id": "123456789012", "region": w["region"],
         "profile": w["profile"], "workspace_id": w["workspace_id"]})
    for op in (fonts.verify, fonts.prepare, fonts.migration_plan):
        with pytest.raises(RuntimeError, match="missing"):
            op(root)
    assert not (root / "image-build-lanes").exists()


def test_legacy_runtime_probe_is_refused_and_new_probe_never_selects_an_account():
    historical = historical_specification()
    with pytest.raises(ValueError, match="schema-5"):
        runtime.script(historical)
    new = lanes.corrected_first_fonts_specification(historical)
    script = runtime.script(new)
    assert "os.geteuid()" in script
    assert "os.getegid()" in script
    assert "uid==0 or gid==0" not in script
    assert "getpwuid" not in script
    assert "getgrgid" not in script
    assert "os.chown" not in script
    assert runtime.CONTROLLER_FILE in script
    assert "/etc/zog/first-fonts-controller-facts" not in script
    assert "os.O_NOFOLLOW" in script
    assert runtime.expected_controller_sha256(new)


def test_installed_probe_reports_existing_root_identity_without_mutating_state():
    historic = historical_specification()
    new = lanes.corrected_first_fonts_specification(historic)
    class Host:
        def command(self, code):
            return json.dumps({
                "status": "complete", "project_root": new["project_root"],
                "socket_path": new["controller"]["socket_path"],
                "effective_user_id": 0, "effective_group_id": 0,
                "python_executable": new["python_executable"],
                "controller_sha256": runtime.expected_controller_sha256(new),
            })
    inspected = runtime.inspect(Host(), new)
    assert inspected["effective_user_id"] == 0
    assert inspected["effective_group_id"] == 0


def test_new_schema_rejects_injected_execution_identity_selection():
    candidate = lanes.corrected_first_fonts_specification(historical_specification())
    for key in ("execution_user_id", "execution_group_id"):
        bad = copy.deepcopy(candidate)
        bad["controller"][key] = 24202
        with pytest.raises(ValueError, match="controller"):
            lanes.validate(bad)


def current_workspace(tmp_path):
    """A fresh current selection: NO schema-4 provenance or prior migration."""
    from zog.host_deploy import existing_project_runtime as existing
    root = tmp_path / "current-owner"
    workspace = initialize(root, "compiler", "zog-development", "us-east-1")
    host = {
        "region": workspace["region"], "profile": workspace["profile"],
        "instance_id": fonts.COMPILER_INSTANCE,
        "workspace_id": workspace["workspace_id"],
        "account_id": "123456789012",
    }
    save(root / "host.json", host)
    spec = lanes.specification(
        fonts.LANE, existing_project=True,
        project_root="/home/certbot-build-owner/certbot-seed",
        python_executable="/usr/bin/python3.12",
        memory_maximum_bytes=2**30, thread_count_maximum=16,
        cpu_weight=100, disk_reservation_bytes=2**30,
    )
    record = {
        "schema": lanes.INHERITED_SCHEMA, "lane": fonts.LANE,
        "state": "active", "specification": spec,
        "source_root": spec["project_root"] + "/source",
        "package_dir": spec["project_root"] + "/source/project/package",
        "state_dir": spec["project_root"] + "/state",
        "controller_config": (
            spec["project_root"] + "/" + existing.controller_file(spec)),
    }
    lane_path = root / "image-build-lanes" / (fonts.LANE + ".json")
    save(lane_path, record)
    return root, workspace, host, lane_path, record, spec


def test_current_fonts_profile_verify_uses_only_schema5_selection(
        tmp_path, monkeypatch):
    from zog.host_deploy import fonts_lane_migration, fonts_lane_recovery
    from zog.host_deploy import existing_project_runtime as existing
    import hashlib
    root, workspace, host, path, record, spec = current_workspace(tmp_path)
    def obsolete(*args, **kwargs):
        pytest.fail("current schema-5 selection must not depend on old migration")
    monkeypatch.setattr(fonts_lane_migration, "verify_existing", obsolete)
    monkeypatch.setattr(fonts_lane_recovery, "verify_published", obsolete)
    deny_remote(monkeypatch)

    original = path.read_bytes()
    assert not (root / "first-fonts-inherited-migration-v1.json").exists()
    assert not (root / "first-fonts-original-evidence").exists()
    assert not (root / "first-fonts-mixed-state-recovery-v1.json").exists()
    assert not (root / "first-fonts-activation-intent-v1.json").exists()
    selected = fonts.verify(root)
    assert selected == fonts.verify(root)
    assert selected["schema"] == "host-deploy-first-fonts-current-project-selection-v1"
    assert selected["binding"] == fonts._binding(workspace, host)
    assert selected["project_selection"] == "existing"
    assert selected["project_root"] == spec["project_root"]
    assert selected["controller_config"] == record["controller_config"]
    assert selected["expected_controller_sha256"] == hashlib.sha256(
        existing.expected_bytes(spec)).hexdigest()
    assert selected["specification_sha256"] == lanes.specification_sha256(spec)
    assert selected["migration_required"] is False
    assert selected["installed_controller_verified"] is False
    assert selected["native_readback_required"] is True
    assert selected["execution_authorized"] is False
    assert path.read_bytes() == original
    assert not (root / "first-fonts-inherited-migration-v1.json").exists()
    assert not (root / "first-fonts-original-evidence").exists()
    assert not (root / "first-fonts-mixed-state-recovery-v1.json").exists()


@pytest.mark.parametrize("changed", [
    "controller", "foreign-root", "inactive", "wrong-schema",
    "wrong-project-selection", "source-path", "wrong-workspace",
    "wrong-host", "wrong-region", "wrong-account", "bad-controller-policy",
])
def test_current_profile_rejects_foreign_selection_or_host_without_old_migration(
        tmp_path, monkeypatch, changed):
    root, workspace, host, path, record, spec = current_workspace(tmp_path)
    if changed == "controller":
        record["controller_config"] = record["controller_config"].replace(
            "controller-gateway-first-fonts-runtime-inherited-v1.json",
            "controller.json")
    elif changed == "foreign-root":
        spec["project_root"] = "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
    elif changed == "inactive":
        record["state"] = "prepared"
    elif changed == "wrong-schema":
        spec["schema"] = 4
    elif changed == "wrong-project-selection":
        spec["project_selection"] = "unchecked"
    elif changed == "source-path":
        record["source_root"] = "/tmp/wrong-project/source"
    elif changed == "wrong-workspace":
        host["workspace_id"] = "f" * 32
    elif changed == "wrong-host":
        host["instance_id"] = "i-fffffffffffffffff"
    elif changed == "wrong-region":
        host["region"] = "eu-west-1"
    elif changed == "wrong-account":
        host["account_id"] = "not-an-account"
    else:
        spec["controller"]["execution_user_id"] = 24202
    save(path, record)
    save(root / "host.json", host)
    before = path.read_bytes()
    deny_remote(monkeypatch)
    with pytest.raises((RuntimeError, ValueError, KeyError)):
        fonts.verify(root)
    assert path.read_bytes() == before
    assert not (root / "first-fonts-mixed-state-recovery-v1.json").exists()


def test_schema5_nonexisting_project_is_not_recast_as_legacy_migration(
        tmp_path, monkeypatch):
    root, _, host, path, record, spec = current_workspace(tmp_path)
    record["specification"]["project_selection"] = "new"
    save(path, record)
    deny_remote(monkeypatch)
    with pytest.raises((RuntimeError, ValueError)):
        fonts.verify(root)
    assert record["state"] == "active"
    assert not (root / "first-fonts-mixed-state-recovery-v1.json").exists()
