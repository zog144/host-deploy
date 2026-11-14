"""Native migration orchestration with simulated SSM: no Host files/queue touched."""
import copy
import json
from pathlib import Path

import pytest

from zog.host_deploy import fonts_lane_migration as m, fonts_lane_profile as fonts
from zog.host_deploy import image_build_lanes as lanes
from test_fonts_lane_profile import workspace


class FakeHost:
    commands = []
    def __init__(self, configuration):
        self.configuration = configuration
        self.commands = []

    def command(self, script):
        self.commands.append(script)
        if script == "host-install-fonts-project-migrate --verify":
            return json.dumps({
                "schema": "zog-fonts-project-nondestructive-migration-v1",
                "action": "verify", "old_project": fonts.RETAINED_PROJECT_ROOT,
                "new_project": fonts.PROJECT_ROOT, "data_verified": True,
                "old_project_preserved": True, "source_unchanged": True,
                "controller_rebound": False, "accounts_deleted": False,
                "source_tree_sha256": "a" * 64,
                "destination": {"read_write_traverse": True,
                                "state_accessible": True, "source_accessible": True},
            })
        if "disk_free_bytes" in script:
            return json.dumps({"disk_free_bytes": 2**44})
        raise AssertionError("unexpected remote operation: " + script[:200])


def staged(tmp_path, monkeypatch):
    root, ws, config, path, old, digest = workspace(tmp_path, monkeypatch)
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    new_digest = lanes.specification_sha256(corrected)
    original = path.read_bytes()
    intent = m.stage(root, expected_original_specification_sha256=digest,
                     expected_corrected_specification_sha256=new_digest,
                     host_factory=FakeHost)
    return root, path, original, corrected, digest, new_digest, intent


def test_stage_preserves_original_and_is_read_only_on_repeat(tmp_path, monkeypatch):
    root, path, original, corrected, old_digest, digest, intent = staged(tmp_path, monkeypatch)
    assert path.read_bytes() == original
    assert intent["phase"] == "staged"
    assert intent["copy_source_tree_sha256"] == "a" * 64
    assert intent["new_specification_sha256"] == digest
    repeated = m.stage(root, expected_original_specification_sha256=old_digest,
                       expected_corrected_specification_sha256=digest,
                       host_factory=lambda *_: pytest.fail("stage repeat cannot resubmit SSM"))
    assert repeated == intent
    assert not (root / m.HISTORY).exists()


def test_controller_install_and_archived_exact_history(tmp_path, monkeypatch):
    root, path, original, corrected, old_digest, digest, intent = staged(tmp_path, monkeypatch)
    observed = {"status": "prepared"}
    writes = []
    monkeypatch.setattr(m, "_source_selection", lambda host, spec: {"revisions": {"source": spec["source_revision"]}})
    monkeypatch.setattr(m.runtime, "inspect", lambda host, spec: dict(observed))
    def install(host, spec):
        writes.append(spec)
        observed["status"] = "complete"
        return dict(observed)
    monkeypatch.setattr(m.runtime, "install", install)
    activated = m.activate(root, expected_corrected_specification_sha256=digest,
                           host_factory=FakeHost)
    assert activated["schema"] == 5 and activated["state"] == "active"
    assert activated["specification"] == corrected
    assert activated["controller_config"].endswith("/controller-inherited-v1.json")
    assert activated["fonts_migration"]["compilation_authorized"] is False
    assert activated["runtime_companion"]["producer_revision"] == corrected["source_revision"]
    assert activated["controller_companion"]["revision"] == lanes.FIRST_FONTS_INHERITED_BOX_CONTROL_REVISION
    archival = Path(activated["fonts_migration"]["historical_record_path"])
    assert archival.read_bytes() == original
    assert activated["fonts_migration"]["original_record_sha256"] == m._hash(original)
    before = path.read_bytes()
    assert m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost) == activated
    assert len(writes) == 1 and path.read_bytes() == before


def test_interrupted_remote_install_never_blindly_retries(tmp_path, monkeypatch):
    root, path, original, corrected, old_digest, digest, intent = staged(tmp_path, monkeypatch)
    observed = {"status": "prepared"}
    writes = []
    monkeypatch.setattr(m, "_source_selection", lambda *args: {})
    monkeypatch.setattr(m.runtime, "inspect", lambda *args: dict(observed))
    def lost_ack(*args):
        writes.append("issued")
        observed["status"] = "complete"
        raise TimeoutError("SSM acknowledgement lost")
    monkeypatch.setattr(m.runtime, "install", lost_ack)
    with pytest.raises(TimeoutError, match="acknowledgement lost"):
        m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost)
    assert path.read_bytes() == original
    assert m._read(root / m.INTENT)["phase"] == "installing"
    # A repeated invocation only reads remote installation; no second write.
    assert m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost)["state"] == "active"
    assert len(writes) == 1


def test_unknown_remote_ack_without_complete_controller_holds(tmp_path, monkeypatch):
    root, path, original, corrected, old_digest, digest, intent = staged(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_source_selection", lambda *args: {})
    monkeypatch.setattr(m.runtime, "inspect", lambda *args: {"status": "prepared"})
    def unknown(*args):
        raise TimeoutError("SSM acknowledgement lost")
    monkeypatch.setattr(m.runtime, "install", unknown)
    with pytest.raises(TimeoutError):
        m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost)
    monkeypatch.setattr(m.runtime, "install", lambda *args: pytest.fail("blind resubmission"))
    with pytest.raises(RuntimeError, match="no resubmission"):
        m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost)
    assert path.read_bytes() == original


def test_wrong_digest_rejected_without_remote_contact(tmp_path, monkeypatch):
    root, ws, config, path, old, digest = workspace(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match="digest differs"):
        m.stage(root, expected_original_specification_sha256=digest,
                expected_corrected_specification_sha256="sha256:" + "0" * 64,
                host_factory=lambda *args: pytest.fail("no remote call"))
    assert not (root / m.INTENT).exists()


def test_copy_does_not_claim_controller_migrated(tmp_path, monkeypatch):
    root, ws, config, path, old, digest = workspace(tmp_path, monkeypatch)
    class Incorrect(FakeHost):
        def command(self, script):
            if script == "host-install-fonts-project-migrate --verify":
                report = json.loads(super().command(script))
                report["controller_rebound"] = True
                return json.dumps(report)
            return super().command(script)
    with pytest.raises(RuntimeError, match="not the verified original"):
        m.stage(root, expected_original_specification_sha256=digest,
                expected_corrected_specification_sha256=lanes.specification_sha256(
                    lanes.corrected_first_fonts_specification(old["specification"])),
                host_factory=Incorrect)
    assert not (root / m.INTENT).exists()


def test_new_controller_is_separate_from_copied_legacy_json():
    from zog.host_deploy import fonts_lane_runtime as runtime
    assert runtime.CONTROLLER_FILE != "controller.json"
    assert "controller-inherited-v1.json" in runtime.script(
        lanes.corrected_first_fonts_specification(
            {**lanes.specification("gateway-first-fonts-runtime", mode="managed",
                 project_root=fonts.RETAINED_PROJECT_ROOT,
                 source_repository="zog144/image-build", source_revision=fonts.fonts.SOURCE,
                 monthly_pin_repository_path=fonts.fonts.PIN_PATH,
                 monthly_pin_identity="sha256:" + fonts.fonts.PIN_SHA256,
                 provenance_host_id="old", provenance_project_id="old-proj",
                 memory_maximum_bytes=2**30, thread_count_maximum=16,
                 cpu_weight=100, disk_reservation_bytes=2**30,
                 python_executable="/usr/bin/python3"), "schema":4,
             "controller": {**lanes.specification("gateway-first-fonts-runtime", mode="managed",
                 project_root=fonts.RETAINED_PROJECT_ROOT,
                 source_repository="zog144/image-build", source_revision=fonts.fonts.SOURCE,
                 monthly_pin_repository_path=fonts.fonts.PIN_PATH,
                 monthly_pin_identity="sha256:" + fonts.fonts.PIN_SHA256,
                 provenance_host_id="old", provenance_project_id="old-proj",
                 memory_maximum_bytes=2**30, thread_count_maximum=16,
                 cpu_weight=100, disk_reservation_bytes=2**30,
                 python_executable="/usr/bin/python3")["controller"],
             "execution_user_id":24201,"execution_group_id":24202}}))


def test_historical_verify_after_migration_checks_byte_identical_archive(tmp_path, monkeypatch):
    root, path, original, corrected, old_digest, digest, intent = staged(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_source_selection", lambda *args: {})
    status = {"status": "prepared"}
    monkeypatch.setattr(m.runtime, "inspect", lambda *args: dict(status))
    def install(*args):
        status["status"] = "complete"
        return dict(status)
    monkeypatch.setattr(m.runtime, "install", install)
    record = m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost)
    observed = fonts.verify(root)
    assert observed["historical_specification_sha256"] == old_digest
    assert observed["corrected_specification_sha256"] == digest
    assert observed["execution_authorized"] is False
    archived = Path(observed["historical_archive"])
    archived.write_text("tampered")
    with pytest.raises(RuntimeError):
        fonts.verify(root)


def test_foreign_controller_before_migration_intent_never_accepted(tmp_path, monkeypatch):
    root, path, original, corrected, old_digest, digest, intent = staged(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_source_selection", lambda *args: {})
    monkeypatch.setattr(m.runtime, "inspect", lambda *args: {"status": "complete"})
    monkeypatch.setattr(m.runtime, "install", lambda *args: pytest.fail("unexpected installation"))
    with pytest.raises(RuntimeError, match="appeared before reviewed installation intent"):
        m.activate(root, expected_corrected_specification_sha256=digest, host_factory=FakeHost)
    assert path.read_bytes() == original

class InitializedHost(FakeHost):
    def command(self, script):
        if script == "host-install-fonts-project-init --verify":
            source = lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION
            return json.dumps({
                "schema": "zog-fonts-project-first-initialization-v1",
                "action": "verify", "old_project": fonts.RETAINED_PROJECT_ROOT,
                "new_project": fonts.PROJECT_ROOT,
                "historical_project_materialized": False,
                "copy_performed": False,
                "initialized_source_verified": True,
                "layout_complete": True,
                "missing_layout_directories": [],
                "controller_installed": False,
                "compilation_authorized": False,
                "manifest_sha256": "1" * 64,
                "source_checkouts": {
                    "source": {"repository": "zog144/image-build", "revision": source},
                    "companions/box-control": {"repository": lanes.BOX_CONTROL_REPOSITORY,
                                               "revision": lanes.FIRST_FONTS_INHERITED_BOX_CONTROL_REVISION},
                    "companions/build-record": {"repository": lanes.BUILD_RECORD_REPOSITORY,
                                                 "revision": lanes.expected_build_record_revision(source)},
                },
                "source_tree_sha256": {name: char * 64 for name, char in
                                       (("source", "a"), ("companions/box-control", "b"),
                                        ("companions/build-record", "c"))},
                "destination": {"read_write_traverse": True, "state_accessible": True,
                                "source_accessible": True},
            })
        if script == "host-install-fonts-project-migrate --verify":
            raise AssertionError("prepared initialization must not invent a copy receipt")
        return super().command(script)


def test_prepared_never_materialized_initialization_distinct_from_copy(tmp_path, monkeypatch):
    root, ws, host, path, old, digest = workspace(tmp_path, monkeypatch)
    original = path.read_bytes()
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    new_digest = lanes.specification_sha256(corrected)
    intent = m.stage(root, expected_original_specification_sha256=digest,
                     expected_corrected_specification_sha256=new_digest,
                     prepared_initialize=True, host_factory=InitializedHost)
    assert intent["schema"] == m.INITIALIZATION_SCHEMA
    assert intent["source_method"] == "prepared-first-initialization"
    assert intent["initialization_manifest_sha256"] == "1" * 64
    assert "copy_report_sha256" not in intent
    assert "copy_source_tree_sha256" not in intent
    assert intent["historical_project_materialized"] is False
    assert path.read_bytes() == original
    assert m.stage(root, expected_original_specification_sha256=digest,
                   expected_corrected_specification_sha256=new_digest,
                   prepared_initialize=True,
                   host_factory=lambda *_: pytest.fail("idempotent stage must not call SSM")) == intent
    with pytest.raises(RuntimeError, match="conflicts"):
        m.stage(root, expected_original_specification_sha256=digest,
                expected_corrected_specification_sha256=new_digest,
                prepared_initialize=False, host_factory=FakeHost)
    assert path.read_bytes() == original


def test_never_created_activation_uses_real_init_not_copy_receipt(tmp_path, monkeypatch):
    root, ws, host, path, old, digest = workspace(tmp_path, monkeypatch)
    original = path.read_bytes()
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    new_digest = lanes.specification_sha256(corrected)
    m.stage(root, expected_original_specification_sha256=digest,
            expected_corrected_specification_sha256=new_digest,
            prepared_initialize=True, host_factory=InitializedHost)
    observed = {"status": "prepared"}
    writes = []
    monkeypatch.setattr(m, "_source_selection", lambda *a: {"verified": True})
    monkeypatch.setattr(m.runtime, "inspect", lambda *a: dict(observed))
    def install(*_):
        writes.append(True)
        observed["status"] = "complete"
    monkeypatch.setattr(m.runtime, "install", install)
    active = m.activate(root, expected_corrected_specification_sha256=new_digest,
                        host_factory=InitializedHost)
    assert active["fonts_migration"]["source_method"] == "prepared-first-initialization"
    assert active["fonts_migration"]["historical_project_materialized"] is False
    assert "copy_report_sha256" not in active["fonts_migration"]
    assert Path(active["fonts_migration"]["historical_record_path"]).read_bytes() == original
    assert m.verify_existing(root, ws, host, active)["execution_authorized"] is False
    assert m.activate(root, expected_corrected_specification_sha256=new_digest,
                      host_factory=InitializedHost) == active
    assert len(writes) == 1


def test_previously_active_lane_cannot_be_reinitialized(tmp_path, monkeypatch):
    root, ws, host, path, old, digest = workspace(tmp_path, monkeypatch)
    old["state"] = "active"
    from zog.host_deploy.workspace import save
    save(path, old)
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    with pytest.raises(RuntimeError, match="only a never-activated prepared lane"):
        m.stage(root, expected_original_specification_sha256=digest,
                expected_corrected_specification_sha256=lanes.specification_sha256(corrected),
                prepared_initialize=True,
                host_factory=lambda *_: pytest.fail("must reject before contacting Host"))
    assert not (root / m.INTENT).exists()


def test_fabricated_copy_receipt_rejected_by_initialization_stage(tmp_path, monkeypatch):
    root, ws, host, path, old, digest = workspace(tmp_path, monkeypatch)
    class Fabricated(InitializedHost):
        def command(self, script):
            report = json.loads(super().command(script))
            if script == "host-install-fonts-project-init --verify":
                report["copy_performed"] = True
            return json.dumps(report)
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    with pytest.raises(RuntimeError, match="initialization is not verified"):
        m.stage(root, expected_original_specification_sha256=digest,
                expected_corrected_specification_sha256=lanes.specification_sha256(corrected),
                prepared_initialize=True, host_factory=Fabricated)
    assert not (root / m.INTENT).exists()


def test_prepared_initializer_partial_layout_cannot_stage_as_ready(
        tmp_path, monkeypatch):
    root, ws, config, path, old, digest = workspace(tmp_path, monkeypatch)
    corrected = lanes.corrected_first_fonts_specification(old["specification"])
    new_digest = lanes.specification_sha256(corrected)

    class Partial(InitializedHost):
        def command(self, script):
            raw = super().command(script)
            if script == "host-install-fonts-project-init --verify":
                result = json.loads(raw)
                result["layout_complete"] = False
                result["missing_layout_directories"] = [
                    "package", "application", "catalogue"]
                return json.dumps(result)
            return raw

    with pytest.raises(RuntimeError, match="initialization is not verified"):
        m.stage(root, expected_original_specification_sha256=digest,
                expected_corrected_specification_sha256=new_digest,
                prepared_initialize=True, host_factory=Partial)
    assert path.read_bytes()
    assert not (root / m.INTENT).exists()
