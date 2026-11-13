"""Retained first Fonts profile: synthetic owner workspace and compiler Host only."""
import copy
import json
from pathlib import Path

import pytest

from zog.host_deploy import fonts_lane_profile as fonts
from zog.host_deploy import fonts_lane_runtime as runtime
from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import runner
from zog.host_deploy.workspace import initialize, save


def workspace(tmp_path, monkeypatch):
    root = tmp_path / "owner"
    w = initialize(root, "image-build-toolchain", "zog-development", "us-east-1")
    host = {
        "region": w["region"], "profile": w["profile"],
        "instance_id": fonts.COMPILER_INSTANCE, "workspace_id": w["workspace_id"],
        "account_id": "123456789012",
    }
    save(root / "host.json", host)
    candidate = lanes.specification(
        fonts.LANE, mode="managed", project_root=fonts.RETAINED_PROJECT_ROOT,
        source_repository=fonts.fonts.REPOSITORY, source_revision=fonts.fonts.SOURCE,
        monthly_pin_repository_path=fonts.fonts.PIN_PATH,
        monthly_pin_identity="sha256:" + fonts.fonts.PIN_SHA256,
        provenance_host_id="existing-verified-host-uuid",
        provenance_project_id="existing-verified-project-id",
        memory_maximum_bytes=2 * 1024**3, thread_count_maximum=16,
        cpu_weight=100, disk_reservation_bytes=1024**3,
        execution_user_id=24202, execution_group_id=24202,
        startup_timeout_seconds=30, execution_timeout_seconds=14400,
        python_executable="/usr/bin/python3.12",
    )
    # Synthetic test record is not the historical approved record. Require
    # the runtime's full digest comparison, with a local fixture-specific pin.
    digest = lanes.specification_sha256(candidate)
    monkeypatch.setattr(fonts, "RETAINED_SPECIFICATION_SHA256", digest)
    path = root / "image-build-lanes" / (fonts.LANE + ".json")
    record = {"schema": 4, "lane": fonts.LANE, "specification": candidate,
              "state": "prepared"}
    save(path, record)
    return root, w, host, path, record, digest


def installed(spec, status="absent"):
    return {
        "status": status,
        "project_root": spec["project_root"],
        "socket_path": spec["controller"]["socket_path"],
        "execution_user_id": spec["controller"]["execution_user_id"],
        "execution_group_id": spec["controller"]["execution_group_id"],
        "python_executable": spec["python_executable"],
        "controller_sha256": runtime.expected_controller_sha256(spec),
    }


def verify(root, monkeypatch, record, status="absent", now=1000):
    observed = installed(record["specification"], status)
    class Host:
        def __init__(self, config):
            assert config["instance_id"] == fonts.COMPILER_INSTANCE
        def command(self, code):
            assert "/etc/zog/first-fonts-controller-facts" not in code
            assert "os.O_NOFOLLOW" in code
            assert "getpwuid" in code
            return json.dumps(observed)
    monkeypatch.setattr(runner, "Host", Host)
    result = fonts.verify(root, now=now)
    assert result["installed"] == observed
    return result


def test_reviewed_retained_identity_is_unchanged():
    assert fonts.RETAINED_SPECIFICATION_SHA256 == (
        "sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2"
    )
    p = fonts.profile()
    assert p["retained_specification_sha256"] == fonts.RETAINED_SPECIFICATION_SHA256
    assert p["retained_project_root"] == "/home/certbot-build-owner/gateway-first-fonts-runtime"
    assert p["compiler_instance_id"] == "i-00ad300038a599044"
    assert p["source_revision"] == "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert p["monthly_pin_identity"] == (
        "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    )
    assert p["build_record_revision"] == "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
    assert "worker_resource_gate" not in p
    assert "remote_configuration" not in p


def test_exact_old_prepared_record_verifies_and_prepare_returns_identical_bytes(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    original = path.read_bytes()
    verify(root, monkeypatch, record)
    monkeypatch.setattr(runner, "Host", lambda *_: pytest.fail("prepare must not contact Host"))
    assert fonts.prepare(root, now=1010) == record
    assert path.read_bytes() == original
    assert not (root / fonts.INTENT_FILE).exists()


@pytest.mark.parametrize("mutation", [
    lambda r: r["specification"]["resource_policy"].update(cpu_weight=101),
    lambda r: r["specification"].update(project_root="/var/lib/zog/image-build-lanes/gateway-first-fonts-runtime"),
    lambda r: r["specification"].update(source_revision="a"*40),
    lambda r: r["specification"]["controller"].update(execution_user_id=24444),
    lambda r: r["specification"].update(provenance_project_id="other-project"),
    lambda r: r.update(fonts_lane_profile={"schema": "unreviewed"}),
])
def test_conflicting_digest_source_root_identity_and_controller_hold(tmp_path, monkeypatch, mutation):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    previous = copy.deepcopy(record)
    mutation(record)
    save(path, record)
    with pytest.raises(RuntimeError):
        fonts.verify(root)
    assert json.loads(path.read_text()) == record


def test_foreign_workspace_or_compiler_host_holds_before_remote_contact(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    host["instance_id"] = "i-aaaaaaaaaaaaaaaaa"
    save(root / "host.json", host)
    monkeypatch.setattr(runner, "Host", lambda *_: pytest.fail("foreign Host contacted"))
    with pytest.raises(RuntimeError, match="original workspace-owned compiler Host"):
        fonts.verify(root)


def test_mismatching_installed_controller_or_identity_holds(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    observed = installed(record["specification"], "complete")
    observed["execution_user_id"] += 1
    class Host:
        def __init__(self, *_): pass
        def command(self, *_): return json.dumps(observed)
    monkeypatch.setattr(runner, "Host", Host)
    with pytest.raises(RuntimeError, match="differs"):
        fonts.verify(root)
    assert not (root / fonts.FACTS_FILE).exists()


def test_retained_lane_collision_in_other_record_is_rejected(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    foreign = lanes.specification(
        "foreign", mode="reservation", source_repository="zog144/image-build",
        source_revision="a"*40, monthly_pin_repository_path="pin/path.py",
        monthly_pin_identity="sha256:"+"b"*64,
        provenance_host_id="other", provenance_project_id=record["specification"]["provenance_project_id"],
        project_root="/srv/foreign", memory_maximum_bytes=1024,
        thread_count_maximum=2, cpu_weight=100, disk_reservation_bytes=1024,
        execution_user_id=1001, execution_group_id=1001,
    )
    save(root / "image-build-lanes" / "foreign.json",
         {"schema": foreign["schema"], "lane": "foreign", "state": "retired", "specification": foreign})
    with pytest.raises((RuntimeError, fonts.fonts_lane_review.FontsLaneHeld)):
        fonts.verify(root)


def activation_host(monkeypatch, spec, observed):
    calls = []
    class Host:
        def __init__(self, config):
            assert config["instance_id"] == fonts.COMPILER_INSTANCE
            calls.append("host")
        def command(self, command):
            raise AssertionError("script must be patched in unit activation")
        def upload(self, *_):
            raise AssertionError("never upload/overwrite retained controller")
    monkeypatch.setattr(lanes, "Host", Host)
    monkeypatch.setattr(lanes, "runtime_preflight", lambda *_: {})
    monkeypatch.setattr(runtime, "inspect", lambda host, spec: (calls.append("inspect") or installed(spec, observed[0])))
    monkeypatch.setattr(runtime, "install", lambda host, spec: (calls.append("install"), observed.__setitem__(0, "complete")))
    monkeypatch.setattr(lanes, "_capacity", lambda *_: {"disk_free_bytes": 100*1024**3})
    return calls


def test_matching_active_lane_readback_is_idempotent_no_rewrite(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    record["state"] = "active"
    save(path, record)
    verify(root, monkeypatch, record, status="complete", now=1000)
    monkeypatch.setattr(fonts.time, "time", lambda: 1100)
    calls = activation_host(monkeypatch, record["specification"], ["complete"])
    original = path.read_bytes()
    first = lanes.activate(root, fonts.LANE, expected_specification_sha256=digest)
    assert first == record
    assert lanes.activate(root, fonts.LANE, expected_specification_sha256=digest) == record
    assert path.read_bytes() == original
    assert "install" not in calls
    assert not (root / fonts.INTENT_FILE).exists()


def test_active_lane_verifies_installed_state_without_recent_local_snapshot(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    record["state"] = "active"
    save(path, record)
    calls = activation_host(monkeypatch, record["specification"], ["complete"])
    before = path.read_bytes()
    assert lanes.activate(root, fonts.LANE, expected_specification_sha256=digest) == record
    assert path.read_bytes() == before
    assert "install" not in calls and "inspect" in calls


def test_prepared_lane_reconciles_complete_remote_after_local_interruption(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    verify(root, monkeypatch, record, status="complete", now=1000)
    monkeypatch.setattr(fonts.time, "time", lambda: 1100)
    calls = activation_host(monkeypatch, record["specification"], ["complete"])
    active = lanes.activate(root, fonts.LANE, expected_specification_sha256=digest)
    assert active["state"] == "active"
    assert active["specification"] == record["specification"]
    assert active["controller_config"] == fonts.RETAINED_PROJECT_ROOT + "/controller.json"
    assert "install" not in calls
    assert lanes.inspect(root, fonts.LANE) == active


def test_initial_absent_activation_persists_intent_then_installs_exclusively(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    verify(root, monkeypatch, record, status="absent", now=1000)
    monkeypatch.setattr(fonts.time, "time", lambda: 1100)
    observed = ["absent"]
    calls = activation_host(monkeypatch, record["specification"], observed)
    active = lanes.activate(root, fonts.LANE, expected_specification_sha256=digest)
    assert active["state"] == "active"
    assert calls.count("install") == 1
    intent = json.loads((root / fonts.INTENT_FILE).read_text())
    assert intent["specification_sha256"] == digest
    assert intent["binding"] == fonts._binding(w, host)


@pytest.mark.parametrize("remote", ["absent", "partial"])
def test_pending_activation_never_reissues_unresolved_remote_command(tmp_path, monkeypatch, remote):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    verify(root, monkeypatch, record, status=remote, now=1000)
    monkeypatch.setattr(fonts.time, "time", lambda: 1100)
    calls = activation_host(monkeypatch, record["specification"], [remote])
    fonts.activation_intent(root, w, host, record["specification"])
    with pytest.raises(RuntimeError, match="unresolved"):
        lanes.activate(root, fonts.LANE, expected_specification_sha256=digest)
    assert "install" not in calls
    assert path.read_bytes() == json.dumps(record, indent=2).encode() + b"\n"


def test_digest_mismatch_blocks_before_host_and_other_lane_activation(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    verify(root, monkeypatch, record, now=1000)
    monkeypatch.setattr(fonts.time, "time", lambda: 1100)
    monkeypatch.setattr(lanes, "Host", lambda *_: pytest.fail("Host should not be contacted"))
    with pytest.raises(RuntimeError, match="digest/Host/source"):
        lanes.activate(root, fonts.LANE, expected_specification_sha256="sha256:"+"f"*64)
    with pytest.raises(RuntimeError, match="explicit digest"):
        lanes.activate(root, fonts.LANE)


def test_missing_original_lane_is_never_reconstructed(tmp_path):
    root = tmp_path / "owner"
    w = initialize(root, "image-build-toolchain", "zog-development", "us-east-1")
    save(root / "host.json", {"instance_id": fonts.COMPILER_INSTANCE,
         "account_id": "123456789012", "region": w["region"],
         "profile": w["profile"], "workspace_id": w["workspace_id"]})
    with pytest.raises(RuntimeError, match="missing"):
        fonts.prepare(root)
    assert not (root / "image-build-lanes").exists()


def test_installed_probe_is_derived_from_owner_controller_not_manual_config(tmp_path, monkeypatch):
    root, w, host, path, record, digest = workspace(tmp_path, monkeypatch)
    code = runtime.script(record["specification"])
    assert "controller.json" in code
    assert "getpwuid" in code
    assert "/etc/zog/first-fonts-controller-facts" not in code
    assert "os.O_NOFOLLOW" in code
    assert runtime.expected_controller_sha256(record["specification"])
