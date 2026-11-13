"""Source-owned first-Fonts lane profile; all Host responses are synthetic."""
import json
from pathlib import Path

import pytest

from zog.host_deploy import fonts_lane_profile as fonts
from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import runner
from zog.host_deploy.gateway import fonts_lane_review
from zog.host_deploy.workspace import initialize, save


COMPILER = "i-00ad300038a599044"


def workspace(tmp_path):
    root = tmp_path / "owner-workspace"
    w = initialize(root, "image-build-toolchain", "zog-development", "us-east-1")
    save(root / "host.json", {
        "region": w["region"], "profile": w["profile"],
        "instance_id": COMPILER, "workspace_id": w["workspace_id"],
        "account_id": "123456789012",
    })
    return root, w


def facts(w, *, host_id="host-fixture", project_id="first-fonts-project", **changes):
    record = {
        "schema": fonts.REMOTE_CONFIG_SCHEMA,
        "workspace_id": w["workspace_id"],
        "account_id": "123456789012",
        "region": w["region"], "instance_id": COMPILER,
        "provenance_host_id": host_id,
        "provenance_project_id": project_id,
        "observed_state_dir": None,
        "python_executable": "/usr/bin/python3.12",
        "controller": {
            "socket_path": "/run/zog/root-control.sock",
            "execution_user_id": 24202, "execution_group_id": 24202,
            "startup_timeout_seconds": 30, "execution_timeout_seconds": 14400,
            "termination_grace_seconds": 10, "wait_timeout_seconds": 0,
            "transport_timeout_seconds": 45,
        },
        "resource_policy": {
            "memory_maximum_bytes": 8 * 1024**3,
            "thread_count_maximum": 32, "cpu_weight": 100,
            "disk_reservation_bytes": 1024**3,
        },
    }
    for name, val in changes.items():
        record[name] = val
    return record


def observe(root, w, monkeypatch, *, observed=None, timestamp=1000):
    result = observed if observed is not None else facts(w)
    calls = []
    class FakeHost:
        def __init__(self, config):
            assert config["workspace_id"] == w["workspace_id"]
            assert config["instance_id"] == COMPILER
        def command(self, script):
            calls.append(script)
            assert "os.O_NOFOLLOW" in script
            assert fonts.REMOTE_CONFIG in script
            assert "os.lstat(socket)" in script
            return json.dumps(result)
    monkeypatch.setattr(runner, "Host", FakeHost)
    recorded = fonts.verify(root, now=timestamp)
    assert recorded["verified_facts_sha256"] == fonts._digest(result)
    assert len(calls) == 1
    return recorded


def test_profile_fixes_original_source_pin_and_companion_revision():
    p = fonts.profile()
    assert p["schema"] == "host-deploy-first-fonts-managed-lane-v2"
    assert p["lane"] == "gateway-first-fonts-runtime"
    assert p["project_root"] == "/var/lib/zog/image-build-lanes/gateway-first-fonts-runtime"
    assert p["source_revision"] == lanes.FIRST_FONTS_PRODUCER_REVISION
    assert p["source_revision"] == "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert p["monthly_pin_repository_path"] == "project/pins/2026-10-01/commit-pin.py"
    assert p["monthly_pin_identity"] == "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert p["build_record_revision"] == lanes.expected_build_record_revision(p["source_revision"])
    assert p["build_record_revision"] == "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
    # No historical Fonts-specific work/external/worker-deadline prerequisite.
    # Generic lane resource_policy is still validated separately by lane schema.
    assert set(p) == {
        "schema", "lane", "project_root", "source_repository", "source_revision",
        "monthly_pin_repository_path", "monthly_pin_identity",
        "build_record_revision", "remote_configuration",
    }


def test_fonts_profile_uses_generic_lane_disk_and_controller_settings_without_special_envelope(tmp_path):
    root, w = workspace(tmp_path)
    host = json.loads((root / "host.json").read_text())
    candidate = facts(w)
    candidate["resource_policy"]["disk_reservation_bytes"] = 128 * 1024**2
    candidate["controller"]["execution_timeout_seconds"] = 2700
    approved = fonts.validate_remote_facts(candidate, w, host)
    spec = fonts._spec(approved)
    assert lanes.validate(spec) == spec
    assert spec["resource_policy"]["disk_reservation_bytes"] == 128 * 1024**2
    assert spec["controller"]["execution_timeout_seconds"] == 2700
    assert "worker_resource_gate" not in fonts.profile()


def test_missing_unverified_and_stale_host_facts_fail_closed(tmp_path, monkeypatch):
    root, w = workspace(tmp_path)
    with pytest.raises(RuntimeError, match="regular, nonsymlinked"):
        fonts.prepare(root, now=1000)
    observe(root, w, monkeypatch)
    with pytest.raises(RuntimeError, match="stale"):
        fonts.prepare(root, now=5000)
    assert not (root / "image-build-lanes").exists()


@pytest.mark.parametrize("change", [
    {"instance_id": "i-fffffffffffffffff"},
    {"account_id": "000000000000"},
    {"workspace_id": "0"*32},
    {"schema": "unreviewed-v2"},
    {"provenance_host_id": "bad\nidentity"},
    {"provenance_project_id": ""},
    {"python_executable": "python3"},
    {"observed_state_dir": "relative/path"},
    {"controller": {}},
    {"resource_policy": {}},
    {"source_revision": "f"*40},
])
def test_unverified_mismatched_or_overridden_facts_are_rejected(tmp_path, monkeypatch, change):
    root, w = workspace(tmp_path)
    class FakeHost:
        def __init__(self, config):
            pass
        def command(self, script):
            return json.dumps(facts(w, **change))
    monkeypatch.setattr(runner, "Host", FakeHost)
    with pytest.raises((RuntimeError, ValueError)):
        fonts.verify(root, now=1000)
    assert not (root / fonts.FACTS_FILE).exists()


def test_prepare_only_writes_owning_workspace_and_is_idempotent(tmp_path, monkeypatch):
    root, w = workspace(tmp_path)
    observe(root, w, monkeypatch)
    def no_host(*args, **kwargs):
        raise AssertionError("preparation must not instantiate Host or contact AWS/SSM")
    monkeypatch.setattr(runner, "Host", no_host)
    import zog.host_deploy.image_build_lanes as lane_module
    monkeypatch.setattr(lane_module, "Host", no_host)
    before_files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    record = fonts.prepare(root, now=1010)
    after_files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    created = set(after_files) - set(before_files)
    assert created == {"image-build-lanes/gateway-first-fonts-runtime.json"}
    assert record["state"] == "prepared"
    assert record["schema"] == 4
    assert record["specification"]["mode"] == "managed"
    assert record["specification"]["resource_policy"]["memory_maximum_bytes"] == 8*1024**3
    assert record["fonts_lane_profile"]["specification_sha256"] == lanes.specification_sha256(record["specification"])
    path = root / "image-build-lanes" / (fonts.LANE + ".json")
    bytes_before = path.read_bytes()
    assert fonts.prepare(root, now=1011) == record
    assert path.read_bytes() == bytes_before
    with pytest.raises(ValueError, match="source-owned"):
        lanes.prepare(root, record["specification"])


def test_full_digest_is_stable_and_changes_for_any_bound_identity_or_controller(tmp_path):
    root, w = workspace(tmp_path)
    host = json.loads((root / "host.json").read_text())
    original = fonts.validate_remote_facts(facts(w), w, host)
    expected = lanes.specification_sha256(fonts._spec(original))
    assert lanes.specification_sha256(fonts._spec(original)) == expected
    for name, update in (
        ("provenance_host_id", {"provenance_host_id": "new-host"}),
        ("provenance_project_id", {"provenance_project_id": "different-project"}),
        ("observed_state_dir", {"observed_state_dir": "/srv/observed"}),
        ("python_executable", {"python_executable": "/usr/bin/python3.13"}),
        ("memory", {"resource_policy": {**original["resource_policy"], "memory_maximum_bytes": 3*1024**3}}),
        ("controller", {"controller": {**original["controller"], "execution_user_id": 24001}}),
        ("socket", {"controller": {**original["controller"], "socket_path": "/run/zog/another.sock"}}),
    ):
        changed = fonts.validate_remote_facts({**original, **update}, w, host)
        assert lanes.specification_sha256(fonts._spec(changed)) != expected, name


def other_spec(name="existing", **overrides):
    p = lanes.specification(
        name, mode="reservation", source_repository="zog144/image-build",
        source_revision="a"*40,
        monthly_pin_repository_path="project/pins/commit-pin.py",
        monthly_pin_identity="sha256:"+"c"*64,
        provenance_host_id="host-fixture", provenance_project_id="project-existing",
        project_root="/srv/existing", memory_maximum_bytes=100,
        thread_count_maximum=1, cpu_weight=100, disk_reservation_bytes=100,
        execution_user_id=1001, execution_group_id=1001,
    )
    return {**p, **overrides}


@pytest.mark.parametrize("conflict", [
    "project-id", "project-root", "lane-name", "active-matching-producer", "corrupt-history"
])
def test_every_retained_lane_is_checked_and_conflicts_hold(tmp_path, monkeypatch, conflict):
    root, w = workspace(tmp_path)
    observe(root, w, monkeypatch)
    if conflict == "project-id":
        old = other_spec(provenance_project_id="first-fonts-project")
    elif conflict == "project-root":
        old = other_spec(project_root=fonts.PROJECT_ROOT)
    elif conflict == "lane-name":
        old = other_spec(fonts.LANE)
    elif conflict == "active-matching-producer":
        old = other_spec("matching", mode="managed", source_repository=fonts.profile()["source_repository"],
                         source_revision=fonts.profile()["source_revision"],
                         monthly_pin_repository_path=fonts.profile()["monthly_pin_repository_path"],
                         monthly_pin_identity=fonts.profile()["monthly_pin_identity"],
                         project_root="/var/lib/zog/image-build-lanes/matching",
                         observed_state_dir=None, python_executable="/usr/bin/python3.12",schema=4)
    else:
        old = other_spec()
    path = root / "image-build-lanes" / (old["lane"] + ".json")
    status = "active" if conflict == "active-matching-producer" else "retired"
    value = {"schema": old["schema"], "lane": old["lane"], "specification": old, "state": status}
    save(path, value)
    if conflict == "corrupt-history":
        path.write_text("not JSON")
    before = path.read_bytes()
    with pytest.raises((ValueError, RuntimeError, fonts_lane_review.FontsLaneHeld)):
        fonts.prepare(root, now=1010)
    assert path.read_bytes() == before
    assert not (root / "image-build-lanes" / (fonts.LANE + ".json")).exists() or conflict == "lane-name"


def test_changed_verified_facts_cannot_rebind_prepared_lane(tmp_path, monkeypatch):
    root, w = workspace(tmp_path)
    observe(root, w, monkeypatch)
    previous = fonts.prepare(root, now=1010)
    observe(root, w, monkeypatch, observed=facts(w, project_id="another-project"), timestamp=1020)
    with pytest.raises(RuntimeError, match="differs"):
        fonts.prepare(root, now=1025)
    assert lanes.inspect(root, fonts.LANE) == previous


def test_activation_requires_matching_digest_and_selected_owner_host(tmp_path, monkeypatch):
    root, w = workspace(tmp_path)
    observe(root, w, monkeypatch, timestamp=1000)
    prepared = fonts.prepare(root, now=1010)
    monkeypatch.setattr(fonts.time, "time", lambda: 1100)
    monkeypatch.setattr(lanes, "runtime_preflight", lambda *args, **kwargs: {})
    monkeypatch.setattr(lanes, "_capacity", lambda *args, **kwargs: {"disk_free_bytes": 100*1024**3})
    calls = []
    class FakeHost:
        def __init__(self, config):
            assert config["instance_id"] == COMPILER
            calls.append(("host", config["instance_id"]))
        def command(self, command, **kwargs):
            calls.append(("command", command))
            return ""
        def upload(self, payload, path):
            calls.append(("upload", path))
    monkeypatch.setattr(lanes, "Host", FakeHost)
    with pytest.raises(RuntimeError, match="digest/Host"):
        lanes.activate(root, fonts.LANE, expected_specification_sha256="sha256:"+"0"*64)
    with pytest.raises(RuntimeError, match="explicit digest"):
        lanes.activate(root, fonts.LANE)
    assert calls == []
    digest = prepared["fonts_lane_profile"]["specification_sha256"]
    active = lanes.activate(root, fonts.LANE, expected_specification_sha256=digest)
    assert active["state"] == "active"
    assert active["specification"] == prepared["specification"]
    assert calls[0] == ("host", COMPILER)
    assert any(op == "command" and "install -d" in value for op, value in calls)
    assert any(op == "upload" and value.endswith("controller.json") for op, value in calls)


def test_activation_rejects_stale_facts_before_host_contact(tmp_path, monkeypatch):
    root, w = workspace(tmp_path)
    observe(root, w, monkeypatch, timestamp=1000)
    prepared = fonts.prepare(root, now=1010)
    monkeypatch.setattr(fonts.time, "time", lambda: 6000)
    def no_host(*args):
        raise AssertionError("no Host contact before digest and freshness validation")
    monkeypatch.setattr(lanes, "Host", no_host)
    with pytest.raises(RuntimeError, match="stale"):
        lanes.activate(root, fonts.LANE,
                       expected_specification_sha256=prepared["fonts_lane_profile"]["specification_sha256"])
    assert lanes.inspect(root, fonts.LANE)["state"] == "prepared"


def test_command_dispatch_is_profile_owned(tmp_path, monkeypatch, capsys):
    import sys
    from zog.host_deploy.cli import main
    root, w = workspace(tmp_path)
    monkeypatch.setattr(sys, "argv", ["host-deploy", "fonts-lane-profile"])
    main()
    assert json.loads(capsys.readouterr().out)["lane"] == fonts.LANE
    observe(root, w, monkeypatch, timestamp=int(fonts.time.time()))
    monkeypatch.setattr(sys, "argv", [
        "host-deploy", "fonts-lane-prepare", "--workspace", str(root),
    ])
    main()
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "prepared"
    assert result["fonts_lane_profile"]["profile_sha256"] == fonts._digest(fonts.profile())
    assert result["fonts_lane_profile"]["build_record_revision"] == fonts.COMPANION_REVISION
    assert result == lanes.inspect(root, fonts.LANE)
    # The dedicated CLI does not accept generic --spec / UID / source overrides.
    monkeypatch.setattr(sys, "argv", [
        "host-deploy", "fonts-lane-prepare", "--workspace", str(root),
        "--spec", "/tmp/unreviewed.json",
    ])
    with pytest.raises(SystemExit):
        main()
