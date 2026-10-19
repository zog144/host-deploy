import copy
import hashlib
import hmac
import os
import socket
import sys
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_deploy import station_production as p


def manifest(tmp_path):
    home = tmp_path / "controller-home"
    root = home / "project"
    mounts = [root / "state" / "station", root / "state" / "archive"]
    specification_digests = {}
    for name in p.PROGRAMS:
        directory = root / "application" / name
        directory.mkdir(parents=True, exist_ok=True)
        source = directory / "application.py"
        source.write_text("# reviewed " + name + " spec\\n")
        specification_digests[name] = "sha256:" + hashlib.sha256(
            source.read_bytes()
        ).hexdigest()
    return {
        "schema": p.SCHEMA,
        "project": {
            "root": str(root), "home": str(home),
            "service_user": "zogcontroller",
            "controller": "box-control/RootControlSystemdTransport",
        },
        "sources": {name: chr(97 + i)*40 for i, name in enumerate(p.REPOSITORIES)},
        "image": {"rootfs": "sha256:" + "a"*64, "generation": "gen-20261013"},
        "applications": {
            name: {
                "specification_sha256": specification_digests[name],
                "software_view": "sha256:" + chr(100 + i)*64,
                "storage_id": chr(97 + i)*32,
                "grant": {
                    "grant_id": chr(99 + i)*32,
                    "grant_version": 1, "uid": 1001 + i, "gid": 1101 + i,
                },
                "mount": {
                    "path": str(mounts[i]), "device": 110 + i, "inode": 220 + i,
                },
                "preparation_revision": "prod-migration-v2",
            }
            for i, name in enumerate(p.PROGRAMS)
        },
        "host_bindings": {
            "policy_sha256": "sha256:" + "e"*64,
            "mirror_live": "/run/zog-host/mirror-live",
        },
        "compiler_rpc": {
            "config_directory": "/var/lib/station-access/compiler-rpc",
            "workspace_id": "f"*32, "ownership_epoch": "9"*32,
            "scopes": ["compiler.status", "dispatch.status"],
        },
        "services": {
            "station": "boot-independent",
            "archive": "host-discover-lease-selected",
            "root_control": "systemd", "box_control": "controller-requests",
        },
    }


def test_manifest_is_exact_and_immutable(tmp_path):
    value = manifest(tmp_path)
    assert p.validate_manifest(value) == value
    digest = p.manifest_digest(value)
    assert digest.startswith("sha256:")
    for mutate in [
        lambda m: m["sources"].update({"image-build": "unstable"}),
        lambda m: m["project"].update({"service_user": "root"}),
        lambda m: m["project"].update({"home": "/root"}),
        lambda m: m["services"].update({"archive": "boot-independent"}),
        lambda m: m["compiler_rpc"].update({"scopes": ["dispatch.submit"]}),
        lambda m: m["applications"]["archive-mirror"]["grant"].update({"uid": 1001}),
        lambda m: m["applications"]["archive-mirror"]["mount"].update({"inode": 0}),
        lambda m: m["applications"]["archive-mirror"]["mount"].update(
            {"path": m["project"]["home"]}
        ),
        lambda m: m["host_bindings"].update({"mirror_live": "/var/lib/host-discover/credentials"}),
        lambda m: m.update({"rootfs_override": "/tmp/anything"}),
    ]:
        wrong = copy.deepcopy(value)
        mutate(wrong)
        with pytest.raises(ValueError):
            p.validate_manifest(wrong)


def test_durable_preparation_is_idempotent_and_conflict_fails_closed(tmp_path):
    value = manifest(tmp_path)
    directory = tmp_path / "state"
    directory.mkdir()
    first = p.prepare(directory, value)
    assert first == p.prepare(directory, value)
    assert p.plan(directory)["state"] == "prepared-not-launched"
    assert p.plan(directory)["safe_to_cut_over"] is False
    tampered = copy.deepcopy(value)
    tampered["sources"]["station-access"] = "f"*40
    with pytest.raises(p.ProductionBlocked, match="deployment-identity-conflict"):
        p.prepare(directory, tampered)
    assert p.load(directory) == first
    retained = directory / "station-production.json"
    retained.write_text("{")
    with pytest.raises(p.ProductionBlocked, match="retained-state-invalid"):
        p.prepare(directory, value)


def test_missing_and_symlinked_record_fail_closed(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir()
    with pytest.raises(p.ProductionBlocked, match="deployment-not-prepared"):
        p.load(directory)
    destination = tmp_path / "external"
    destination.write_text("{}")
    (directory / "station-production.json").symlink_to(destination)
    with pytest.raises(p.ProductionBlocked, match="retained-state-unsafe"):
        p.prepare(directory, manifest(tmp_path))


class FakeController:
    def __init__(self, value):
        self.value = value
        self.project = SimpleNamespace(path=Path(value["project"]["root"]))
        self.issued = []
        self.requests = []
        self.results = {}

    def application_preparation(self, name):
        app = self.value["applications"][name]
        return {
            "state": "ready", "storage_id": app["storage_id"],
            "revision": app["preparation_revision"],
            "generation": self.value["image"]["generation"],
            "definition": {
                "name": name, "software_view": app["software_view"],
                "execution_binding": {
                    "schema": "zog-execution-identity-v1",
                    "project": self.value["project"]["root"],
                    "application": name,
                    "grant_id": app["grant"]["grant_id"],
                    "version": app["grant"]["grant_version"],
                    "uid": app["grant"]["uid"],
                    "gid": app["grant"]["gid"],
                },
            },
        }

    def issue_application_request_id(self):
        serial = len(self.issued) + 1
        body = "r1-" + format(1760000000000 + serial, "x") + "-" + format(serial, "032x")
        digest = hmac.new(bytes.fromhex("b" * 64), body.encode(), hashlib.sha256).hexdigest()
        ident = body + "-" + digest
        self.issued.append(ident)
        return ident

    def application_request_result(self, ident):
        return self.results.get(ident)

    def request_application_launch(self, name, *, request_id):
        self.requests.append((name, request_id))
        return {"request_id": request_id}


def mount_stat(value):
    lookup = {
        app["mount"]["path"]: SimpleNamespace(
            st_dev=app["mount"]["device"], st_ino=app["mount"]["inode"]
        )
        for app in value["applications"].values()
    }
    return lambda path, **kwargs: lookup[str(path)]


def test_station_boot_requests_only_station_with_durable_identity(tmp_path):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, value)
    ctrl = FakeController(value)
    first_boot = "00000000-0000-0000-0000-000000000001"
    a = p.station_boot_request(
        folder, controller=ctrl, boot_id=first_boot, stat_fn=mount_stat(value)
    )
    assert a["state"] == "requested-not-serving"
    assert a["archive_action"] == "none"
    assert ctrl.requests == [("station-access", ctrl.issued[0])]
    ctrl.results[ctrl.issued[0]] = SimpleNamespace(status=SimpleNamespace(value="satisfied"))
    again = p.station_boot_request(
        folder, controller=ctrl, boot_id=first_boot, stat_fn=mount_stat(value)
    )
    assert a == again
    assert len(ctrl.requests) == 1
    reboot = p.station_boot_request(
        folder, controller=ctrl,
        boot_id="00000000-0000-0000-0000-000000000002",
        stat_fn=mount_stat(value),
    )
    assert reboot["request_id"] == ctrl.issued[1]
    assert ctrl.requests == [
        ("station-access", ctrl.issued[0]), ("station-access", ctrl.issued[1])
    ]
    assert json.loads((folder / "station-boot-request.json").read_text())[
        "previous_request_id"
    ] == ctrl.issued[0]


def test_interrupted_controller_reply_is_not_a_second_request(tmp_path):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, value)
    ctrl = FakeController(value)
    ctrl.request_application_launch = lambda *a, **kw: (_ for _ in ()).throw(
        TimeoutError("reply missing")
    )
    boot = "00000000-0000-0000-0000-000000000001"
    with pytest.raises(p.ProductionBlocked, match="controller-launch-uncertain"):
        p.station_boot_request(folder, controller=ctrl, boot_id=boot,
                               stat_fn=mount_stat(value))
    assert len(ctrl.issued) == 1
    with pytest.raises(p.ProductionBlocked, match="controller-launch-uncertain"):
        p.station_boot_request(folder, controller=ctrl, boot_id=boot,
                               stat_fn=mount_stat(value))
    assert ctrl.issued == [ctrl.issued[0]]
    with pytest.raises(p.ProductionBlocked, match="previous-boot-reconciliation-required"):
        p.station_boot_request(
            folder, controller=ctrl,
            boot_id="00000000-0000-0000-0000-000000000002",
            stat_fn=mount_stat(value),
        )


def test_missing_preparation_grant_and_mount_block_before_request(tmp_path):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, value)
    ctrl = FakeController(value)
    original = ctrl.application_preparation
    ctrl.application_preparation = lambda name: (
        {**original(name), "state": "uncertain"}
        if name == "station-access" else original(name)
    )
    with pytest.raises(p.ProductionBlocked, match="preparation-not-ready"):
        p.station_boot_request(
            folder, controller=ctrl,
            boot_id="00000000-0000-0000-0000-000000000001",
            stat_fn=mount_stat(value),
        )
    assert not ctrl.issued
    ctrl.application_preparation = original
    with pytest.raises(p.ProductionBlocked, match="mount-identity-mismatch"):
        p.station_boot_request(
            folder, controller=ctrl,
            boot_id="00000000-0000-0000-0000-000000000001",
            stat_fn=lambda path, **kw: SimpleNamespace(st_dev=123, st_ino=456),
        )
    assert not ctrl.issued


def test_cli_preparation_and_blocked_inspection(tmp_path, capsys):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    source = tmp_path / "manifest.json"
    source.write_text(json.dumps(value))
    assert p.main(["prepare", "--directory", str(folder), "--manifest", str(source)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "prepared"
    assert p.main(["inspect", "--directory", str(folder)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["safe_to_cut_over"] is False
    assert p.main(["inspect", "--directory", str(tmp_path / "missing")]) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "blocked"


def test_station_boot_is_independent_of_archive_role_preparation(tmp_path):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, value)
    ctrl = FakeController(value)
    original = ctrl.application_preparation
    ctrl.application_preparation = lambda name: (
        None if name == "archive-mirror" else original(name)
    )
    boot = p.station_boot_request(
        folder, controller=ctrl,
        boot_id="00000000-0000-0000-0000-000000000001",
        stat_fn=mount_stat(value),
    )
    assert boot["state"] == "requested-not-serving"
    assert ctrl.requests == [("station-access", ctrl.issued[0])]


def test_station_boot_blocks_modified_spec_and_software_binding(tmp_path):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, value)
    ctrl = FakeController(value)
    boot = "00000000-0000-0000-0000-000000000001"
    spec_path = Path(value["project"]["root"]) / "application/station-access/application.py"
    spec_path.write_text("modified after review")
    with pytest.raises(p.ProductionBlocked, match="application-specification-mismatch"):
        p.station_boot_request(folder, controller=ctrl, boot_id=boot,
                               stat_fn=mount_stat(value))
    assert not ctrl.issued
    spec_path.write_text("# reviewed station-access spec\\n")
    original = ctrl.application_preparation
    def wrong_software(name):
        result = original(name)
        if name == "station-access":
            result["definition"]["software_view"] = "sha256:" + "f"*64
        return result
    ctrl.application_preparation = wrong_software
    with pytest.raises(p.ProductionBlocked, match="immutable-software-selection-mismatch"):
        p.station_boot_request(folder, controller=ctrl, boot_id=boot,
                               stat_fn=mount_stat(value))
    assert not ctrl.issued


def test_preparation_gate_accepts_actual_controller_binding_on_both_applications(tmp_path):
    """The manifest alias grant_version must match the producer field version."""
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    record = p.prepare(folder, value)
    controller = FakeController(value)
    assert p.preparation_gate(record, controller)
    for name in p.PROGRAMS:
        binding = controller.application_preparation(name)["definition"]["execution_binding"]
        assert binding["schema"] == "zog-execution-identity-v1"
        assert binding["project"] == value["project"]["root"]
        assert binding["application"] == name
        assert binding["version"] == value["applications"][name]["grant"]["grant_version"]
        assert "grant_version" not in binding
    assert record["manifest"] == value
    assert record["manifest_sha256"] == p.manifest_digest(value)


@pytest.mark.parametrize("application", p.PROGRAMS)
@pytest.mark.parametrize(("key", "wrong"), [
    ("version", None),
    ("version", 0),
    ("version", 2),
    ("version", "1"),
    ("version", True),
    ("schema", None),
    ("schema", "zog-execution-identity-v2"),
    ("project", None),
    ("project", "/home/a-different-owner/other-project"),
    ("application", None),
    ("application", "other-application"),
    ("grant_id", None),
    ("grant_id", "f" * 32),
    ("uid", None),
    ("uid", 234567),
    ("gid", None),
    ("gid", 234567),
])
def test_preparation_gate_rejects_malformed_controller_identity(
    tmp_path, application, key, wrong
):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    record = p.prepare(folder, value)
    controller = FakeController(value)
    original = controller.application_preparation

    def defective(name):
        result = original(name)
        if name == application:
            binding = result["definition"]["execution_binding"]
            if wrong is None:
                binding.pop(key, None)
            else:
                binding[key] = wrong
        return result

    controller.application_preparation = defective
    with pytest.raises(p.ProductionBlocked, match="persistent-identity-mismatch"):
        p.preparation_gate(record, controller)
    assert p.load(folder) == record


def test_legacy_manifest_shaped_grant_is_not_accepted_as_controller_identity(tmp_path):
    """An operator-defined manifest shape cannot impersonate a controller grant."""
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    record = p.prepare(folder, value)
    controller = FakeController(value)
    controller.application_preparation = lambda name: {
        "state": "ready",
        "storage_id": value["applications"][name]["storage_id"],
        "revision": value["applications"][name]["preparation_revision"],
        "generation": value["image"]["generation"],
        "definition": {
            "name": name,
            "software_view": value["applications"][name]["software_view"],
            "execution_binding": dict(value["applications"][name]["grant"]),
        },
    }
    with pytest.raises(p.ProductionBlocked, match="persistent-identity-mismatch"):
        p.preparation_gate(record, controller)


def test_station_boot_rejects_mismatched_grant_before_request(tmp_path):
    value = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, value)
    controller = FakeController(value)
    original = controller.application_preparation

    def defective(name):
        result = original(name)
        if name == "station-access":
            result["definition"]["execution_binding"]["version"] = 2
        return result

    controller.application_preparation = defective
    with pytest.raises(p.ProductionBlocked, match="persistent-identity-mismatch"):
        p.station_boot_request(
            folder, controller=controller,
            boot_id="00000000-0000-0000-0000-000000000001",
            stat_fn=mount_stat(value),
        )
    assert controller.issued == []
    assert controller.requests == []
    assert not (folder / "station-boot-request.json").exists()


def test_real_controller_issued_token_round_trip_if_companion_installed(tmp_path):
    """Integration: request identity is produced and authenticated by box-control."""
    pytest.importorskip("zog.box_control")
    from zog.box_control.project import Project
    from zog.box_control.retention import Retention

    project = Project(tmp_path / "actual-controller")
    project.state_dir.mkdir(parents=True)
    project.application_request_dir.mkdir(parents=True)
    project.application_request_result_dir.mkdir(parents=True)
    identity = Retention(project).issue()
    Retention(project).validate(identity)
    assert len(identity) > 64
    assert p._controller_request_id(identity, newly_issued=True) == identity


@pytest.mark.parametrize("value", [
    "", "STATION1", "r1-missing-signature", "r1-xyz-" + "a"*32 + "-" + "b"*64,
    "r1-1-" + "a"*32 + "-" + "x"*64,
    "r1-1-" + "a"*32 + "-" + "b"*64 + "../payload",
    "r1-1-" + "a"*32 + "-" + "b"*64 + "a"*100,
    "bad\nnewline", "x"*201, None,
])
def test_invalid_new_controller_tokens_block_with_no_persisted_request(
    tmp_path, value
):
    configuration = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, configuration)
    controller = FakeController(configuration)
    controller.issue_application_request_id = lambda: value
    with pytest.raises(p.ProductionBlocked, match="controller-request-identity-invalid"):
        p.station_boot_request(
            folder, controller=controller,
            boot_id="00000000-0000-0000-0000-000000000001",
            stat_fn=mount_stat(configuration),
        )
    assert not (folder / "station-boot-request.json").exists()
    assert controller.requests == []


def test_journal_retains_issued_token_after_lost_reply_and_restart(tmp_path):
    configuration = manifest(tmp_path)
    directory = tmp_path / "state"
    directory.mkdir()
    p.prepare(directory, configuration)
    first = FakeController(configuration)
    token = first.issue_application_request_id()
    # Re-create a controller that issues the same identity for this test only.
    first.issue_application_request_id = lambda: token
    first.request_application_launch = lambda *args, **kw: (_ for _ in ()).throw(
        TimeoutError("SSM/reply lost after durable admission")
    )
    boot = "00000000-0000-0000-0000-000000000001"
    with pytest.raises(p.ProductionBlocked, match="controller-launch-uncertain"):
        p.station_boot_request(
            directory, controller=first, boot_id=boot, stat_fn=mount_stat(configuration)
        )
    retained = json.loads((directory / "station-boot-request.json").read_text())
    assert retained["request_id"] == token
    second = FakeController(configuration)
    second.results[token] = SimpleNamespace(status=SimpleNamespace(value="pending"))
    second.request_application_launch = lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("pending request must not be resubmitted")
    )
    # A pending result already exists; the controller is authoritative.
    outcome = p.station_boot_request(
        directory, controller=second, boot_id=boot, stat_fn=mount_stat(configuration)
    )
    assert outcome["request_id"] == token
    assert second.issued == []
    with pytest.raises(p.ProductionBlocked, match="previous-boot-reconciliation-required"):
        p.station_boot_request(
            directory, controller=second,
            boot_id="00000000-0000-0000-0000-000000000002",
            stat_fn=mount_stat(configuration),
        )
    assert json.loads((directory / "station-boot-request.json").read_text()) == retained


def test_retained_controller_journal_rejects_corrupt_or_unbounded_identity(tmp_path):
    configuration = manifest(tmp_path)
    directory = tmp_path / "state"
    directory.mkdir()
    p.prepare(directory, configuration)
    controller = FakeController(configuration)
    boot = "00000000-0000-0000-0000-000000000001"
    p.station_boot_request(
        directory, controller=controller, boot_id=boot, stat_fn=mount_stat(configuration)
    )
    journal = directory / "station-boot-request.json"
    snapshot = json.loads(journal.read_text())
    for bad in ("bad/../path", "x"*201, "", 42):
        corrupt = {**snapshot, "request_id": bad}
        journal.write_text(json.dumps(corrupt))
        with pytest.raises(p.ProductionBlocked, match="controller-request-identity-invalid"):
            p.station_boot_request(
                directory, controller=controller, boot_id=boot,
                stat_fn=mount_stat(configuration),
            )
        assert controller.requests == [("station-access", controller.issued[0])]
    journal.write_text(json.dumps(snapshot))


def test_exact_runtime_binding_requires_explicit_project_epoch_and_nondefault_socket(tmp_path):
    value = manifest(tmp_path)
    binding = {
        "schema": p.CONTROLLER_BINDING_SCHEMA,
        "project_root": value["project"]["root"],
        "service_user": value["project"]["service_user"],
        "generation": value["image"]["generation"],
        "manifest_sha256": p.manifest_digest(value),
        "root_control_socket": "/run/zog-station-production/control.sock",
        "python_executable": "/usr/bin/python3.12",
    }
    assert p.validate_controller_binding(binding, value) == binding
    for key, bad, reason in [
        ("project_root", "/root/other", "identity-mismatch"),
        ("generation", "other-image", "identity-mismatch"),
        ("manifest_sha256", "sha256:" + "f"*64, "identity-mismatch"),
        ("service_user", "root", "identity-mismatch"),
        ("root_control_socket", p.DEFAULT_ROOT_CONTROL_SOCKET, "default-prohibited"),
        ("python_executable", "/usr/bin/env", "python-not-absolute-approved"),
    ]:
        with pytest.raises(p.ProductionBlocked, match=reason):
            p.validate_controller_binding({**binding, key: bad}, value)
    with pytest.raises(ValueError, match="controller binding"):
        p.validate_controller_binding({**binding, "extra": "arbitrary"}, value)


def test_runtime_socket_validation_and_explicit_python_binding(tmp_path):
    path = tmp_path / "approved-control.sock"
    binding = {"root_control_socket": str(path),
               "python_executable": os.path.realpath(sys.executable)}
    with pytest.raises(p.ProductionBlocked, match="socket-unavailable"):
        p.verify_controller_runtime(binding)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        p.verify_controller_runtime(binding)
        wrong = {**binding, "python_executable": "/usr/bin/another-python"}
        with pytest.raises(p.ProductionBlocked, match="python-mismatch"):
            p.verify_controller_runtime(wrong)
    path.unlink()
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(p.ProductionBlocked, match="socket-unsafe"):
        p.verify_controller_runtime(binding)


def test_evaluator_checks_station_only_and_never_reports_portal_serving(tmp_path):
    configuration = manifest(tmp_path)
    folder = tmp_path / "state"
    folder.mkdir()
    p.prepare(folder, configuration)
    controller = FakeController(configuration)
    controller.evaluate = lambda: SimpleNamespace(ok=True)
    response = p.evaluate_station(
        folder, controller=controller, stat_fn=mount_stat(configuration)
    )
    assert response["state"] == "evaluated-not-serving"
    assert response["safe_to_cut_over"] is False
    assert response["archive_action"] == "none-by-host-deploy"
    controller.evaluate = lambda: SimpleNamespace(ok=False, errors=["example"])
    with pytest.raises(p.ProductionBlocked, match="controller-evaluation-failed"):
        p.evaluate_station(folder, controller=controller,
                           stat_fn=mount_stat(configuration))
    original = controller.application_preparation
    controller.application_preparation = lambda name: (
        None if name == "archive-mirror" else original(name)
    )
    controller.evaluate = lambda: SimpleNamespace(ok=True)
    assert p.evaluate_station(folder, controller=controller,
                              stat_fn=mount_stat(configuration))["state"] == "evaluated-not-serving"


def test_unit_files_bind_python_controller_root_and_bounded_evaluation():
    root = Path(__file__).resolve().parents[1] / "src/zog/host_deploy"
    boot = (root / "station-portal@.service").read_text()
    evaluator = (root / "station-evaluator@.service").read_text()
    timer = (root / "station-evaluator@.timer").read_text()
    for unit in (boot, evaluator):
        assert "User=%i" in unit
        assert "zog-station-production-root-control.service" in unit
        assert "--controller-binding ${ZOG_STATION_CONTROLLER_BINDING}" in unit
        assert "--directory ${ZOG_STATION_PLAN_DIRECTORY}" in unit
        assert "/usr/bin/python3.12 -B -m zog.host_deploy.station_production" in unit
        assert "TimeoutStartSec=90s" in unit
        assert "ProtectSystem=strict" in unit
        assert "archive-mirror" not in unit
    assert "boot-request" in boot
    assert "evaluate" in evaluator
    assert "OnUnitInactiveSec=1min" in timer
    assert "Unit=station-evaluator@%i.service" in timer


def test_explicit_controller_transport_and_pinned_image_provider_if_available(tmp_path):
    pytest.importorskip("zog.box_control")
    from zog.box_control.runtime.root_control import RootControlSystemdTransport
    value = manifest(tmp_path)
    binding = {
        "schema": p.CONTROLLER_BINDING_SCHEMA,
        "project_root": value["project"]["root"],
        "service_user": value["project"]["service_user"],
        "generation": value["image"]["generation"],
        "manifest_sha256": p.manifest_digest(value),
        "root_control_socket": str(tmp_path / "special-owner.sock"),
        "python_executable": "/usr/bin/python3.12",
    }
    ctl = p.build_controller(binding)
    assert ctl.project.path == Path(value["project"]["root"]).resolve()
    assert isinstance(ctl.systemd_transport, RootControlSystemdTransport)
    assert ctl.systemd_transport.socket_path == Path(binding["root_control_socket"])
    assert ctl.image_provider.__class__.__name__ == "PinnedPublishedImage"
