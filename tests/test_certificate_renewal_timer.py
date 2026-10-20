"""Unit-level timer binding checks; never executes Certbot or systemd."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import time

import pytest

from zog.host_deploy import certificate_renewal as core
from zog.host_deploy import certificate_renewal_timer as timer


class Controller:
    def __init__(self):
        self.count = 0
        self.queued = []
        self.results = {}
        self.evaluations = 0
    def evaluate(self):
        self.evaluations += 1
        return SimpleNamespace(ok=True)
    def issue_application_request_id(self):
        self.count += 1
        return "REQ" + str(self.count) + "VALID"
    def request_application_launch(self, app, *, program_name, request_id):
        self.queued.append((app, program_name, request_id))
    def application_request_result(self, rid):
        return self.results.get(rid)


def policy(tmp_path):
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    return {
        "schema": timer.SCHEMA,
        "application": "certify-manage", "program": "renew",
        "certificate_id": "station-web", "policy_sha256": "a"*64,
        "project_root": str(tmp_path / "project"),
        "generation": "b"*64, "controller_user": "cert-owner",
        "issuer_user": "cert-owner",
        "root_control_socket": "/run/zog-station-production/control.sock",
        "python_executable": "/usr/bin/python3.12",
        "journal_directory": str(journal),
        "issuer_policy_file": str(tmp_path / "issuer-policy.json"),
        "issuer_state": str(tmp_path / "issuer-state"),
        "renew_when_days_remaining": 30,
        "minimum_interval_hours": 24,
        "evaluate_queued_request": True,
        "publication_policy_file": None,
        "issuer_observer_policy_file": None,
        "controller_backend": "local",
        "issuer_lifecycle_socket": None,
        "issuer_inspection_policy_file": None,
    }


def issuer(days=10, *, operation="renew", outcome="unchanged", completed=None):
    finished = completed or datetime.now(timezone.utc) + timedelta(seconds=3)
    return (SimpleNamespace(
        health="valid", detail=None, days_remaining=days,
        fingerprint_sha256="e"*64
    ), {
        "operation": operation,
        "outcome": outcome,
    }, finished)


def test_timer_authorizes_one_exact_renewal_and_requires_fresh_issuer_evidence(tmp_path):
    config = policy(tmp_path)
    ctrl = Controller()
    now = datetime.now(timezone.utc)
    result = timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(10))
    assert result["phase"] == "submitted"
    assert ctrl.count == 1
    assert ctrl.queued == [("certify-manage", "renew", result["request_id"])]
    assert ctrl.evaluations == 1

    rid = result["request_id"]
    ctrl.results[rid] = SimpleNamespace(
        request_id=rid, operation="launch", program_name="renew",
        application="certify-manage", status="satisfied",
        updated_at=time.time() + 20,
    )
    second = timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(10))
    assert second["phase"] == "verified"
    assert second["outcome"] == "unchanged"
    assert ctrl.count == 1
    again = timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(10))
    assert again["phase"] == "verified"
    assert ctrl.count == 1  # minimum-interval guard is in the durable coordinator


def test_not_due_and_untrusted_issuer_block_new_request(tmp_path):
    config = policy(tmp_path)
    ctrl = Controller()
    not_due = timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(45))
    assert not_due["phase"] == "idle"
    assert ctrl.count == 0
    def uncertain(_):
        raise core.RenewalBlocked("issuer-uncertain")
    with pytest.raises(core.RenewalBlocked, match="issuer-readiness-unproven"):
        timer.run(config, controller=ctrl, issuer_checker=uncertain)
    assert ctrl.count == 0


def test_untrusted_policy_or_privilege_scope_rejected(tmp_path):
    config = policy(tmp_path)
    for changed in (
        {"program": "issue"},
        {"application": "other"},
        {"issuer_user": "other-account"},
        {"root_control_socket": "/run/zog/root-control.sock"},
        {"renew_when_days_remaining": 0},
        {"minimum_interval_hours": 1},
        {"evaluate_queued_request": False},
        {"python_executable": "/usr/bin/python3.13"},
        {"publication_policy_file": "/tmp/../bad"},
        {"python_executable": "/usr/bin/python3.13"},
        {"unknown_override": "arbitrary"},
    ):
        with pytest.raises(core.RenewalBlocked):
            timer.validate_policy({**config, **changed})


def test_verified_issuer_completion_must_follow_retained_request(tmp_path):
    config = policy(tmp_path)
    ctrl = Controller()
    timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(10))
    rid = ctrl.queued[0][2]
    ctrl.results[rid] = SimpleNamespace(
        request_id=rid, operation="launch", status="satisfied",
        application="certify-manage", program_name="renew",
        updated_at=time.time()+10
    )
    stale = datetime.now(timezone.utc) - timedelta(hours=2)
    with pytest.raises(core.RenewalBlocked, match="issuer-result-not-fresh"):
        timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(
            10, completed=stale
        ))
    assert ctrl.count == 1
    assert core._binding(config["policy_sha256"], config["certificate_id"])


def test_timer_template_is_disabled_by_default_and_readonly_bound():
    source = Path(__file__).resolve().parents[1] / "src/zog/host_deploy"
    service = (source / "certificate-renewal@.service").read_text()
    timer_unit = (source / "certificate-renewal@.timer").read_text()
    assert "User=%i" in service
    assert "--policy /etc/zog/certificate-renewal-%i.json" in service
    assert "TimeoutStartSec=300s" in service
    assert "OnCalendar=hourly" in timer_unit
    assert "Unit=certificate-renewal@%i.service" in timer_unit
    assert "WantedBy=timers.target" in timer_unit


def test_issuer_observer_uses_public_inspect_fields_not_private_record(tmp_path, monkeypatch):
    """The observer consumes only the producer's redacted inspection contract."""
    import sys
    import types
    config = policy(tmp_path)
    auth = SimpleNamespace(
        certificate_id=config["certificate_id"],
        fingerprint=config["policy_sha256"],
        hostnames=("station.example.org",),
    )
    certificate = SimpleNamespace(
        certificate_id=config["certificate_id"],
        hostnames=auth.hostnames,
        health="valid", detail=None, days_remaining=10,
        fingerprint_sha256="e"*64, operation="renew",
        outcome="unchanged", policy_sha256=config["policy_sha256"],
        operation_updated_at=datetime.now(timezone.utc).isoformat(),
    )
    package = types.ModuleType("zog.certify_manage")
    package.__path__ = []
    manager = types.ModuleType("zog.certify_manage.manager")
    model = types.ModuleType("zog.certify_manage.model")
    security = types.ModuleType("zog.certify_manage.security")

    class FakeManager:
        def __init__(self, *args):
            pass
        def inspect(self):
            return certificate
        def _read(self):
            raise AssertionError("consumer must not read issuer private journal")

    class FakeAuthorization:
        @staticmethod
        def from_dict(value):
            return auth

    manager.CertificateManager = FakeManager
    model.Authorization = FakeAuthorization
    security.trusted_policy = lambda path: b'{"schema":"test"}'
    for name, module in (
        ("zog.certify_manage", package),
        ("zog.certify_manage.manager", manager),
        ("zog.certify_manage.model", model),
        ("zog.certify_manage.security", security),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    assert timer._issuer_verification(config)[1]["outcome"] == "unchanged"
    certificate.policy_sha256 = "f"*64
    with pytest.raises(core.RenewalBlocked, match="issuer-readiness-unproven"):
        timer._issuer_verification(config)


def test_evaluation_is_bounded_and_keeps_retained_request(tmp_path):
    config = policy(tmp_path)
    ctrl = Controller()
    ctrl.evaluate = lambda: SimpleNamespace(ok=False, errors=["blocked"])
    with pytest.raises(core.RenewalBlocked, match="controller-evaluation-failed"):
        timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(9))
    saved = json.loads((Path(config["journal_directory"]) / "renewal.json").read_text())
    assert saved["phase"] == "submitted"
    assert ctrl.count == 1
    with pytest.raises(core.RenewalBlocked, match="controller-evaluation-failed"):
        timer.run(config, controller=ctrl, issuer_checker=lambda _: issuer(9))
    assert ctrl.count == 1


def test_authenticated_observer_is_bound_to_same_controller_id_before_local_proof(tmp_path):
    config = policy(tmp_path)
    config["issuer_observer_policy_file"] = "/etc/zog/issuer-observer-policy.json"
    controller = Controller()
    from zog.host_deploy.certificate_renewal import _locked, _load, _binding
    requests = []
    expected = datetime.now(timezone.utc)
    def trusted(policy, *, request_id, started, controller_result):
        assert controller_result.request_id == request_id
        assert controller_result.program_name == "renew"
        assert started.tzinfo is not None
        requests.append(request_id)
        return {
            "schema": "zog-trusted-issuer-observation-v1",
            "status": "journal-ready", "request_id": request_id,
            "certificate_id": "station-web", "policy_sha256": "a"*64,
            "certificate_fingerprint_sha256": "e"*64,
            "outcome": "unchanged",
            "journal_updated_at": (datetime.now(timezone.utc)).isoformat(),
            "tls_ready": False,
        }
    timer.run(config, controller=controller, issuer_checker=lambda _: issuer(10),
              issuer_observer=trusted)
    rid = controller.queued[0][2]
    controller.results[rid] = SimpleNamespace(
        request_id=rid, operation="launch", program_name="renew",
        application="certify-manage", status="satisfied", runtime_id="RUNTIME1",
        updated_at=time.time() + 15,
    )
    answer = timer.run(config, controller=controller,
                       issuer_checker=lambda _: issuer(10),
                       issuer_observer=trusted)
    assert answer["phase"] == "verified"
    assert requests == [rid]
    assert controller.count == 1


def test_incomplete_authenticated_observer_does_not_promote_controller_success(tmp_path):
    config = policy(tmp_path)
    config["issuer_observer_policy_file"] = "/etc/zog/issuer-observer-policy.json"
    controller = Controller()
    timer.run(config, controller=controller, issuer_checker=lambda _: issuer(10))
    rid = controller.queued[0][2]
    controller.results[rid] = SimpleNamespace(
        request_id=rid, operation="launch", program_name="renew",
        application="certify-manage", status="satisfied", runtime_id="RUNTIME1",
        updated_at=time.time() + 15,
    )
    def waiting(*args, **kwargs):
        return {"status": "ongoing", "tls_ready": False}
    outcome = timer.run(config, controller=controller,
                        issuer_checker=lambda _: issuer(10), issuer_observer=waiting)
    assert outcome["phase"] == "awaiting-issuer"
    assert controller.count == 1


def test_selected_lifecycle_policy_forbids_generic_evaluator_and_requires_observer(tmp_path):
    cfg = policy(tmp_path)
    cfg.update(
        controller_backend="selected-broker",
        issuer_lifecycle_socket="/run/zog/issuer-lifecycle.sock",
        issuer_inspection_policy_file="/etc/zog/issuer-inspection.json",
        issuer_observer_policy_file="/etc/zog/issuer-observer.json",
        issuer_user="other-issuer",
        root_control_socket=None,
        evaluate_queued_request=False,
    )
    assert timer.validate_policy(cfg) == cfg
    for change in (
        {"evaluate_queued_request": True},
        {"issuer_lifecycle_socket": None},
        {"root_control_socket": "/run/zog-station-production/control.sock"},
        {"issuer_observer_policy_file": None},
        {"issuer_inspection_policy_file": None},
        {"issuer_lifecycle_socket": "/tmp/../untrusted"},
    ):
        with pytest.raises(core.RenewalBlocked):
            timer.validate_policy({**cfg, **change})


def test_selected_broker_committed_result_uses_authenticated_journal_time(tmp_path):
    config = policy(tmp_path)
    config.update(
        controller_backend="selected-broker",
        issuer_lifecycle_socket="/run/zog/issuer-lifecycle.sock",
        issuer_inspection_policy_file="/etc/zog/issuer-inspection.json",
        issuer_observer_policy_file="/etc/zog/issuer-observer.json",
        issuer_user="other-issuer",
        root_control_socket=None,
        evaluate_queued_request=False,
    )
    controller = Controller()
    controller.direct_selected_launch = True
    # The selected broker MUST NOT expose generic project evaluation.
    controller.evaluate = lambda: pytest.fail("selected broker has no generic evaluate")
    first = timer.run(config, controller=controller, issuer_checker=lambda _: issuer(10))
    request_id = first["request_id"]
    assert first["phase"] == "submitted"
    controller.results[request_id] = SimpleNamespace(
        request_id=request_id, application="certify-manage",
        program_name="renew", operation="launch", status="satisfied",
        runtime_id="RUNTIME1", updated_at=None
    )
    shared_completion = datetime.now(timezone.utc)
    def accepted(policy, *, request_id, started, controller_result):
        return {
            "schema": "zog-trusted-issuer-observation-v1",
            "status": "journal-ready", "request_id": request_id,
            "certificate_id": "station-web", "policy_sha256": "a"*64,
            "host_policy_digest": "sha256:" + "d"*64,
            "certificate_fingerprint_sha256": "e"*64, "outcome": "unchanged",
            "journal_updated_at": shared_completion.isoformat(),
            "tls_ready": False,
        }
    result = timer.run(config, controller=controller,
                       issuer_checker=lambda _: issuer(10, completed=shared_completion),
                       issuer_observer=accepted)
    assert result["phase"] == "verified"
    assert controller.count == 1


def test_unreviewed_long_running_inspector_blocks_native_selected_broker(tmp_path):
    local_cfg = policy(tmp_path)
    cfg = dict(local_cfg)
    cfg.update(
        controller_backend="selected-broker",
        issuer_lifecycle_socket="/run/zog/issuer-lifecycle.sock",
        issuer_inspection_policy_file="/etc/zog/issuer-inspection.json",
        issuer_observer_policy_file="/etc/zog/issuer-observer.json",
        issuer_user="other-issuer",
        root_control_socket=None,
        evaluate_queued_request=False,
    )
    with pytest.raises(core.RenewalBlocked, match="selected-inspection-runtime-not-approved"):
        timer._require_approved_native_inspection(timer.validate_policy(cfg))
    timer._require_approved_native_inspection(timer.validate_policy(local_cfg))
