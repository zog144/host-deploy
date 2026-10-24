"""Issuer-UID X.509 inspection and request-bound journal cross-checks."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import time

import pytest
from zog.host_deploy.certificate_renewal import RenewalBlocked
from zog.host_deploy import certificate_issuer_inspection as inspection
from zog.host_deploy import certificate_renewal_timer as timer

NOW = datetime.now(timezone.utc)
FP = "e"*64


def policy():
    return {
        "schema": inspection.SCHEMA,
        "socket_path": "/run/zog/certify-inspect.sock",
        "issuer_uid": 24001, "caller_uid": 23001,
        "certificate_id": "station-web", "policy_sha256": "a"*64,
        "hostnames": ["candidate.example.org"],
    }


def evidence(*, changed=None):
    obj = {
        "schema": inspection.CERTIFICATE_SCHEMA, "nonce": "a"*32,
        "certificate_id": "station-web",
        "hostnames": ["candidate.example.org"],
        "policy_sha256": "a"*64, "health": "valid",
        "certificate_fingerprint_sha256": FP,
        "valid_from": (NOW-timedelta(days=3)).isoformat(),
        "expires_at": (NOW+timedelta(days=12)).isoformat(),
        "days_remaining": 12,
        "operation": "renew", "outcome": "unchanged",
        "operation_updated_at": NOW.isoformat(),
        "issuer_verified": True, "observed_at": datetime.now(timezone.utc).isoformat(),
        "tls_ready": False,
    }
    obj.update(changed or {})
    return obj


def inspect(monkeypatch, result=None, *, owner=23001):
    monkeypatch.setattr(inspection, "_caller_uid", lambda: owner)
    sockets = []
    class FakeClient:
        def __init__(self, socket_path, *, expected_issuer_uid):
            sockets.append((socket_path, expected_issuer_uid))
        def inspect(self):
            return evidence() if result is None else result
    answer = inspection.inspect_issuer(policy(), client_factory=FakeClient)
    return answer, sockets


def test_valid_independent_inspection_is_not_tls_readiness(monkeypatch):
    (status, operation, completed), sockets = inspect(monkeypatch)
    assert sockets == [("/run/zog/certify-inspect.sock", 24001)]
    assert status.health == "valid" and status.tls_ready is False
    assert status.fingerprint_sha256 == FP
    assert operation == {"operation": "renew", "outcome": "unchanged"}
    assert completed == NOW


@pytest.mark.parametrize("change", [
    {"certificate_id": "other"},
    {"hostnames": ["wrong.example.org"]},
    {"policy_sha256": "0"*64},
    {"health": "invalid"}, {"issuer_verified": False},
    {"outcome": "recovered-unverified"}, {"operation": "stage"},
    {"certificate_fingerprint_sha256": "x"*64},
    {"tls_ready": True}, {"days_remaining": -1},
    {"operation_updated_at": None},
    {"observed_at": (NOW-timedelta(hours=1)).isoformat()},
    {"expires_at": (NOW-timedelta(days=1)).isoformat()},
    {"valid_from": (NOW+timedelta(days=1)).isoformat()},
    {"extra": "private"}, {"issuer_verified": 1},
])
def test_fail_closed_on_wrong_scope_or_invalid_issuer_evidence(monkeypatch, change):
    with pytest.raises(RenewalBlocked):
        inspect(monkeypatch, evidence(changed=change))


def test_separate_peer_uid_required(monkeypatch):
    with pytest.raises(RenewalBlocked, match="inspection-caller-identity-mismatch"):
        inspect(monkeypatch, owner=24001)


def test_socket_error_never_falls_back_to_private_certbot_files(monkeypatch):
    monkeypatch.setattr(inspection, "_caller_uid", lambda: 23001)
    class Offline:
        def __init__(self, socket_path, *, expected_issuer_uid):
            pass
        def inspect(self):
            raise ConnectionError("sensitive guest path")
    with pytest.raises(RenewalBlocked, match="inspection-unavailable"):
        inspection.inspect_issuer(policy(), client_factory=Offline)


@pytest.mark.parametrize("change", [
    {"caller_uid": 0}, {"issuer_uid": 23001},
    {"socket_path": "/tmp/../redirect"},
    {"hostnames": ["candidate.example.org", "candidate.example.org"]},
    {"hostnames": ["-invalid.example.org"]},
    {"policy_sha256": "bad"}, {"unknown": "override"},
])
def test_root_scoped_inspector_policy_validation(change):
    with pytest.raises(RenewalBlocked, match="inspection-policy-invalid"):
        inspection.validate_policy({**policy(), **change})


def timer_policy(tmp_path):
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    return {
        "schema": timer.SCHEMA, "application": "certify-manage",
        "program": "renew", "certificate_id": "station-web",
        "policy_sha256": "a"*64, "project_root": str(tmp_path / "project"),
        "generation": "b"*64, "controller_user": "controller",
        "issuer_user": "certissuer", "root_control_socket": None,
        "python_executable": "/usr/bin/python3.12",
        "journal_directory": str(journal),
        "issuer_policy_file": str(tmp_path / "issuer-policy.json"),
        "issuer_state": str(tmp_path / "issuer-state"),
        "renew_when_days_remaining": 30,
        "minimum_interval_hours": 24,
        "evaluate_queued_request": False,
        "publication_policy_file": None,
        "issuer_observer_policy_file": "/etc/zog/issuer-observer.json",
        "issuer_inspection_policy_file": "/etc/zog/issuer-inspection.json",
        "controller_backend": "selected-broker",
        "issuer_lifecycle_socket": "/run/zog/issuer-lifecycle.sock",
    }


class Controller:
    direct_selected_launch = True
    def __init__(self):
        self.issued = 0
        self.results = {}
    def issue_application_request_id(self):
        self.issued += 1
        return "r1-1-" + format(self.issued, "032x") + "-" + "a"*64
    def application_request_result(self, ident):
        return self.results.get(ident)
    def request_application_launch(self, app, *, program_name, request_id):
        assert app == "certify-manage" and program_name == "renew"
    def evaluate(self):
        pytest.fail("selected broker must never allow generic controller evaluation")


def test_two_independent_proofs_required_before_verified_renewal(tmp_path, monkeypatch):
    ctrl = Controller()
    config = timer_policy(tmp_path)
    initial = datetime.now(timezone.utc) - timedelta(minutes=1)
    certificate = evidence(changed={
        "operation_updated_at": initial.isoformat(),
        "observed_at": datetime.now(timezone.utc).isoformat(),
    })
    def inspector(_):
        return inspect(monkeypatch, certificate)[0]
    output = timer.run(config, controller=ctrl, issuer_checker=inspector)
    assert output["phase"] == "submitted"
    rid = output["request_id"]
    ctrl.results[rid] = SimpleNamespace(
        request_id=rid, operation="launch", application="certify-manage",
        program_name="renew", status="satisfied", runtime_id="RUNTIME1",
        updated_at=None,
    )
    # Receipt from controller matches the locally inspected issuer journal
    # exactly after timezone normalization. But predating this request fails.
    def authenticated(policy, *, request_id, started, controller_result):
        return {
            "status": "journal-ready", "tls_ready": False,
            "request_id": request_id, "certificate_id": "station-web",
            "policy_sha256": "a"*64, "outcome": "unchanged",
            "host_policy_digest": "sha256:" + "d"*64,
            "certificate_fingerprint_sha256": FP,
            "journal_updated_at": certificate["operation_updated_at"],
        }
    with pytest.raises(RenewalBlocked, match="issuer-result-not-fresh"):
        timer.run(config, controller=ctrl, issuer_checker=inspector,
                  issuer_observer=authenticated)
    assert ctrl.issued == 1
    certificate["operation_updated_at"] = (
        datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    good = timer.run(config, controller=ctrl, issuer_checker=inspector,
                     issuer_observer=authenticated)
    assert good["phase"] == "verified"
    assert good["publication"] == "unchanged-no-delivery"
    assert ctrl.issued == 1


@pytest.mark.parametrize("bad", [
    {"certificate_fingerprint_sha256": "f"*64},
    {"outcome": "renewed"},
    {"certificate_id": "other"},
    {"policy_sha256": "f"*64},
    {"tls_ready": True},
    {"journal_updated_at": (NOW+timedelta(seconds=12)).isoformat()},
])
def test_observation_and_inspection_mismatch_prevents_stage(tmp_path, monkeypatch, bad):
    config = timer_policy(tmp_path)
    ctrl = Controller()
    data = evidence(changed={"operation_updated_at": datetime.now(timezone.utc).isoformat()})
    def issuer(_):
        return inspect(monkeypatch, data)[0]
    first = timer.run(config, controller=ctrl, issuer_checker=issuer)
    rid = first["request_id"]
    ctrl.results[rid] = SimpleNamespace(
        request_id=rid, application="certify-manage", program_name="renew",
        operation="launch", status="satisfied", runtime_id="RUNTIME1",
        updated_at=None
    )
    def observer(policy, *, request_id, started, controller_result):
        return {**{
            "status": "journal-ready", "tls_ready": False,
            "certificate_id": "station-web", "policy_sha256": "a"*64,
            "outcome": "unchanged", "certificate_fingerprint_sha256": FP,
            "journal_updated_at": data["operation_updated_at"],
        }, **bad}
    with pytest.raises(RenewalBlocked):
        timer.run(config, controller=ctrl, issuer_checker=issuer,
                  issuer_observer=observer,
                  publication_advance=lambda *args: pytest.fail("no stage"))
    assert ctrl.issued == 1


def test_unknown_issuer_cannot_authorize_new_due_request(tmp_path, monkeypatch):
    cfg = timer_policy(tmp_path)
    ctrl = Controller()
    def never(_):
        raise RenewalBlocked("inspection-unavailable")
    with pytest.raises(RenewalBlocked, match="issuer-readiness-unproven"):
        timer.run(cfg, controller=ctrl, issuer_checker=never)
    assert ctrl.issued == 0


def test_selected_broker_default_checker_uses_authenticated_inspector(tmp_path, monkeypatch):
    """No private CertificateManager import in the split-UID timer code path."""
    cfg = timer_policy(tmp_path)
    ctrl = Controller()
    from zog.host_deploy import certificate_issuer_inspection as inspection_module
    called = []
    def authorized_checker(policy):
        assert policy["issuer_inspection_policy_file"] == "/etc/zog/issuer-inspection.json"
        called.append("bound-policy")
        def check(_policy):
            called.append("issuer-socket")
            return (
                SimpleNamespace(
                    health="valid", detail=None, days_remaining=31,
                    fingerprint_sha256=FP,
                ),
                {"operation": "issue", "outcome": "issued"},
                datetime.now(timezone.utc)-timedelta(hours=1),
            )
        return check
    monkeypatch.setattr(inspection_module, "inspection_checker", authorized_checker)
    monkeypatch.setattr(timer, "_issuer_verification",
                        lambda policy: pytest.fail("no direct issuer private mount"))
    result = timer.run(cfg, controller=ctrl)
    assert result["phase"] == "idle"
    assert ctrl.issued == 0
    assert called == ["bound-policy", "issuer-socket"]
