"""Selected certificate stage and owner TLS-delivery recovery (offline mocks)."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_deploy import certificate_renewal as renewal
from zog.host_deploy import certificate_renewal_publication as pub
from zog.host_deploy import certificate_renewal_timer as timer

SHA = "a" * 64
CERT = "station-web"
FINGERPRINT = "f" * 64


class Control:
    def __init__(self):
        self.issued = []
        self.submitted = []
        self.results = {}
        self.evaluated = 0

    def issue_application_request_id(self):
        token = "r1-1-" + format(len(self.issued) + 1, "032x") + "-" + "e"*64
        self.issued.append(token)
        return token

    def application_request_result(self, ident):
        return self.results.get(ident)

    def request_application_launch(self, application, *, program_name, request_id):
        self.submitted.append((application, program_name, request_id))

    def evaluate(self):
        self.evaluated += 1
        return SimpleNamespace(ok=True)


def issuer_proof(req, *, outcome="renewed"):
    return {
        "schema": renewal.ATTESTATION_SCHEMA, "request_id": req,
        "certificate_id": CERT, "policy_sha256": SHA, "health": "valid",
        "operation": "renew", "outcome": outcome,
        "fingerprint_sha256": FINGERPRINT,
    }


def prepared(tmp_path, *, outcome="renewed"):
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    ctrl = Control()
    issued = renewal.tick(directory, ctrl, policy_sha256=SHA, certificate_id=CERT,
                          authorize_new=True)
    rid = issued["request_id"]
    ctrl.results[rid] = SimpleNamespace(
        request_id=rid, application="certify-manage", program_name="renew",
        operation="launch", status="satisfied",
    )
    result = renewal.tick(directory, ctrl, policy_sha256=SHA, certificate_id=CERT,
                          issuer_observation=lambda ident: issuer_proof(ident, outcome=outcome))
    assert result["phase"] == "verified"
    return directory, ctrl, rid


def policy(tmp_path):
    return {
        "schema": pub.POLICY_SCHEMA, "certificate_id": CERT,
        "policy_sha256": SHA, "service_id": "candidate-nginx",
        "issuer_state": str(tmp_path / "issuer"),
        "issuer_policy_file": str(tmp_path / "issuer-policy.json"),
        "socket_path": str(tmp_path / "delivery.sock"),
        "stage_program": "stage", "approved_stage": True,
        "hostnames": ["candidate.example.org"],
    }


def valid_stage(p, fp):
    assert fp == FINGERPRINT
    assert p["stage_program"] == "stage"
    return {"fingerprint": fp, "receipt_digest": "b"*64}


def _publication_journal(directory):
    return json.loads((directory / "renewal-publication.json").read_text())


def test_unchanged_never_stages_or_delivers(tmp_path):
    directory, ctrl, rid = prepared(tmp_path, outcome="unchanged")
    calls = []
    answer = pub.advance(
        directory, ctrl, policy(tmp_path),
        stage_observer=lambda *args: calls.append("stage"),
        delivery_client=lambda *args: calls.append("deliver"),
    )
    assert answer["state"] == "unchanged-no-delivery"
    assert calls == []
    assert len(ctrl.issued) == 1
    assert len(ctrl.submitted) == 1  # only initial renew
    assert not (directory / "renewal-publication.json").exists()


def test_changed_stage_id_is_persisted_before_selected_request(tmp_path):
    directory, ctrl, rid = prepared(tmp_path)
    def submit(application, *, program_name, request_id):
        if program_name == "stage":
            assert _publication_journal(directory)["stage_id"] == request_id
            raise TimeoutError("lost acknowledgement")
        ctrl.submitted.append((application, program_name, request_id))
    ctrl.request_application_launch = submit
    with pytest.raises(TimeoutError, match="lost acknowledgement"):
        pub.advance(directory, ctrl, policy(tmp_path), stage_observer=valid_stage)
    original = _publication_journal(directory)
    assert original["phase"] == "stage-issued"
    assert len(ctrl.issued) == 2
    submitted = []
    ctrl.request_application_launch = lambda application, *, program_name, request_id: (
        submitted.append((application, program_name, request_id))
    )
    a = pub.advance(directory, ctrl, policy(tmp_path), stage_observer=valid_stage)
    assert a["state"] == "stage-submitted"
    assert submitted == [("certify-manage", "stage", original["stage_id"])]
    assert len(ctrl.issued) == 2
    ctrl.results[original["stage_id"]] = SimpleNamespace(
        request_id=original["stage_id"], application="certify-manage",
        program_name="stage", operation="launch", status="pending",
    )
    assert pub.advance(directory, ctrl, policy(tmp_path))["state"] == "stage-pending"
    assert len(ctrl.issued) == 2


def test_stage_receipt_then_single_browser_verified_delivery(tmp_path):
    directory, ctrl, renewal_id = prepared(tmp_path)
    approved = policy(tmp_path)
    first = pub.advance(directory, ctrl, approved, stage_observer=valid_stage)
    stage_id = first["stage_id"]
    ctrl.results[stage_id] = SimpleNamespace(
        request_id=stage_id, application="certify-manage", program_name="stage",
        operation="launch", status="satisfied",
    )
    delivered = []
    verified = pub.advance(
        directory, ctrl, approved,
        stage_observer=valid_stage,
        delivery_client=lambda p, f: delivered.append((p["service_id"], f)) or True,
    )
    assert verified["state"] == "browser-verified"
    assert delivered == [("candidate-nginx", FINGERPRINT)]
    state = _publication_journal(directory)
    assert state["phase"] == "complete"
    assert state["renewal_id"] == renewal_id
    assert state["receipt_digest"] == "b"*64
    again = pub.advance(
        directory, ctrl, approved, stage_observer=lambda *x: pytest.fail("no stage"),
        delivery_client=lambda *x: pytest.fail("no second nginx reload"),
    )
    assert again["idempotent"] is True
    assert len(ctrl.issued) == 2
    pub.check_renewal_fence(directory, SHA, CERT)


def test_delivery_lost_reply_never_repeats_reload_and_blocks_new_renewal(tmp_path):
    directory, ctrl, rid = prepared(tmp_path)
    selected = policy(tmp_path)
    stage = pub.advance(directory, ctrl, selected)
    ctrl.results[stage["stage_id"]] = SimpleNamespace(
        request_id=stage["stage_id"], application="certify-manage",
        program_name="stage", operation="launch", status="satisfied",
    )
    calls = []
    def lost_reply(p, fingerprint):
        calls.append(fingerprint)
        raise TimeoutError("nginx may already have reloaded")
    with pytest.raises(renewal.RenewalBlocked, match="delivery-recovery-required"):
        pub.advance(directory, ctrl, selected, stage_observer=valid_stage, delivery_client=lost_reply)
    assert calls == [FINGERPRINT]
    assert _publication_journal(directory)["phase"] == "delivery-uncertain"
    with pytest.raises(renewal.RenewalBlocked, match="delivery-recovery-required"):
        pub.advance(directory, ctrl, selected, stage_observer=valid_stage, delivery_client=lost_reply)
    with pytest.raises(renewal.RenewalBlocked, match="previous-renewal-not-delivered"):
        pub.check_renewal_fence(directory, SHA, CERT)
    assert calls == [FINGERPRINT]
    assert len(ctrl.issued) == 2


@pytest.mark.parametrize("wrong", [
    {"approved_stage": False},
    {"stage_program": "issue"},
    {"service_id": "../nginx"},
    {"policy_sha256": "bad"},
    {"issuer_state": "/tmp/../redirection"},
    {"hostnames": ["not..allowed.example.org"]},
    {"arbitrary_command": "nginx -s reload"},
])
def test_invalid_stage_authorization_does_not_issue_any_request(tmp_path, wrong):
    directory, ctrl, _ = prepared(tmp_path)
    before = len(ctrl.issued)
    with pytest.raises(renewal.RenewalBlocked):
        pub.advance(directory, ctrl, {**policy(tmp_path), **wrong})
    assert len(ctrl.issued) == before


def test_stage_result_mismatch_or_failure_prevents_tls_delivery(tmp_path):
    directory, ctrl, _ = prepared(tmp_path)
    selected = policy(tmp_path)
    first = pub.advance(directory, ctrl, selected)
    token = first["stage_id"]
    ctrl.results[token] = SimpleNamespace(
        request_id=token, application="certify-manage",
        program_name="issue", operation="launch", status="satisfied",
    )
    with pytest.raises(renewal.RenewalBlocked, match="stage-controller-identity-mismatch"):
        pub.advance(directory, ctrl, selected, delivery_client=lambda *a: pytest.fail("no delivery"))
    ctrl.results[token].program_name = "stage"
    ctrl.results[token].status = "failed"
    with pytest.raises(renewal.RenewalBlocked, match="stage-controller-unsatisfied"):
        pub.advance(directory, ctrl, selected, delivery_client=lambda *a: pytest.fail("no delivery"))
    assert _publication_journal(directory)["phase"] == "blocked"


def test_unproven_stage_receipt_does_not_deliver(tmp_path):
    directory, ctrl, _ = prepared(tmp_path)
    selected = policy(tmp_path)
    stage = pub.advance(directory, ctrl, selected)
    ctrl.results[stage["stage_id"]] = SimpleNamespace(
        request_id=stage["stage_id"], application="certify-manage",
        program_name="stage", operation="launch", status="satisfied",
    )
    with pytest.raises(renewal.RenewalBlocked, match="stage-receipt-unproven"):
        pub.advance(directory, ctrl, selected,
                    stage_observer=lambda p, fp: {"fingerprint": "c"*64, "receipt_digest": "b"*64},
                    delivery_client=lambda *a: pytest.fail("no delivery"))
    assert _publication_journal(directory)["phase"] == "awaiting-stage"


def test_changed_policy_cannot_take_over_pending_stage(tmp_path):
    directory, ctrl, _ = prepared(tmp_path)
    selected = policy(tmp_path)
    pub.advance(directory, ctrl, selected)
    altered = {**selected, "service_id": "other-nginx"}
    with pytest.raises(renewal.RenewalBlocked, match="publication-journal-identity-mismatch"):
        pub.advance(directory, ctrl, altered)
    assert len(ctrl.issued) == 2


def test_timer_reconciles_changed_renewal_before_new_controller_request(tmp_path):
    directory, ctrl, rid = prepared(tmp_path)
    from zog.host_deploy.certificate_renewal_timer import run, SCHEMA as TIMER_SCHEMA
    config = {
        "schema": TIMER_SCHEMA, "application": "certify-manage", "program": "renew",
        "certificate_id": CERT, "policy_sha256": SHA,
        "project_root": str(tmp_path / "project"), "generation": "b"*64,
        "controller_user": "certowner", "issuer_user": "certowner",
        "root_control_socket": "/run/zog-station-production/control.sock",
        "python_executable": "/usr/bin/python3.12",
        "journal_directory": str(directory),
        "issuer_policy_file": str(tmp_path / "issuer-policy.json"),
        "issuer_state": str(tmp_path / "issuer"),
        "renew_when_days_remaining": 30, "minimum_interval_hours": 24,
        "evaluate_queued_request": True,
        "publication_policy_file": str(tmp_path / "approved-stage.json"),
        "issuer_observer_policy_file": None,
        "controller_backend": "local",
        "issuer_lifecycle_socket": None,
        "issuer_inspection_policy_file": None,
    }
    completed_at = datetime.now(timezone.utc)
    def inspector(p):
        return (SimpleNamespace(days_remaining=12, fingerprint_sha256=FINGERPRINT,
                                health="valid", detail=None),
                {"operation": "renew", "outcome": "renewed"}, completed_at)
    calls = []
    def stage_one(path, controller, stage_policy):
        calls.append("stage")
        return {"state": "stage-submitted", "stage_id": "s1"}
    ctrl.evaluated = 0
    answer = run(config, controller=ctrl, issuer_checker=inspector,
                 publication_policy_loader=lambda p: policy(tmp_path),
                 publication_advance=stage_one)
    assert answer["publication"] == "stage-submitted"
    assert len(ctrl.issued) == 1  # stage mock did not issue another ID
    assert ctrl.evaluated == 1
    assert calls == ["stage"]


def test_delivery_callback_must_return_actual_positive_acceptance(tmp_path):
    directory, ctrl, _ = prepared(tmp_path)
    selected = policy(tmp_path)
    stage = pub.advance(directory, ctrl, selected)
    ctrl.results[stage["stage_id"]] = SimpleNamespace(
        request_id=stage["stage_id"], application="certify-manage",
        program_name="stage", operation="launch", status="satisfied",
    )
    with pytest.raises(renewal.RenewalBlocked, match="delivery-recovery-required"):
        pub.advance(directory, ctrl, selected, stage_observer=valid_stage,
                    delivery_client=lambda *args: False)
    assert _publication_journal(directory)["phase"] == "delivery-uncertain"


def test_timer_changed_outcome_without_stage_approval_fails_closed(tmp_path):
    directory, ctrl, _ = prepared(tmp_path)
    from zog.host_deploy.certificate_renewal_timer import run, SCHEMA as TIMER_SCHEMA
    config = {
        "schema": TIMER_SCHEMA, "application": "certify-manage", "program": "renew",
        "certificate_id": CERT, "policy_sha256": SHA,
        "project_root": str(tmp_path / "project"), "generation": "b"*64,
        "controller_user": "certowner", "issuer_user": "certowner",
        "root_control_socket": "/run/zog-station-production/control.sock",
        "python_executable": "/usr/bin/python3.12",
        "journal_directory": str(directory),
        "issuer_policy_file": str(tmp_path / "issuer-policy.json"),
        "issuer_state": str(tmp_path / "issuer"),
        "renew_when_days_remaining": 30, "minimum_interval_hours": 24,
        "evaluate_queued_request": True, "publication_policy_file": None,
        "issuer_observer_policy_file": None,
        "controller_backend": "local",
        "issuer_lifecycle_socket": None,
        "issuer_inspection_policy_file": None,
    }
    initial = len(ctrl.issued)
    with pytest.raises(renewal.RenewalBlocked, match="publication-authorization-required"):
        run(config, controller=ctrl, issuer_checker=lambda p: (
            SimpleNamespace(days_remaining=8, fingerprint_sha256=FINGERPRINT,
                            health="valid", detail=None),
            {"operation": "renew", "outcome": "renewed"},
            datetime.now(timezone.utc),
        ))
    assert len(ctrl.issued) == initial


def test_stage_pending_reconciliation_uses_one_bounded_evaluator(tmp_path):
    directory, ctrl, _ = prepared(tmp_path)
    from zog.host_deploy.certificate_renewal_timer import _publish_one
    selected = policy(tmp_path)
    first = pub.advance(directory, ctrl, selected)
    stage_id = first["stage_id"]
    ctrl.results[stage_id] = SimpleNamespace(
        request_id=stage_id, application="certify-manage",
        program_name="stage", operation="launch", status="pending",
    )
    state = _publish_one(
        {"journal_directory": str(directory)}, ctrl, selected,
        lambda folder, controller, selection: pub.advance(
            folder, controller, selection,
            stage_observer=valid_stage,
            delivery_client=lambda *args: pytest.fail("not ready"),
        ),
    )
    assert state["state"] == "stage-pending"
    assert ctrl.evaluated == 1
    assert len(ctrl.issued) == 2


def test_invalid_hostnames_and_partial_delivery_journal_fail_closed(tmp_path):
    selected = policy(tmp_path)
    for bad_host in ("a..example.org", "a-.example.org", "-a.example.org",
                     ".example.org", "a.example.org.", "a"*64 + ".example.org"):
        with pytest.raises(renewal.RenewalBlocked, match="publication-policy-invalid"):
            pub.validate_policy({**selected, "hostnames": [bad_host]})
    directory, ctrl, _ = prepared(tmp_path)
    pub.advance(directory, ctrl, selected)
    journal = directory / "renewal-publication.json"
    value = json.loads(journal.read_text())
    value["phase"] = "complete"
    journal.write_text(json.dumps(value))
    with pytest.raises(renewal.RenewalBlocked, match="publication-journal-identity-mismatch"):
        pub.advance(directory, ctrl, selected)
