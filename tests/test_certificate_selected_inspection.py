"""Short-lived inspect selector: durable ID, terminal result, trusted invocation."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import pytest

from zog.host_deploy import certificate_selected_inspection as ins
from zog.host_deploy import certificate_renewal as renewal

FP = "f"*64
SCOPE = {
    "certificate_id": "station-web", "policy_sha256": "a"*64,
    "hostnames": ["candidate.example.org"], "issuer_uid": 24001,
    "issuer_gid": 24002, "storage_id": "b"*32, "grant_id": "c"*32,
}


class Controller:
    def __init__(self):
        self.issued = []
        self.launched = []
        self.answers = {}
        self.after_submit = None

    def issue_application_request_id(self):
        token = "r1-123-" + format(len(self.issued) + 1, "032x") + "-" + "d"*64
        self.issued.append(token)
        return token

    def application_request_result(self, ident):
        return self.answers.get(ident)

    def request_application_launch(self, application, *, program_name, request_id):
        if self.after_submit is not None:
            self.after_submit(application, program_name, request_id)
        self.launched.append((application, program_name, request_id))


def directory(tmp_path):
    path = tmp_path / "journal"
    path.mkdir(mode=0o700)
    return path


def status(controller, rid, *, program="inspect", state="satisfied"):
    controller.answers[rid] = SimpleNamespace(
        request_id=rid, application="certify-manage",
        program_name=program, operation="launch", status=state,
        runtime_id="RUNTIME01",
    )


def evidence(rid, *, original=None, changed=None):
    issuer = {
        "schema": "zog-certify-inspection-result-v1",
        "certificate_id": "station-web",
        "hostnames": ["candidate.example.org"], "policy_sha256": "a"*64,
        "health": "valid", "certificate_fingerprint_sha256": FP,
        "operation": "renew", "outcome": "unchanged",
        "operation_updated_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc)+timedelta(days=30)).isoformat(),
        "valid_from": (datetime.now(timezone.utc)-timedelta(days=1)).isoformat(),
        "days_remaining": 30, "issuer_verified": True, "tls_ready": False,
    }
    wrapper = {
        "schema": ins.EVIDENCE_SCHEMA, "inspect_request_id": rid,
        "runtime_id": "RUNTIME01", "invocation_id": "a"*32,
        "program": "inspect", "storage_id": "b"*32, "grant_id": "c"*32,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "original_renewal_id": original, "issuer_result": issuer,
    }
    # Test mutations intentionally distinguish authenticated controller
    # provenance from issuer-owned one-shot certificate output.
    for name, value in (changed or {}).items():
        if name in issuer:
            issuer[name] = value
        else:
            wrapper[name] = value
    return wrapper

def test_original_inspect_id_is_saved_before_selected_start(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    journal = path / "selected-inspection.json"
    def lost(app, program, rid):
        assert (app, program) == ("certify-manage", "inspect")
        assert json.loads(journal.read_text())["request_id"] == rid
        raise TimeoutError("broker may already have launched")
    ctrl.after_submit = lost
    with pytest.raises(TimeoutError):
        ins.tick(path, ctrl, SCOPE)
    saved = json.loads(journal.read_text())
    assert saved["phase"] == "issued"
    assert ctrl.issued == [saved["request_id"]]
    ctrl.after_submit = None
    again = ins.tick(path, ctrl, SCOPE)
    assert again["phase"] == "submitted"
    assert ctrl.launched == [("certify-manage", "inspect", saved["request_id"])]
    assert ctrl.issued == [saved["request_id"]]


def test_process_exit_cannot_establish_valid_certificate(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    first = ins.tick(path, ctrl, SCOPE)
    rid = first["request_id"]
    status(ctrl, rid)
    result = ins.tick(path, ctrl, SCOPE)
    assert result["phase"] == "awaiting-evidence"
    assert result["fingerprint"] is None
    # No privileged result reader is yet implemented. A status/exit is not proof.
    assert not hasattr(ctrl, "read_secret") and ctrl.issued == [rid]


def test_trusted_invocation_reader_correlates_exact_inspect_id(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    first = ins.tick(path, ctrl, SCOPE)
    rid = first["request_id"]
    status(ctrl, rid)
    visits = []
    def trusted_reader(ident, runtime):
        visits.append((ident, runtime))
        return evidence(ident)
    result = ins.tick(path, ctrl, SCOPE, trusted_reader=trusted_reader)
    assert result["phase"] == "verified"
    assert result["fingerprint"] == FP
    assert visits == [(rid, "RUNTIME01")]
    again = ins.tick(path, ctrl, SCOPE)
    assert again["request_id"] == rid
    assert len(ctrl.issued) == 1


@pytest.mark.parametrize("wrong", [
    {"inspect_request_id": "other"},
    {"runtime_id": "OTHER"},
    {"invocation_id": None},
    {"program": "renew"}, {"storage_id": "d"*32},
    {"grant_id": "d"*32}, {"issuer_uid": 1},
    {"issuer_gid": 1}, {"certificate_id": "wrong"},
    {"hostnames": ["other.example.org"]}, {"policy_sha256": "e"*64},
    {"outcome": "recovered-unverified"}, {"health": "invalid"},
    {"certificate_fingerprint_sha256": "wrong"}, {"issuer_verified": False},
    {"tls_ready": True},
    {"observed_at": (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()},
    {"expires_at": (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()},
    {"extra_path": "/var/lib/private"},
])
def test_forged_or_stale_result_cannot_advance_selected_inspect(tmp_path, wrong):
    path = directory(tmp_path)
    ctrl = Controller()
    rid = ins.tick(path, ctrl, SCOPE)["request_id"]
    status(ctrl, rid)
    with pytest.raises(renewal.RenewalBlocked):
        ins.tick(path, ctrl, SCOPE,
                 trusted_reader=lambda ident, runtime: evidence(ident, changed=wrong))
    assert json.loads((path/"selected-inspection.json").read_text())["phase"] == "awaiting-evidence"
    assert len(ctrl.issued) == 1


def test_active_renewal_prevents_inspector_start(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    renewal.tick(path, ctrl, policy_sha256=SCOPE["policy_sha256"],
                 certificate_id=SCOPE["certificate_id"], authorize_new=True)
    issued_before = len(ctrl.issued)
    with pytest.raises(renewal.RenewalBlocked, match="active-renewal"):
        ins.tick(path, ctrl, SCOPE)
    assert len(ctrl.issued) == issued_before


def test_selected_inspect_has_new_id_and_preserves_original_renewal(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    original = renewal.tick(path, ctrl, policy_sha256=SCOPE["policy_sha256"],
                            certificate_id=SCOPE["certificate_id"], authorize_new=True)
    old_id = original["request_id"]
    status(ctrl, old_id, program="renew")
    proof = {
        "schema": renewal.ATTESTATION_SCHEMA, "request_id": old_id,
        "certificate_id": SCOPE["certificate_id"], "policy_sha256": SCOPE["policy_sha256"],
        "health": "valid", "operation": "renew", "outcome": "unchanged",
        "fingerprint_sha256": FP,
    }
    accepted = renewal.tick(path, ctrl, policy_sha256=SCOPE["policy_sha256"],
                            certificate_id=SCOPE["certificate_id"],
                            issuer_observation=lambda rid: proof)
    assert accepted["phase"] == "verified"
    inspect_id = ins.tick(path, ctrl, SCOPE, original_renewal_id=old_id)["request_id"]
    assert inspect_id != old_id
    status(ctrl, inspect_id)
    scoped_evidence = evidence(inspect_id, original=old_id)
    owner_proof = {
        "status": "journal-ready", "request_id": old_id,
        "certificate_id": SCOPE["certificate_id"],
        "policy_sha256": SCOPE["policy_sha256"],
        "storage_id": SCOPE["storage_id"], "grant_id": SCOPE["grant_id"],
        "certificate_fingerprint_sha256": FP, "outcome": "unchanged",
        "journal_updated_at": scoped_evidence["issuer_result"]["operation_updated_at"],
        "tls_ready": False,
    }
    verified = ins.tick(
        path, ctrl, SCOPE, original_renewal_id=old_id,
        trusted_reader=lambda rid, runtime: scoped_evidence,
        trusted_renewal_observation=owner_proof,
    )
    assert verified["phase"] == "verified"
    assert json.loads((path / "renewal.json").read_text())["request_id"] == old_id


def test_pending_result_and_wrong_selected_result_preserve_record(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    rid = ins.tick(path, ctrl, SCOPE)["request_id"]
    status(ctrl, rid, state="pending")
    assert ins.tick(path, ctrl, SCOPE)["phase"] == "submitted"
    status(ctrl, rid, program="stage")
    with pytest.raises(renewal.RenewalBlocked, match="result-mismatch"):
        ins.tick(path, ctrl, SCOPE)
    assert len(ctrl.issued) == 1


def test_no_second_inspection_during_short_freshness_window(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    rid = ins.tick(path, ctrl, SCOPE)["request_id"]
    status(ctrl, rid)
    ins.tick(path, ctrl, SCOPE, trusted_reader=lambda rid, rt: evidence(rid))
    assert ins.tick(path, ctrl, SCOPE)["request_id"] == rid
    assert len(ctrl.issued) == 1


def test_unapproved_broker_selector_fails_and_retains_id(tmp_path):
    path = directory(tmp_path)
    ctrl = Controller()
    def denied(app, program, rid):
        raise renewal.RenewalBlocked("issuer-lifecycle-selection-rejected")
    ctrl.after_submit = denied
    with pytest.raises(renewal.RenewalBlocked, match="selection-rejected"):
        ins.tick(path, ctrl, SCOPE)
    record = json.loads((path/"selected-inspection.json").read_text())
    assert record["phase"] == "issued"
    assert len(ctrl.issued) == 1


def test_post_renewal_inspection_requires_distinct_trusted_journal_proof(tmp_path):
    """An inspect report cannot itself attest its claimed original renew ID."""
    original_id = "r1-12-" + "a"*32 + "-" + "b"*64
    inspect_id = "r1-13-" + "c"*32 + "-" + "d"*64
    certificate = evidence(inspect_id, original=original_id)
    with pytest.raises(renewal.RenewalBlocked, match="original-renewal-proof-mismatch"):
        ins.correlate(SCOPE, inspect_id, "RUNTIME01", certificate,
                      original_renewal_id=original_id)
    proof = {
        "status": "journal-ready", "request_id": original_id,
        "certificate_id": SCOPE["certificate_id"],
        "policy_sha256": SCOPE["policy_sha256"],
        "storage_id": SCOPE["storage_id"], "grant_id": SCOPE["grant_id"],
        "certificate_fingerprint_sha256": FP, "outcome": "unchanged",
        "journal_updated_at": certificate["issuer_result"]["operation_updated_at"],
        "tls_ready": False,
    }
    for wrong in (
        {"request_id": inspect_id},
        {"journal_updated_at": (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()},
        {"certificate_fingerprint_sha256": "a"*64},
        {"storage_id": "0"*32},
        {"outcome": "renewed"},
        {"tls_ready": True},
    ):
        with pytest.raises(renewal.RenewalBlocked, match="original-renewal-proof-mismatch"):
            ins.correlate(
                SCOPE, inspect_id, "RUNTIME01", certificate,
                original_renewal_id=original_id,
                renewal_observation={**proof, **wrong},
            )
    valid = ins.correlate(
        SCOPE, inspect_id, "RUNTIME01", certificate,
        original_renewal_id=original_id, renewal_observation=proof,
    )
    assert valid["inspect_request_id"] == inspect_id
    assert valid["tls_ready"] is False
