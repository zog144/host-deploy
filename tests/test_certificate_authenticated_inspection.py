"""Host-owned, UID-pinned invocation inspection without native systemd mutations."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import json

import pytest

from zog.host_deploy.certificate_issuer_lifecycle import SelectedIssuerController
from zog.host_deploy.certificate_authenticated_inspection import correlate
from zog.host_deploy.certificate_renewal import RenewalBlocked
from zog.host_deploy import certificate_selected_inspection as selected

SCOPE = {
    "certificate_id": "station-web", "policy_sha256": "a" * 64,
    "hostnames": ["candidate.example.org"], "issuer_uid": 24001,
    "issuer_gid": 24002, "storage_id": "b" * 32, "grant_id": "c" * 32,
}
POLICY = "sha256:" + "d" * 64
FP = "e" * 64
ID = "r1-1-" + "f" * 32 + "-" + "f" * 64


def envelope(*, observed_at=None, outcome="unchanged"):
    now = datetime.now(timezone.utc)
    return {
        "schema": "zog-trusted-issuer-inspection-v1",
        "request_id": ID, "runtime_id": "RUNTIME01",
        "program": "inspect", "boot_id": "a" * 32,
        "invocation_id": "b" * 32,
        "storage_id": SCOPE["storage_id"], "grant_id": SCOPE["grant_id"],
        "issuer_uid": SCOPE["issuer_uid"], "issuer_gid": SCOPE["issuer_gid"],
        "host_policy_digest": POLICY, "status": "verified",
        "tls_ready": False,
        "inspection": {
            "schema": "zog-certify-inspection-result-v1",
            "certificate_id": SCOPE["certificate_id"],
            "hostnames": SCOPE["hostnames"],
            "policy_sha256": SCOPE["policy_sha256"],
            "health": "valid", "certificate_fingerprint_sha256": FP,
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "days_remaining": 30, "operation": "renew",
            "outcome": outcome,
            "operation_updated_at": (now - timedelta(minutes=1)).isoformat(),
            "issuer_verified": True, "observed_at": (
                observed_at or now.isoformat()), "tls_ready": False,
        },
    }


def journal_observation(e):
    return {
        "schema": "zog-trusted-issuer-observation-v1",
        "status": "journal-ready", "request_id": "renew-id-1",
        "certificate_id": SCOPE["certificate_id"],
        "policy_sha256": SCOPE["policy_sha256"],
        "host_policy_digest": POLICY,
        "storage_id": SCOPE["storage_id"], "grant_id": SCOPE["grant_id"],
        "certificate_fingerprint_sha256": FP,
        "outcome": "unchanged",
        "tls_ready": False,
        "journal_updated_at": e["inspection"]["operation_updated_at"],
    }


def test_authenticated_correlator_checks_original_renewal_and_freshness():
    e = envelope()
    proof = journal_observation(e)
    accepted = correlate(
        SCOPE, ID, "RUNTIME01", e, original_renewal_id="renew-id-1",
        renewal_observation=proof, host_policy_digest=POLICY,
    )
    assert accepted["fingerprint"] == FP and accepted["tls_ready"] is False
    assert accepted["invocation_id"] == "b" * 32
    for bad in (
        {"runtime_id": "WRONG"},
        {"request_id": "renew-id-1"},
        {"host_policy_digest": "sha256:" + "0" * 64},
        {"status": "unverified"},
        {"boot_id": "invalid"},
        {"inspection": {**e["inspection"], "tls_ready": True}},
        {"inspection": {**e["inspection"],
                        "observed_at": (
                            datetime.now(timezone.utc) - timedelta(minutes=16)
                        ).isoformat()}},
    ):
        with pytest.raises(RenewalBlocked):
            correlate(SCOPE, ID, "RUNTIME01", {**e, **bad},
                      original_renewal_id="renew-id-1",
                      renewal_observation=proof, host_policy_digest=POLICY)
    with pytest.raises(RenewalBlocked, match="renewal-mismatch"):
        correlate(SCOPE, ID, "RUNTIME01", e,
                  original_renewal_id="renew-id-1",
                  renewal_observation={**proof, "request_id": ID},
                  host_policy_digest=POLICY)


class Broker:
    def __init__(self, path, *, controller_uid):
        assert path == "/run/zog/certify-lifecycle.sock"
        assert controller_uid == 23001
        self.last = None
        self.launched = False

    def issue_application_request_id(self):
        return ID

    def launch_application(self, application, *, program_name, request_id):
        self.last = (application, program_name, request_id)
        self.launched = True
        return SimpleNamespace(application="certify-manage",
                               selected_program=program_name,
                               runtime_id="RUNTIME01")

    def application_request_result(self, request_id):
        if not self.launched:
            return {"request_id": request_id, "program": None,
                    "status": "unknown", "runtime_id": None}
        return {"request_id": request_id, "program": "inspect",
                "status": "satisfied", "runtime_id": "RUNTIME01"}

    def inspect_issuer_result(self, request_id):
        assert request_id == ID
        return envelope()


def test_pinned_controller_adapter_accepts_inspect_but_no_general_commands():
    ctrl = SelectedIssuerController(
        "/run/zog/certify-lifecycle.sock", controller_uid=23001,
        client_factory=Broker,
    )
    ctrl.request_application_launch(
        "certify-manage", program_name="inspect", request_id=ID)
    assert ctrl.application_request_result(ID).program_name == "inspect"
    assert ctrl.inspect_issuer_result(ID)["request_id"] == ID
    with pytest.raises(RenewalBlocked, match="selection-rejected"):
        ctrl.request_application_launch(
            "certify-manage", program_name="shell", request_id=ID)
    with pytest.raises(RenewalBlocked, match="uid-required"):
        SelectedIssuerController(
            "/run/zog/certify-lifecycle.sock",
            client_factory=lambda _: Broker("/run/zog/certify-lifecycle.sock",
                                            controller_uid=23001)
        ).inspect_issuer_result(ID)


def test_selected_inspect_persists_distinct_id_and_uses_only_saved_reader(tmp_path):
    d = tmp_path / "inspection"
    d.mkdir(mode=0o700)
    ctrl = SelectedIssuerController(
        "/run/zog/certify-lifecycle.sock", controller_uid=23001,
        client_factory=Broker,
    )
    first = selected.tick(d, ctrl, SCOPE)
    assert first["phase"] == "submitted"
    assert first["request_id"] == ID
    # Caller injection is not used to select a saved invocation.
    result = selected.tick(d, ctrl, SCOPE, host_policy_digest=POLICY)
    assert result["phase"] == "verified"
    assert result["fingerprint"] == FP
    assert json.loads((d / "selected-inspection.json").read_text())[
        "request_id"] == ID
