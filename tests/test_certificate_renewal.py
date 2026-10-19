"""Offline controller-authorized renewal replay and fail-closed evidence."""
from dataclasses import dataclass
import os
import pytest
from zog.host_deploy.certificate_renewal import tick, RenewalBlocked

POLICY = "a" * 64
ID = "station-web"

@dataclass
class Result:
    request_id: str
    application: str = "certify-manage"
    program_name: str = "renew"
    operation: str = "launch"
    status: str = "pending"

class Control:
    def __init__(self):
        self.count = 0
        self.submitted = []
        self.results = {}
    def issue_application_request_id(self):
        self.count += 1
        return "r1-abc123-abc123abc123abc123abc123abc12312-" + "f"*64
    def application_request_result(self, request_id):
        return self.results.get(request_id)
    def request_application_launch(self, application, *, program_name, request_id):
        self.submitted.append((application, program_name, request_id))

def dir_(tmp_path):
    path = tmp_path / "journal"
    path.mkdir(mode=0o700)
    return path

def step(path, control, **kwargs):
    return tick(path, control, certificate_id=ID, policy_sha256=POLICY, **kwargs)

def proof(request):
    return dict(schema="zog-certify-renewal-observation-v1",
                request_id=request, certificate_id=ID, policy_sha256=POLICY,
                operation="renew", health="valid", outcome="unchanged",
                fingerprint_sha256="b" * 64)

def test_lost_reply_reuses_one_exact_request_identity(tmp_path):
    path = dir_(tmp_path)
    control = Control()
    result = step(path, control, authorize_new=True)
    assert result["phase"] == "submitted"
    assert control.count == 1
    result = step(path, control, authorize_new=True)
    assert control.count == 1
    assert control.submitted == [("certify-manage", "renew", result["request_id"])] * 2
    rid = result["request_id"]
    control.results[rid] = Result(rid, status="satisfied")
    assert step(path, control, authorize_new=True)["phase"] == "awaiting-issuer"
    assert control.count == 1
    good = step(path, control, issuer_observation=proof)
    assert good["phase"] == "verified"
    assert good["outcome"] == "unchanged"

def test_controller_satisfied_alone_is_not_cert_ready(tmp_path):
    path = dir_(tmp_path)
    control = Control()
    rid = step(path, control, authorize_new=True)["request_id"]
    control.results[rid] = Result(rid, status="satisfied")
    assert step(path, control)["phase"] == "awaiting-issuer"
    assert step(path, control)["phase"] == "awaiting-issuer"
    assert control.count == 1

def test_foreign_program_result_fails_closed(tmp_path):
    path = dir_(tmp_path)
    control = Control()
    rid = step(path, control, authorize_new=True)["request_id"]
    control.results[rid] = Result(rid, program_name="issue", status="satisfied")
    with pytest.raises(RenewalBlocked, match="controller-result-identity-mismatch"):
        step(path, control)
    assert control.count == 1

def test_rejected_issuer_proof_fences_followup(tmp_path):
    path = dir_(tmp_path)
    control = Control()
    rid = step(path, control, authorize_new=True)["request_id"]
    control.results[rid] = Result(rid, status="satisfied")
    step(path, control)
    with pytest.raises(RenewalBlocked, match="issuer-observation-not-proven"):
        step(path, control, issuer_observation=lambda req: {**proof(req), "health": "uncertain"})
    with pytest.raises(RenewalBlocked, match="prior-renewal-requires-review"):
        step(path, control, authorize_new=True)

def test_changed_policy_cannot_reuse_pending_request(tmp_path):
    path = dir_(tmp_path)
    control = Control()
    step(path, control, authorize_new=True)
    with pytest.raises(RenewalBlocked, match="journal-binding-or-state-mismatch"):
        tick(path, control, policy_sha256="c"*64, certificate_id=ID, authorize_new=True)

def test_controller_failed_never_retries_automatically(tmp_path):
    path = dir_(tmp_path)
    control = Control()
    rid = step(path, control, authorize_new=True)["request_id"]
    control.results[rid] = Result(rid, status="failed")
    with pytest.raises(RenewalBlocked, match="controller-renewal-not-satisfied"):
        step(path, control)
    assert control.count == 1
    with pytest.raises(RenewalBlocked, match="prior-renewal-requires-review"):
        step(path, control, authorize_new=True)

def test_symlink_journal_rejected(tmp_path):
    path = dir_(tmp_path)
    target = tmp_path / "outside"
    target.write_text("protected")
    (path / "renewal.json").symlink_to(target)
    with pytest.raises(OSError):
        step(path, Control(), authorize_new=True)
    assert target.read_text() == "protected"
