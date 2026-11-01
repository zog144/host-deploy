"""Root-control issuer journal proof must bind the local host-deploy policy.

No station-access UID account, filesystem, signing key, socket, or remote
authority projection is ever opened by these verifier tests.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from zog.host_deploy import certificate_issuer_observer as root
from zog.host_deploy import certificate_renewal_timer as timer
from zog.host_deploy import certificate_authenticated_inspection as inspected
from zog.host_deploy.certificate_renewal import RenewalBlocked

POLICY = "a" * 64
HOST = "sha256:" + "b" * 64
REQ = "r1-1-" + "c" * 32 + "-" + "d" * 64


def timer_policy():
    return {
        "certificate_id": "station-web",
        "policy_sha256": POLICY,
        "issuer_observer_policy_file": "/etc/zog/issuer-observer.json",
    }


def root_policy():
    return {
        "schema": root.SCHEMA,
        "socket_path": "/run/zog/issuer-observer.sock",
        "caller_uid": 23001,
        "certificate_id": "station-web",
        "policy_sha256": POLICY,
        "host_policy_digest": HOST,
        "storage_id": "e" * 32, "grant_id": "f" * 32,
        "issuer_uid": 24001, "issuer_gid": 24002,
    }


def root_receipt():
    return {
        "schema": root.OBSERVED,
        "status": "journal-ready",
        "request_id": REQ,
        "runtime_id": "RUNTIME01",
        "certificate_id": "station-web",
        "policy_sha256": POLICY,
        "host_policy_digest": HOST,
        "storage_id": "e" * 32,
        "grant_id": "f" * 32,
        "certificate_fingerprint_sha256": "1" * 64,
        "outcome": "renewed",
        "journal_updated_at": datetime.now(timezone.utc).isoformat(),
        "tls_ready": False,
    }


def _verified(monkeypatch, *, approved=None, observed=None, local=None):
    from zog.host_deploy import certificate_issuer_observer as observer
    monkeypatch.setattr(observer, "read_policy",
                        lambda path: approved if approved is not None else root_policy())
    seen = []

    def read_root(policy, *, request_id, issued_at, controller_result):
        seen.append((policy, request_id))
        return observed if observed is not None else root_receipt()

    monkeypatch.setattr(observer, "observe_request", read_root)
    p = local if local is not None else timer_policy()
    result = timer._authenticated_issuer_evidence(
        p, request_id=REQ,
        started=datetime.now(timezone.utc) - timedelta(minutes=1),
        controller_result=SimpleNamespace(request_id=REQ),
    )
    return result, seen


def test_local_policy_pins_exact_root_observation(monkeypatch):
    result, seen = _verified(monkeypatch)
    assert result["request_id"] == REQ
    assert result["policy_sha256"] == POLICY
    assert result["host_policy_digest"] == HOST
    assert seen == [(root_policy(), REQ)]
    assert not any("970" in repr(item) for item in seen)


@pytest.mark.parametrize("override", [
    {"policy_sha256": "2" * 64},
    {"certificate_id": "foreign-cert"},
    {"host_policy_digest": "sha256:" + "3" * 64},
    {"request_id": "different-request"},
    {"tls_ready": True},
])
def test_root_observation_cannot_change_local_authority(monkeypatch, override):
    with pytest.raises(RenewalBlocked, match="root-observation"):
        _verified(monkeypatch, observed={**root_receipt(), **override})


@pytest.mark.parametrize("override", [
    {"policy_sha256": "2" * 64},
    {"certificate_id": "foreign-cert"},
])
def test_root_policy_cannot_replace_local_policy(monkeypatch, override):
    with pytest.raises(RenewalBlocked, match="issuer-observer-policy-mismatch"):
        _verified(monkeypatch, approved={**root_policy(), **override})


def test_wrong_local_policy_blocks_before_root_observation(monkeypatch):
    with pytest.raises(RenewalBlocked, match="issuer-observer-policy-mismatch"):
        _verified(monkeypatch, local={**timer_policy(), "policy_sha256": "0" * 64})


def test_root_observation_is_a_distinct_claim_from_inspection_policy(monkeypatch):
    # Even an otherwise perfect root journal result cannot select the
    # independent expected host policy digest for a selected inspect result.
    proof = root_receipt()
    checked = {
        "schema": inspected.TRUSTED, "request_id": REQ,
        "runtime_id": "RUNTIME01", "program": "inspect",
        "boot_id": "a" * 32, "invocation_id": "b" * 32,
        "storage_id": "e" * 32, "grant_id": "f" * 32,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "host_policy_digest": HOST, "status": "verified",
        "tls_ready": False, "inspection": None,
    }
    scope = {
        "certificate_id": "station-web", "policy_sha256": POLICY,
        "hostnames": ["candidate.example.org"], "storage_id": "e" * 32,
        "grant_id": "f" * 32, "issuer_uid": 24001, "issuer_gid": 24002,
    }
    with pytest.raises(RenewalBlocked, match="trusted-inspection-invocation-mismatch"):
        inspected.correlate(
            scope, REQ, "RUNTIME01", checked,
            renewal_observation=proof, host_policy_digest=None,
        )
