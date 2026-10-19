"""Trusted issuer observation: exact saved ID, grant, storage and no TLS shortcut."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from zog.host_deploy import certificate_issuer_observer as o
from zog.host_deploy.certificate_renewal import RenewalBlocked

REQ = "r1-199abcdef-" + "a"*32 + "-" + "b"*64


def policy():
    return {
        "schema": o.SCHEMA, "socket_path": "/run/zog/issuer-observer.sock",
        "caller_uid": 23001, "certificate_id": "station-web",
        "policy_sha256": "c"*64, "host_policy_digest": "sha256:" + "d"*64,
        "storage_id": "e"*32, "grant_id": "f"*32,
        "issuer_uid": 24001, "issuer_gid": 24002,
    }


def result():
    return SimpleNamespace(
        request_id=REQ, application="certify-manage", program_name="renew",
        operation="launch", status="satisfied", runtime_id="RUNTIME1",
    )


def evidence(*, when=None):
    return {
        "schema": o.OBSERVED, "request_id": REQ,
        "runtime_id": "RUNTIME1", "program": "renew",
        "storage_id": "e"*32, "grant_id": "f"*32,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "policy_sha256": "c"*64, "host_policy_digest": "sha256:" + "d"*64,
        "certificate_id": "station-web",
        "certificate_fingerprint_sha256": "1"*64,
        "journal_updated_at": (when or datetime.now(timezone.utc)).isoformat(),
        "outcome": "renewed", "status": "journal-ready", "tls_ready": False,
    }


def call(monkeypatch, *, e=None, ctrl=None, request=REQ, started=None):
    monkeypatch.setattr(o.os, "geteuid", lambda: 23001)
    visits = []

    class FakeClient:
        def __init__(self, socket_path):
            assert socket_path == policy()["socket_path"]
        def observe_issuer_request(self, request_id):
            visits.append(request_id)
            return e if e is not None else evidence()

    answer = o.observe_request(
        policy(), request_id=request,
        issued_at=started or (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        controller_result=ctrl if ctrl is not None else result(),
        client_factory=FakeClient,
    )
    return answer, visits


def test_trusted_observer_receives_only_exact_long_controller_id(monkeypatch):
    output, called = call(monkeypatch)
    assert called == [REQ]
    assert output["status"] == "journal-ready"
    assert output["certificate_fingerprint_sha256"] == "1"*64
    assert output["tls_ready"] is False
    assert not any(word in output for word in (
        "certbot_account", "private_key", "nginx_config", "shell",
    ))


@pytest.mark.parametrize("name,value", [
    ("request_id", "ANOTHER"),
    ("runtime_id", "ANOTHER"),
    ("program", "issue"),
    ("storage_id", "0"*32),
    ("grant_id", "0"*32),
    ("issuer_uid", 99999),
    ("issuer_gid", 99999),
    ("policy_sha256", "0"*64),
    ("host_policy_digest", "sha256:" + "0"*64),
    ("certificate_id", "wrong"),
    ("tls_ready", True),
    ("schema", "fake"),
])
def test_foreign_or_overclaimed_evidence_rejected(monkeypatch, name, value):
    with pytest.raises(RenewalBlocked, match="issuer-observation-binding-mismatch"):
        call(monkeypatch, e={**evidence(), name: value})


@pytest.mark.parametrize("status", ["ongoing", "stale", "uncertain"])
def test_incomplete_issuer_status_never_claims_readiness(monkeypatch, status):
    output, called = call(monkeypatch, e={**evidence(), "status": status,
                                         "certificate_fingerprint_sha256": None,
                                         "journal_updated_at": None,
                                         "outcome": None})
    assert output == {"status": status, "request_id": REQ, "tls_ready": False}
    assert called == [REQ]


def test_mismatched_controller_result_rejected_before_socket(monkeypatch):
    monkeypatch.setattr(o.os, "geteuid", lambda: 23001)
    for change in (
        {"request_id": "ANOTHER"},
        {"application": "station-access"},
        {"program_name": "issue"},
        {"operation": "terminate"},
        {"status": "pending"},
        {"runtime_id": None},
    ):
        with pytest.raises(RenewalBlocked):
            o.observe_request(
                policy(), request_id=REQ,
                issued_at=datetime.now(timezone.utc).isoformat(),
                controller_result=SimpleNamespace(**{**vars(result()), **change}),
                client_factory=lambda _path: pytest.fail("untrusted result reached socket"),
            )


def test_issuer_observation_precedes_request_and_future_clock_rejected(monkeypatch):
    past = datetime.now(timezone.utc) - timedelta(minutes=15)
    with pytest.raises(RenewalBlocked, match="issuer-observation-stale"):
        call(monkeypatch, e=evidence(when=past))
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    with pytest.raises(RenewalBlocked, match="observer-intent-in-future"):
        call(monkeypatch, started=future.isoformat())


def test_socket_failure_bounded_and_does_not_fall_back_to_private_issuer(monkeypatch):
    monkeypatch.setattr(o.os, "geteuid", lambda: 23001)
    class Offline:
        def __init__(self, _):
            pass
        def observe_issuer_request(self, request_id):
            raise ConnectionRefusedError("private host path")
    with pytest.raises(RenewalBlocked, match="issuer-observer-unavailable"):
        o.observe_request(
            policy(), request_id=REQ,
            issued_at=datetime.now(timezone.utc).isoformat(),
            controller_result=result(), client_factory=Offline
        )


def test_same_controller_owner_uid_cannot_impersonate_host_deploy(monkeypatch):
    monkeypatch.setattr(o.os, "geteuid", lambda: 24001)
    with pytest.raises(RenewalBlocked, match="observer-caller-identity-mismatch"):
        o.observe_request(
            policy(), request_id=REQ,
            issued_at=datetime.now(timezone.utc).isoformat(),
            controller_result=result(),
            client_factory=lambda _: pytest.fail("not authorized"),
        )


def test_policy_binds_exact_storage_grant_and_observer_socket():
    assert o.validate_policy(policy()) == policy()
    for change in (
        {"socket_path": "/tmp/../other"},
        {"caller_uid": True}, {"issuer_uid": 0},
        {"grant_id": "../other"},
        {"storage_id": "a"*64},
        {"unexpected": "shell"},
    ):
        with pytest.raises(RenewalBlocked):
            o.validate_policy({**policy(), **change})
