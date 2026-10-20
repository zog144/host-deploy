"""Versioned certificate authority provenance and local-consumer scope."""
import copy
import uuid

import pytest
from zog.host_deploy import certificate_hostname_authority as auth

NOW = 1800000000


def authority():
    return {
        "schema": auth.SCHEMA, "origin": "standalone-local",
        "verified_by": "authenticated-local-admin",
        "host_id": str(uuid.UUID(int=1)),
        "installation_id": str(uuid.UUID(int=2)),
        "operation_id": str(uuid.UUID(int=3)),
        "revision": 1, "status": "approved",
        "approved_at": NOW-3600, "expires_at": NOW+86400,
        "revoked_at": None, "certificate_id": "station-web",
        "service_id": "candidate-nginx",
        "hostnames": ["candidate.example.org"], "policy_sha256": "a"*64,
        "challenge": "dns-01", "dns_mode": "local-cloudflare",
        "dns_zone": "example.org", "credential_id": "local-cloudflare",
        "credential_revision": 3,
    }


def test_standalone_authority_matches_exact_local_consumer():
    a = authority()
    assert auth.validate(a, now=NOW) == a
    assert auth.authorize_consumer(a, {
        "service_id": a["service_id"], "certificate_id": a["certificate_id"],
        "hostnames": a["hostnames"], "policy_sha256": a["policy_sha256"]
    }, now=NOW)["consumer"] == "candidate-nginx"
    for bad in ({"service_id": "other"}, {"certificate_id": "other"},
                {"hostnames": ["other.example.org"]},
                {"policy_sha256": "b"*64}):
        with pytest.raises(auth.AuthorityBlocked):
            auth.authorize_consumer(a, {**a, **bad}, now=NOW)


def test_managed_origin_requires_distinct_review_and_rejects_replay():
    first = authority()
    managed = {**first, "origin": "managed",
               "verified_by": "signed-host-discover"}
    assert auth.validate(managed, now=NOW)["origin"] == "managed"
    with pytest.raises(auth.AuthorityBlocked):
        auth.compare_revision(first, managed)
    assert auth.compare_revision(first, copy.deepcopy(first)) is False
    newer = {**first, "revision": 2, "operation_id": str(uuid.UUID(int=4)),
             "credential_revision": 4}
    assert auth.compare_revision(first, newer)
    for invalid in (
        {**first, "revision": 2},
        {**first, "revision": 1, "credential_revision": 5},
        {**first, "revision": 0},
    ):
        with pytest.raises(auth.AuthorityBlocked):
            auth.compare_revision(first, invalid)


def test_revocation_stale_and_credentials_cannot_appear_in_receipt():
    a = authority()
    for invalid in (
        {"status": "revoked", "revoked_at": None},
        {"expires_at": NOW-1},
        {"credential_revision": 0},
        {"dns_zone": "other.org"},
        {"access_token": "secret"},
        {"hostnames": ["example.org", "example.org"]},
        {"host_id": "foreign"},
    ):
        with pytest.raises(auth.AuthorityBlocked):
            auth.validate({**a, **invalid}, now=NOW)
    revoked = {**a, "status": "revoked", "revoked_at": NOW}
    assert auth.compare_revision(a, {**revoked, "revision": 2,
                                    "operation_id": str(uuid.UUID(int=5))})
    with pytest.raises(auth.AuthorityBlocked):
        auth.compare_revision(
            {**revoked, "revision": 2, "operation_id": str(uuid.UUID(int=5))},
            {**a, "revision": 3, "operation_id": str(uuid.UUID(int=6))})


def test_authority_delivery_wrapper_denies_foreign_consumer_and_uses_root_receipt(monkeypatch):
    from zog.host_deploy import certificate_delivery as delivery
    from datetime import datetime, timezone
    a = authority()
    actual_now = int(datetime.now(timezone.utc).timestamp())
    a["approved_at"] = actual_now - 3600
    a["expires_at"] = actual_now + 86400
    authorized = {
        "service_id": a["service_id"], "certificate_id": a["certificate_id"],
        "hostnames": a["hostnames"], "policy_sha256": a["policy_sha256"],
    }
    monkeypatch.setattr(delivery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(delivery, "policy_validate", lambda policy: policy)
    queried = []
    def root_owned(path, *, now):
        queried.append(path)
        return a
    monkeypatch.setattr(auth, "read_owned", root_owned)
    deliveries = []
    monkeypatch.setattr(delivery, "publish",
                        lambda policy, fp, **kw: deliveries.append((policy, fp)) or
                        {"state": "browser-verified"})
    result = delivery.publish_authorized(
        authorized, "e" * 64, authority_path="/etc/zog/authority.json")
    assert result["state"] == "browser-verified"
    assert queried == ["/etc/zog/authority.json"]
    assert deliveries == [(authorized, "e" * 64)]
    with pytest.raises(delivery.DeliveryBlocked, match="hostname-authority"):
        delivery.publish_authorized(
            {**authorized, "service_id": "unapproved"},
            "e" * 64, authority_path="/etc/zog/authority.json")
    assert len(deliveries) == 1


def test_delivery_wrapper_refuses_unprivileged_invocation(monkeypatch):
    from zog.host_deploy import certificate_delivery as delivery
    monkeypatch.setattr(delivery.os, "geteuid", lambda: 1000)
    with pytest.raises(delivery.DeliveryBlocked, match="not-authorized"):
        delivery.publish_authorized(
            {}, "e" * 64, authority_path="/etc/zog/authority.json")


def test_versioned_listener_refuses_expired_authority_before_binding(monkeypatch):
    from zog.host_deploy import certificate_delivery as delivery
    a = authority()
    policy = {
        "service_id": a["service_id"], "certificate_id": a["certificate_id"],
        "hostnames": a["hostnames"], "policy_sha256": a["policy_sha256"]
    }
    monkeypatch.setattr(delivery, "read_policy", lambda _: policy)
    def refuse(path, *, now):
        raise auth.AuthorityBlocked("stale-assignment")
    monkeypatch.setattr(auth, "read_owned", refuse)
    class MustNotBind:
        def __init__(self, *args, **kwargs):
            pytest.fail("rejected authority must not allocate socket")
    monkeypatch.setattr(delivery, "_Server", MustNotBind)
    with pytest.raises(auth.AuthorityBlocked, match="stale-assignment"):
        delivery.serve("/etc/zog/issuer-policy.json",
                       authority_path="/etc/zog/authority.json")


def test_owner_authority_cli_selects_versioned_publisher(monkeypatch, capsys):
    from zog.host_deploy import certificate_delivery as delivery
    monkeypatch.setattr(delivery, "read_policy", lambda path: {"approved": path})
    published = []
    monkeypatch.setattr(delivery, "publish",
        lambda *args, **kwargs: pytest.fail("legacy publisher used"))
    def accepted(policy, fp, *, authority_path, **kwargs):
        published.append((policy, fp, authority_path))
        return {"schema": delivery.SCHEMA, "state": "browser-verified"}
    monkeypatch.setattr(delivery, "publish_authorized", accepted)
    result = delivery.main([
        "--owner-policy", "/etc/zog/delivery.json",
        "--owner-authority", "/etc/zog/authority.json",
        "--fingerprint", "e" * 64,
    ])
    assert result == 0
    assert published == [
        ({"approved": "/etc/zog/delivery.json"}, "e" * 64,
         "/etc/zog/authority.json")
    ]
    assert "browser-verified" in capsys.readouterr().out
