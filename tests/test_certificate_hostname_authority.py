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
