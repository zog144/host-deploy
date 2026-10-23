"""Signed managed root authority -> exact installed local nginx policy gate.

Synthetic Ed25519 signer is generated only in this test. No network, ACME,
issuer private key, station UID-970 state, or real nginx is involved.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from zog.host_deploy import certificate_managed_authority as managed
from zog.host_deploy import certificate_hostname_authority as owner
from zog.host_deploy import certificate_delivery as delivery

NOW = 1790000000


def ident(number):
    return str(uuid.UUID(int=number))


def fixture():
    signer = Ed25519PrivateKey.generate()
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = hashlib.sha256(raw).hexdigest()
    pin = {
        "schema": 1,
        "kind": managed.PIN_KIND,
        "registry_id": "primary",
        "authority_public_key": base64.b64encode(raw).decode("ascii"),
        "authority_key_id": fingerprint,
    }
    binding = {
        "schema": managed.BINDING_SCHEMA,
        "host_id": ident(1), "installation_id": ident(2),
        "state_volume_id": ident(3), "registry_id": "primary",
        "authority_key_id": fingerprint,
        "consumer": "host-nginx-https",
        "service_id": "candidate-nginx", "certificate_id": "station-web",
        "hostnames": ["candidate.example.org"],
        "policy_sha256": "a"*64,
        "challenge": "dns-01", "dns_mode": "local-cloudflare",
        "dns_zone": "example.org", "credential_id": "local-cloudflare",
        "credential_revision": 3,
        "contact_email": "webmaster@example.org",
        "acme_directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
    }
    assign = {
        "schema": managed.ASSIGNMENT_SCHEMA,
        "authority_origin": "command-center",
        "host_id": binding["host_id"], "installation_id": binding["installation_id"],
        "operation_id": ident(4), "revision": 7,
        "status": "approved", "approved_at": NOW - 3600,
        "revoked_at": None, "expires_at": NOW+86400,
        "certificate_id": binding["certificate_id"],
        "hostnames": binding["hostnames"],
        "contact_email": binding["contact_email"],
        "acme_directory": binding["acme_directory"],
        "challenge": binding["challenge"], "dns_mode": binding["dns_mode"],
        "dns_zone": binding["dns_zone"], "credential_id": binding["credential_id"],
        "credential_revision": binding["credential_revision"],
        "consumer": binding["consumer"],
    }
    digest = hashlib.sha256(managed._canonical(assign)).hexdigest()
    observation = {
        "schema": managed.ROOT_SCHEMA,
        "origin": "managed", "verified_by": "signed-host-discover",
        "host_id": binding["host_id"],
        "installation_id": binding["installation_id"],
        "state_volume_id": binding["state_volume_id"],
        "registry_id": pin["registry_id"],
        "authority_public_key": pin["authority_public_key"],
        "authority_key_id": fingerprint,
        "revision": assign["revision"], "operation_id": assign["operation_id"],
        "assignment_sha256": digest,
        "operations": [{"operation_id": assign["operation_id"],
                        "assignment_sha256": digest}],
        "envelope": {
            "schema": managed.ENVELOPE_SCHEMA,
            "key_id": fingerprint, "assignment": assign,
            "signature": base64.b64encode(
                signer.sign(b"zog-certificate-assignment-v1\0" +
                            managed._canonical(assign))
            ).decode("ascii"),
        },
    }
    return observation, pin, binding


def test_real_ed25519_checkpoint_yields_exact_local_receipt():
    observation, pin, binding = fixture()
    result = managed.derive_managed_owner_authority(
        observation, pin, binding, now=NOW)
    assert owner.validate(result, now=NOW) == result
    assert result["origin"] == "managed"
    assert result["service_id"] == binding["service_id"]
    assert result["policy_sha256"] == binding["policy_sha256"]
    assert result["operation_id"] == observation["operation_id"]
    assert result["revision"] == observation["revision"]
    assert result["hostnames"] == ["candidate.example.org"]
    assert result["status"] == "approved"
    assert managed.derive_managed_owner_authority(
        observation, pin, binding, now=NOW, previous=result) == result


@pytest.mark.parametrize("where,key,replacement", [
    ("binding", "host_id", ident(33)),
    ("binding", "installation_id", ident(33)),
    ("binding", "state_volume_id", ident(33)),
    ("binding", "policy_sha256", "0"*64),
    ("binding", "service_id", "another-nginx"),
    ("binding", "consumer", "station-nginx-https"),
    ("binding", "certificate_id", "foreign-cert"),
    ("binding", "hostnames", ["other.example.org"]),
    ("binding", "credential_revision", 9),
    ("binding", "acme_directory", "https://evil.example.org/directory"),
    ("binding", "contact_email", "wrong@example.org"),
    ("observation", "host_id", ident(44)),
    ("observation", "authority_key_id", "0"*64),
    ("observation", "assignment_sha256", "0"*64),
    ("observation", "revision", 6),
    ("observation", "operation_id", ident(77)),
    ("envelope", "signature", base64.b64encode(b"0"*64).decode()),
    ("envelope", "key_id", "0"*64),
    ("pin", "authority_key_id", "0"*64),
])
def test_unsigned_or_foreign_authority_cannot_select_local_consumer(where,key,replacement):
    observation, pin, binding = fixture()
    target = {"binding": binding, "observation": observation,
              "pin": pin, "envelope": observation["envelope"]}[where]
    target[key] = replacement
    with pytest.raises(owner.AuthorityBlocked):
        managed.derive_managed_owner_authority(
            observation, pin, binding, now=NOW)


def test_signed_revocation_and_expiry_never_authorize_new_delivery():
    observation, pin, binding = fixture()
    assignment = observation["envelope"]["assignment"]
    assignment["status"] = "revoked"
    assignment["revoked_at"] = NOW - 10
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pin["authority_public_key"] = base64.b64encode(raw).decode()
    pin["authority_key_id"] = hashlib.sha256(raw).hexdigest()
    binding["authority_key_id"] = pin["authority_key_id"]
    observation["authority_public_key"] = pin["authority_public_key"]
    observation["authority_key_id"] = pin["authority_key_id"]
    observation["envelope"]["key_id"] = pin["authority_key_id"]
    observation["assignment_sha256"] = hashlib.sha256(managed._canonical(assignment)).hexdigest()
    observation["operations"][0]["assignment_sha256"] = observation["assignment_sha256"]
    observation["envelope"]["signature"] = base64.b64encode(
        key.sign(b"zog-certificate-assignment-v1\0" + managed._canonical(assignment))
    ).decode()
    with pytest.raises(owner.AuthorityBlocked, match="revoked-or-expired"):
        managed.derive_managed_owner_authority(observation, pin, binding, now=NOW)
    assignment["status"] = "approved"
    assignment["revoked_at"] = None
    assignment["expires_at"] = NOW-1
    with pytest.raises(owner.AuthorityBlocked):
        managed.derive_managed_owner_authority(observation, pin, binding, now=NOW)


def test_managed_delivery_reopens_root_state_and_refuses_stale_receipt(monkeypatch):
    observation, pin, binding = fixture()
    current = managed.derive_managed_owner_authority(observation, pin, binding, now=NOW)
    expected = {
        managed.ROOT_SIGNER_PIN_PATH: pin,
        managed.ROOT_CONSUMER_BINDING_PATH: binding,
        managed.ROOT_OBSERVATION_PATH: observation,
    }
    monkeypatch.setattr(managed, "_read_root_json",
                        lambda path, *, mode, limit: expected[path])
    assert managed.verify_current_managed_receipt(current, now=NOW) == current
    with pytest.raises(owner.AuthorityBlocked, match="stale"):
        managed.verify_current_managed_receipt(
            {**current, "policy_sha256": "f"*64}, now=NOW)
    # Revoking the current root observation denies even an older approved
    # root-owned receipt; no UID-970 file or callback is consulted.
    observation["envelope"]["assignment"]["status"] = "revoked"
    with pytest.raises(owner.AuthorityBlocked):
        managed.verify_current_managed_receipt(current, now=NOW)


def test_managed_delivery_fails_closed_without_installed_root_checkpoint(monkeypatch):
    observation, pin, binding = fixture()
    from zog.host_deploy import certificate_managed_authority as m
    from zog.host_deploy import certificate_hostname_authority as a
    current = managed.derive_managed_owner_authority(
        observation, pin, binding, now=NOW)
    monkeypatch.setattr(delivery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(delivery, "policy_validate", lambda p: p)
    monkeypatch.setattr(a, "read_owned", lambda p, *, now: current)
    monkeypatch.setattr(delivery, "publish",
                        lambda *args, **kwargs: pytest.fail("nginx must not be called"))
    monkeypatch.setattr(m, "verify_current_managed_receipt",
                        lambda *args, **kwargs: (_ for _ in ()).throw(
                            a.AuthorityBlocked("root-authority-missing")))
    with pytest.raises(delivery.DeliveryBlocked, match="hostname-authority-unavailable"):
        delivery.publish_authorized(
            {"service_id": current["service_id"],
             "certificate_id": current["certificate_id"],
             "hostnames": current["hostnames"],
             "policy_sha256": current["policy_sha256"]},
            "e"*64, authority_path="/etc/zog/delivery-authority.json")
