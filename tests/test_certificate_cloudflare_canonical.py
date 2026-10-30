"""Canonical host-identify v1 owner-policy interoperability; zero real secrets."""
import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures
from zog.host_deploy.certificate_cloudflare_canonical import (
    CanonicalCloudflareBlocked, PROTOCOL_SOURCE, PURPOSE, CONSUMER, PATH,
    verify_owner_binding, plan_selected, verify_native_installation,
)
from test_certificate_cross_host_admission import sample, uuidn, NOW

def fixture():
    x = sample()
    issuer = x["ledger"]["issuer"]
    installed = {k: issuer[k] for k in (
        "grant_id","storage_id","uid","gid","software_view",
        "certificate_data_path","controller_record_sha256")}
    for k in ("host_id","installation_id","state_volume_id","registry_id"):
        installed[k] = x["binding"][k]
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    raw_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    pin = {
        "schema": "zog-credential-authority-pin-v1",
        "registry_id": x["binding"]["registry_id"],
        "authority_public_key": base64.b64encode(raw_key).decode(),
        "authority_key_id": signatures.fingerprint(key.public_key()),
    }
    raw_pin = json.dumps(pin, sort_keys=True, separators=(",", ":")).encode()
    auth = {
        "schema": cd.AUTHORIZATION_SCHEMA, "issuer": x["client"]["https_origin"],
        "host_id": x["owner"]["host_id"],
        "host_fingerprint": x["client"]["host_fingerprint"],
        "installation_id": x["owner"]["installation_id"],
        "state_volume_id": x["binding"]["state_volume_id"],
        "registry_id": x["binding"]["registry_id"],
        "consumer": CONSUMER, "purpose": PURPOSE,
        "credential_id": x["owner"]["credential_id"],
        "credential_revision": x["owner"]["credential_revision"],
        "authorization_id": uuidn(40), "revision": 2, "status": "approved",
        "approved_at": NOW-1, "revoked_at": None, "expires_at": NOW+1000,
    }
    profile = {
        "schema": "zog-issuer-https-credential-client-v1",
        "project": x["authorization"]["project"],
        "https_origin": x["client"]["https_origin"],
        "tls_authority_pin_sha256": x["client"]["tls_authority_pin_sha256"],
        "station_signer_pin_sha256": x["client"]["station_signer_pin_sha256"],
        "owner_authority_sha256": x["client"]["owner_authority_sha256"],
        "host_id": x["owner"]["host_id"],
        "host_fingerprint": x["client"]["host_fingerprint"],
        "installation_id": x["owner"]["installation_id"],
        "state_volume_id": x["binding"]["state_volume_id"],
        "registry_id": x["binding"]["registry_id"],
        "authorization_id": x["client"]["authorization_id"],
        "assignment_id": x["authorization"]["assignment_id"],
        "assignment_revision": x["authorization"]["assignment_revision"],
        "receipt_sha256": x["authorization"]["receipt_sha256"],
        "purpose": PURPOSE,
        "credential_revision": auth["credential_revision"],
        "grant_id": issuer["grant_id"], "storage_id": issuer["storage_id"],
        "consumer_uid": issuer["uid"],
        "delivery_credential_id": auth["credential_id"],
        "credential_authorization_id": auth["authorization_id"],
        "credential_authorization_revision": auth["revision"],
        "credential_authority_pin_sha256": hashlib.sha256(raw_pin).hexdigest(),
    }
    fields = {k:x[k] for k in (
        "owner","binding","ledger","delivery","authorization",
        "projection","client","owner_bytes","signer_pin_bytes")}
    fields.update(issuer=installed, profile=profile,
                  authority_pin_bytes=raw_pin,
                  signed_authorization=cd.sign_authorization(auth,key),
                  protocol_ledger=cd.new_ledger(auth), now=NOW)
    return fields, auth


def test_signed_owner_policy_and_canonical_request():
    fields, a = fixture()
    reviewed = verify_owner_binding(**fields)
    assert reviewed["authorization"] == a
    request, next_state = plan_selected(
        reviewed=reviewed, protocol_ledger=fields["protocol_ledger"],
        request_id=uuidn(55), now=NOW)
    assert request["schema"] == cd.REQUEST_SCHEMA
    assert request["consumer"] == "certify-manage"
    assert request["purpose"] == "issuer-cloudflare-dns01"
    assert request["request_id"] == uuidn(55)
    assert set(request) == set(cd._BINDING_FIELDS) | {
        "schema","credential_revision","authorization_id",
        "authorization_revision","request_id","action",
        "previous_delivery_id","created_at","expires_at"}
    assert next_state["requests"][0]["status"] == "pending"
    assert all("secret" not in str(row).lower() for row in next_state["requests"])
    assert PROTOCOL_SOURCE == "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
    assert PATH == "/.well-known/zog/credential-delivery/v1"


@pytest.mark.parametrize("part,key,value",[
    ("owner","credential_revision",6),
    ("owner","dns_zone","foreign.org"),
    ("authorization","credential_revision",8),
    ("profile","host_fingerprint","0"*64),
    ("profile","credential_authorization_id",uuidn(77)),
    ("profile","credential_authorization_revision",7),
    ("profile","credential_authority_pin_sha256","0"*64),
    ("profile","issuer_uid",0),  # extra field not allowed
    ("issuer","uid",0),
    ("client","https_origin","http://station.example.org"),
])
def test_independent_source_or_policy_drift_fails_closed(part,key,value):
    fields, a = fixture()
    fields[part][key] = value
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_owner_binding(**fields)


def test_replaced_authority_signature_revocation_or_ledger_rollback_fails():
    fields, a = fixture()
    changed = copy.deepcopy(fields)
    changed["signed_authorization"]["signature"] = "invalid"
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_owner_binding(**changed)
    changed = copy.deepcopy(fields)
    changed["signed_authorization"]["authorization"]["status"] = "revoked"
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_owner_binding(**changed)
    changed = copy.deepcopy(fields)
    changed["protocol_ledger"]["authorization_revision"] = 9
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_owner_binding(**changed)


def test_pending_request_never_reused_as_an_automatic_retry():
    fields, a = fixture()
    reviewed = verify_owner_binding(**fields)
    req, state = plan_selected(
        reviewed=reviewed, protocol_ledger=fields["protocol_ledger"],
        request_id=uuidn(55), now=NOW)
    with pytest.raises(CanonicalCloudflareBlocked):
        plan_selected(reviewed=reviewed, protocol_ledger=state,
                      request_id=uuidn(55), now=NOW)
    with pytest.raises(CanonicalCloudflareBlocked):
        plan_selected(reviewed=reviewed, protocol_ledger=state,
                      request_id=uuidn(56), now=NOW)


def test_installation_receipt_requires_root_native_result_and_delivered_state():
    fields, a = fixture()
    reviewed = verify_owner_binding(**fields)
    req, pending = plan_selected(
        reviewed=reviewed, protocol_ledger=fields["protocol_ledger"],
        request_id=uuidn(55), now=NOW)
    public = {
        "schema": cd.DELIVERY_SCHEMA,
        "request_id": req["request_id"], "delivery_id": uuidn(56),
        "authorization_id": req["authorization_id"],
        "authorization_revision": req["authorization_revision"],
        "credential_id": req["credential_id"],
        "credential_revision": req["credential_revision"],
        "consumer": CONSUMER, "purpose": PURPOSE,
        "issued_at": NOW, "expires_at": NOW+60}
    receipt = {
        "schema": cd.RECEIPT_SCHEMA, **cd.binding(req),
        "credential_revision": req["credential_revision"],
        "authorization_id": req["authorization_id"],
        "authorization_revision": req["authorization_revision"],
        "request_id": req["request_id"],
        "delivery_id": public["delivery_id"], "receipt_id": uuidn(57),
        "outcome": "installed", "installed_at": NOW+2}
    issuer = {"schema": "zog-issuer-cloudflare-installation-v1",
              "status": "installed",
              "credential_revision": req["credential_revision"],
              "assignment_revision": fields["authorization"]["assignment_revision"]}
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_native_installation(
            reviewed=reviewed, request=req, delivery_metadata=public,
            receipt=receipt, protocol_ledger=pending, issuer_install=issuer,
            now=NOW+2)
    delivered = cd.record_delivery(pending, public)
    out = verify_native_installation(
        reviewed=reviewed, request=req, delivery_metadata=public,
        receipt=receipt, protocol_ledger=delivered, issuer_install=issuer,
        now=NOW+2)
    assert out["next_ledger"]["requests"][0]["status"] == "installed"
    assert out["credential_installed_native"] is False
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_native_installation(
            reviewed=reviewed, request=req,
            delivery_metadata={**public,"secret":"DO-NOT-LOG"},
            receipt=receipt, protocol_ledger=delivered, issuer_install=issuer,
            now=NOW+2)
    with pytest.raises(CanonicalCloudflareBlocked):
        verify_native_installation(
            reviewed=reviewed, request=req, delivery_metadata=public,
            receipt=receipt, protocol_ledger=delivered,
            issuer_install={**issuer,"assignment_revision":999},now=NOW+2)


def test_exact_station_public_vector_signature_and_byte_identity():
    """Same unchanged station-access PR #10 fixture, same host-identify source."""
    from pathlib import Path
    vector = Path("dependencies/station-access/tests/host_registry/fixtures/credential-delivery-v1-vector.json")
    v = json.loads(vector.read_text())
    host = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["host_seed_hex"]))
    authority = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["authority_seed_hex"]))
    assert cd.digest(v["authorization"]) == v["authorization_sha256"]
    assert cd.digest(v["request"]) == v["request_sha256"]
    assert cd.digest(v["delivery"]) == v["delivery_sha256"]
    assert (cd.sign_authorization(v["authorization"], authority)["signature"]
            == v["authorization_signature_base64"])
    assert (cd.sign_delivery(v["delivery"], authority)["signature"]
            == v["delivery_signature_base64"])
    a = cd.verify_authorization(
        cd.sign_authorization(v["authorization"], authority),
        authority.public_key(), expected_issuer=v["origin"],
        expected_binding=cd.binding(v["authorization"]), now=v["time"])
    assert a["consumer"] == CONSUMER and a["purpose"] == PURPOSE
    from time import time
    current = int(time())
    fresh_authorization = {**a, "approved_at": current-10,
                           "expires_at": current+3600}
    fresh_request = {**v["request"], "created_at": current,
                     "expires_at": current+60}
    prepared = cd.prepare_request(
        v["origin"]+v["request_path"], fresh_request,
        fresh_authorization, host, nonce="A"*24)
    decoded, nonce, _ = cd.verify_request_http(
        prepared.url, "POST", dict(prepared.headers),
        prepared.body, host.public_key(), fresh_authorization, now=current)
    assert decoded == fresh_request
    assert prepared.body == cd.canonical(fresh_request)
    assert nonce == "A"*24
    # The host-deploy owner-policy adapter processes only public metadata,
    # never the signed delivery envelope's secret or its reusable hash.
