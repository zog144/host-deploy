"""Nonsecret host-owner policy adapter for CANONICAL credential-delivery v1.

This module does not fetch/decrypt secrets, construct a competing wire format,
create keys, write a journal, or grant issuer execution. The root-control
receiver owns RFC9421 signing, authenticated HTTPS, private FD installation,
durable one-shot ledger and HostIdentity installation/cancellation receipts.
"""
from __future__ import annotations

import hashlib
import json
import re

from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures

from .certificate_cross_host_admission import validate as validate_owner

PROTOCOL_SOURCE = "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
PROTOCOL_BLOB = "02332127defe565e00e398b71ada50d5c2bdd4d6"
PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"
PATH = "/.well-known/zog/credential-delivery/v1"
RECEIPT_PATH = PATH + "/receipt"
CANCEL_PATH = PATH + "/cancel"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class CanonicalCloudflareBlocked(ValueError):
    def __init__(self):
        super().__init__("canonical-cloudflare-owner-policy-denied")


def _deny():
    raise CanonicalCloudflareBlocked() from None


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _deny()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def verify_owner_binding(*, owner, binding, ledger, delivery, authorization,
                         projection, client, owner_bytes, signer_pin_bytes,
                         issuer, profile, authority_pin_bytes,
                         signed_authorization, protocol_ledger, now):
    """Require BOTH local certificate authority and signed Credential Authority.

    All file bytes and the installed pin must be independently read from
    protected root-owned paths under the host-install/root-control lock;
    caller-provided dictionaries alone are never native authorization.
    """
    try:
        legacy = validate_owner(
            owner, binding, ledger, delivery, authorization, projection, client,
            owner_bytes=owner_bytes, signer_pin_bytes=signer_pin_bytes, now=now)
        _exact(issuer, {
            "host_id","installation_id","state_volume_id","registry_id",
            "grant_id","storage_id","uid","gid","software_view",
            "certificate_data_path","controller_record_sha256"})
        for key in ("host_id","installation_id","state_volume_id","registry_id"):
            if issuer[key] != binding[key]:
                _deny()
        for key in ("grant_id","storage_id","uid","gid","software_view",
                    "certificate_data_path","controller_record_sha256"):
            if issuer[key] != ledger["issuer"][key]:
                _deny()
        # Root-control's independent profile is NOT made authoritative by
        # being passed as JSON. The native installer must attest its bytes.
        required = {
            "schema","project","https_origin","tls_authority_pin_sha256",
            "station_signer_pin_sha256","owner_authority_sha256",
            "host_id","host_fingerprint","installation_id","state_volume_id",
            "registry_id","authorization_id","assignment_id",
            "assignment_revision","receipt_sha256","purpose",
            "credential_revision","grant_id","storage_id","consumer_uid",
            "delivery_credential_id","credential_authorization_id",
            "credential_authorization_revision","credential_authority_pin_sha256"}
        _exact(profile, required)
        if profile["schema"] != "zog-issuer-https-credential-client-v1":
            _deny()
        for key, expected in {
            "project": authorization["project"],
            "https_origin": client["https_origin"],
            "tls_authority_pin_sha256": client["tls_authority_pin_sha256"],
            "station_signer_pin_sha256": client["station_signer_pin_sha256"],
            "owner_authority_sha256": client["owner_authority_sha256"],
            "host_id": owner["host_id"],
            "host_fingerprint": client["host_fingerprint"],
            "installation_id": owner["installation_id"],
            "state_volume_id": binding["state_volume_id"],
            "registry_id": binding["registry_id"],
            "authorization_id": legacy["authorization_id"],
            "assignment_id": authorization["assignment_id"],
            "assignment_revision": authorization["assignment_revision"],
            "receipt_sha256": authorization["receipt_sha256"],
            "purpose": PURPOSE,
            "credential_revision": authorization["credential_revision"],
            "grant_id": issuer["grant_id"],
            "storage_id": issuer["storage_id"],
            "consumer_uid": issuer["uid"],
            "delivery_credential_id": owner["credential_id"],
        }.items():
            if profile.get(key) != expected:
                _deny()
        if type(authority_pin_bytes) is not bytes or not authority_pin_bytes:
            _deny()
        if (hashlib.sha256(authority_pin_bytes).hexdigest() !=
                profile["credential_authority_pin_sha256"]):
            _deny()
        pin = json.loads(authority_pin_bytes, object_pairs_hook=_pairs)
        _exact(pin, {"schema","registry_id","authority_public_key",
                     "authority_key_id"})
        if (pin["schema"] != "zog-credential-authority-pin-v1"
                or pin["registry_id"] != binding["registry_id"]):
            _deny()
        key = signatures.public_key(pin["authority_public_key"])
        if signatures.fingerprint(key) != pin["authority_key_id"]:
            _deny()
        expected_binding = {
            "host_id": owner["host_id"],
            "host_fingerprint": profile["host_fingerprint"],
            "installation_id": owner["installation_id"],
            "state_volume_id": binding["state_volume_id"],
            "registry_id": binding["registry_id"],
            "consumer": CONSUMER, "purpose": PURPOSE,
            "credential_id": profile["delivery_credential_id"],
        }
        signed = cd.verify_authorization(
            signed_authorization, key, expected_issuer=profile["https_origin"],
            expected_binding=expected_binding, now=now)
        if (signed["status"] != "approved"
                or signed["authorization_id"] != profile["credential_authorization_id"]
                or signed["revision"] != profile["credential_authorization_revision"]
                or signed["credential_revision"] != owner["credential_revision"]
                or not signed["credential_id"].startswith("cloudflare-")):
            _deny()
        cd.validate_ledger(protocol_ledger)
        if cd.advance_authorization(protocol_ledger, signed) != protocol_ledger:
            _deny()
        return {"authorization": signed, "authority_key": key,
                "owner_policy_sha256": owner["policy_sha256"],
                "nginx_delivery_policy_sha256": legacy["delivery_policy_sha256"],
                "issuer_grant_id": issuer["grant_id"],
                "issuer_storage_id": issuer["storage_id"],
                "issuer_uid": issuer["uid"],
                "issuer_gid": issuer["gid"],
                "assignment_revision": authorization["assignment_revision"],
                "credential_revision": authorization["credential_revision"]}
    except Exception:
        _deny()


def _pairs(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            _deny()
        values[key] = value
    return values


def plan_selected(*, reviewed, protocol_ledger, request_id, now,
                  action="deliver", previous_delivery_id=None):
    """Build only host-identify v1 canonical request and pending ledger.

    The resulting ledger MUST be durably committed by the protected native
    root owner BEFORE signing or sending the request. Returning a candidate
    ledger is not an installed or persisted receipt.
    """
    try:
        authorization = reviewed["authorization"]
        if (action not in ("deliver","renew") or type(now) is not int
                or type(request_id) is not str):
            _deny()
        request = {
            "schema": cd.REQUEST_SCHEMA, **cd.binding(authorization),
            "credential_revision": authorization["credential_revision"],
            "authorization_id": authorization["authorization_id"],
            "authorization_revision": authorization["revision"],
            "request_id": request_id, "action": action,
            "previous_delivery_id": previous_delivery_id,
            "created_at": now, "expires_at": now + 60,
        }
        cd.validate_request(request, authorization, now=now)
        if any(row["request_id"] == request_id
               for row in protocol_ledger["requests"]):
            _deny()  # no automatic replay on an uncertain operation
        candidate = cd.admit_request(protocol_ledger, request)
        return request, candidate
    except Exception:
        _deny()


def verify_native_installation(*, reviewed, request, delivery_metadata,
                               receipt, protocol_ledger, issuer_install,
                               now):
    """Validate a root-control verified, secret-free installation result.

    The HostIdentity signer and RFC9421 receipt are root-control's native
    responsibility. This function never signs a receipt or reads a token.
    """
    try:
        auth = reviewed["authorization"]
        cd.validate_request(request, auth, now=now)
        if not isinstance(delivery_metadata, dict) or "secret" in delivery_metadata:
            _deny()
        if (set(delivery_metadata) != {
                "schema","request_id","delivery_id","authorization_id",
                "authorization_revision","credential_id","credential_revision",
                "consumer","purpose","issued_at","expires_at"}):
            _deny()
        if (delivery_metadata["schema"] != cd.DELIVERY_SCHEMA
                or delivery_metadata["request_id"] != request["request_id"]
                or any(delivery_metadata[field] != request[field]
                       for field in ("authorization_id","authorization_revision",
                                     "credential_id","credential_revision",
                                     "consumer","purpose"))):
            _deny()
        # Root-control must have already verified the *signed* delivery and
        # persisted the delivered phase; no unsigned delivery is admitted.
        if (type(issuer_install) is not dict
                or issuer_install.get("schema") !=
                    "zog-issuer-cloudflare-installation-v1"
                or issuer_install.get("status") != "installed"
                or issuer_install.get("assignment_revision") !=
                    reviewed["assignment_revision"]
                or issuer_install.get("credential_revision") !=
                    request["credential_revision"]):
            _deny()
        cd.validate_receipt(receipt, request, delivery_metadata, now=now)
        candidate = cd.record_installation(protocol_ledger, receipt)
        return {"schema": cd.RECEIPT_SCHEMA,
                "status": "nonsecret-installation-validated",
                "request_id": request["request_id"],
                "delivery_id": delivery_metadata["delivery_id"],
                "receipt_id": receipt["receipt_id"],
                "next_ledger": candidate,
                "credential_installed_native": False}
    except Exception:
        _deny()
