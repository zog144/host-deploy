"""Managed root checkpoint -> exact local HTTPS owner-authority receipt.

This is a *consumer*, never a station/UID-970 reader or a signing-key producer.
The host owner must install the signer pin and local consumer binding through
an independently authenticated root-only installer. Do not use a web request.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .certificate_hostname_authority import (
    AuthorityBlocked, SCHEMA, compare_revision, validate as owner_validate,
)

ROOT_SCHEMA = "zog-host-discover-certificate-authority-observation-v1"
PIN_KIND = "zog-certificate-assignment-authority-pin"
ASSIGNMENT_SCHEMA = "zog-certificate-assignment-v1"
ENVELOPE_SCHEMA = "zog-certificate-assignment-envelope-v1"
BINDING_SCHEMA = "zog-host-deploy-managed-certificate-consumer-binding-v1"
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
ROOT_KEYS = {
    "schema", "origin", "verified_by", "host_id", "installation_id",
    "state_volume_id", "registry_id", "authority_public_key",
    "authority_key_id", "revision", "operation_id", "assignment_sha256",
    "operations", "envelope",
}
PIN_KEYS = {"schema", "kind", "registry_id", "authority_public_key",
            "authority_key_id"}
ASSIGNMENT_KEYS = {
    "schema", "authority_origin", "host_id", "installation_id",
    "operation_id", "revision", "status", "approved_at", "revoked_at",
    "expires_at", "certificate_id", "hostnames", "contact_email",
    "acme_directory", "challenge", "dns_mode", "dns_zone",
    "credential_id", "credential_revision", "consumer",
}
BINDING_KEYS = {
    "schema", "host_id", "installation_id", "state_volume_id",
    "registry_id", "authority_key_id", "consumer", "service_id",
    "certificate_id", "hostnames", "policy_sha256", "challenge",
    "dns_mode", "dns_zone", "credential_id", "credential_revision",
    "contact_email", "acme_directory",
}


def _deny(reason="managed-certificate-authority-invalid"):
    raise AuthorityBlocked(reason)


def _canonical(data):
    try:
        return json.dumps(data, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _deny()


def _uuid(value):
    if type(value) is not str or not _UUID.fullmatch(value):
        _deny()
    try:
        if str(uuid.UUID(value)) != value:
            _deny()
    except (ValueError, TypeError):
        _deny()
    return value


def _identity(value):
    if type(value) is not str or not _ID.fullmatch(value):
        _deny()
    return value


def _pin(pin):
    if (type(pin) is not dict or set(pin) != PIN_KEYS
            or type(pin["schema"]) is not int or pin["schema"] != 1
            or pin["kind"] != PIN_KIND):
        _deny()
    _identity(pin["registry_id"])
    if type(pin["authority_key_id"]) is not str or not _HEX.fullmatch(pin["authority_key_id"]):
        _deny()
    try:
        raw = base64.b64decode(pin["authority_public_key"], validate=True)
        if (len(raw) != 32 or base64.b64encode(raw).decode("ascii")
                != pin["authority_public_key"]):
            _deny()
        pub = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError):
        _deny()
    if hashlib.sha256(raw).hexdigest() != pin["authority_key_id"]:
        _deny("managed-certificate-signer-pin-mismatch")
    return pub


def _valid_binding(binding):
    if (type(binding) is not dict or set(binding) != BINDING_KEYS
            or binding["schema"] != BINDING_SCHEMA):
        _deny()
    for field in ("host_id", "installation_id", "state_volume_id"):
        _uuid(binding[field])
    for field in ("registry_id", "consumer", "service_id", "certificate_id"):
        _identity(binding[field])
    if (binding["consumer"] != "host-nginx-https"
            or type(binding["authority_key_id"]) is not str
            or not _HEX.fullmatch(binding["authority_key_id"])
            or type(binding["policy_sha256"]) is not str
            or not _HEX.fullmatch(binding["policy_sha256"])):
        _deny()
    # An independent local binding may not enable a different ACME directory,
    # challenge mode, DNS credential or hostname merely because it was signed.
    if (type(binding["contact_email"]) is not str
            or len(binding["contact_email"]) > 254
            or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", binding["contact_email"])
            or type(binding["acme_directory"]) is not str
            or not binding["acme_directory"].startswith("https://")):
        _deny()
    # Use owner receipt schema for canonical hostname, challenge and credential
    # validation; no need to trust a browser-selected file or loose source list.
    probe = {**binding, "origin": "managed", "verified_by": "signed-host-discover",
             "operation_id": "00000000-0000-0000-0000-000000000001",
             "revision": 1, "status": "approved", "approved_at": 1,
             "expires_at": 100, "revoked_at": None}
    probe = {k: v for k, v in probe.items() if k not in {
        "state_volume_id", "registry_id", "authority_key_id", "consumer",
        "contact_email", "acme_directory"}}
    probe["schema"] = SCHEMA
    owner_validate(probe)
    return binding


def derive_managed_owner_authority(
    observation, pin, binding, *, now, previous=None,
):
    """Return an approved/revoked local receipt ONLY from root-proven source.

    Caller has already opened all three files from root-owned protected
    paths. The resulting owner receipt is *not* installed here; host-install
    owns atomic publication and a separate monotonic owner ledger.
    """
    if type(now) not in (int, float) or now <= 0:
        _deny()
    pub = _pin(pin)
    local = _valid_binding(binding)
    if (type(observation) is not dict or set(observation) != ROOT_KEYS
            or observation["schema"] != ROOT_SCHEMA
            or observation["origin"] != "managed"
            or observation["verified_by"] != "signed-host-discover"):
        _deny()
    for key in ("host_id", "installation_id", "state_volume_id", "registry_id",
                "authority_key_id"):
        if observation[key] != local[key]:
            _deny("managed-certificate-installation-mismatch")
    for key in PIN_KEYS - {"kind", "schema"}:
        if observation[key] != pin[key]:
            _deny("managed-certificate-signer-pin-mismatch")
    if type(observation["assignment_sha256"]) is not str or not _HEX.fullmatch(
            observation["assignment_sha256"]):
        _deny()
    if (type(observation["revision"]) is not int
            or not 1 <= observation["revision"] < 2**53):
        _deny()
    _uuid(observation["operation_id"])
    operations = observation["operations"]
    if type(operations) is not list or not 1 <= len(operations) <= 128:
        _deny()
    seen = set()
    current = False
    for entry in operations:
        if type(entry) is not dict or set(entry) != {"operation_id", "assignment_sha256"}:
            _deny()
        ident = _uuid(entry["operation_id"])
        if (ident in seen or type(entry["assignment_sha256"]) is not str
                or not _HEX.fullmatch(entry["assignment_sha256"])):
            _deny()
        seen.add(ident)
        if ident == observation["operation_id"]:
            current = entry["assignment_sha256"] == observation["assignment_sha256"]
    if not current:
        _deny("managed-certificate-root-history-mismatch")
    envelope = observation["envelope"]
    if (type(envelope) is not dict
            or set(envelope) != {"schema", "key_id", "assignment", "signature"}
            or envelope["schema"] != ENVELOPE_SCHEMA
            or envelope["key_id"] != pin["authority_key_id"]):
        _deny()
    assignment = envelope["assignment"]
    if (type(assignment) is not dict or set(assignment) != ASSIGNMENT_KEYS
            or assignment["schema"] != ASSIGNMENT_SCHEMA
            or assignment["authority_origin"] != "command-center"):
        _deny()
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        if (len(signature) != 64 or base64.b64encode(signature).decode()
                != envelope["signature"]):
            _deny()
        pub.verify(signature, b"zog-certificate-assignment-v1\0" + _canonical(assignment))
    except (InvalidSignature, ValueError, TypeError):
        _deny("managed-certificate-assignment-signature-invalid")
    if hashlib.sha256(_canonical(assignment)).hexdigest() != observation["assignment_sha256"]:
        _deny("managed-certificate-assignment-digest-mismatch")
    for key in ("host_id", "installation_id", "operation_id", "revision"):
        if assignment[key] != observation[key]:
            _deny("managed-certificate-assignment-identity-mismatch")
    for key in ("consumer", "certificate_id", "hostnames", "challenge",
                "dns_mode", "dns_zone", "credential_id",
                "credential_revision", "contact_email", "acme_directory"):
        if assignment[key] != local[key]:
            _deny("managed-certificate-local-policy-mismatch")
    if (assignment["status"] not in ("approved", "revoked")
            or type(assignment["approved_at"]) is not int
            or type(assignment["expires_at"]) is not int
            or assignment["approved_at"] <= 0
            or assignment["approved_at"] > now + 300
            or assignment["expires_at"] <= assignment["approved_at"]
            or assignment["expires_at"] - assignment["approved_at"] > 31*86400
            or (assignment["status"] == "approved"
                and assignment["revoked_at"] is not None)
            or (assignment["status"] == "revoked"
                and (type(assignment["revoked_at"]) is not int
                     or assignment["revoked_at"] < assignment["approved_at"]))):
        _deny()
    receipt = {
        "schema": SCHEMA, "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": local["host_id"],
        "installation_id": local["installation_id"],
        "operation_id": observation["operation_id"],
        "revision": observation["revision"],
        "status": assignment["status"],
        "approved_at": assignment["approved_at"],
        "expires_at": assignment["expires_at"],
        "revoked_at": assignment["revoked_at"],
        "certificate_id": local["certificate_id"],
        "service_id": local["service_id"],
        "hostnames": list(local["hostnames"]),
        "policy_sha256": local["policy_sha256"],
        "challenge": local["challenge"],
        "dns_mode": local["dns_mode"],
        "dns_zone": local["dns_zone"],
        "credential_id": local["credential_id"],
        "credential_revision": local["credential_revision"],
    }
    result = owner_validate(receipt)
    if previous is not None:
        compare_revision(previous, result)
    # Revocation/expiry are *observed* but never authorized to deliver.
    if (result["status"] != "approved" or result["expires_at"] <= now):
        _deny("managed-certificate-authority-revoked-or-expired")
    return result
