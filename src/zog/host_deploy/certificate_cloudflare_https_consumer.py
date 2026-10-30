"""Cloudflare-only consumer of Zog's protected HTTPS credential-delivery protocol.

This is the nonsecret consumer contract, NOT a generic remote-command endpoint.
The selected native root operation must provide independently authenticated
HTTPS transport, exact signed-assignment/owner ledger snapshots, a durable
one-shot request journal, and root-control's install_from_fd handoff.

No transport, importer, issuer retry, renewal or web handler is invoked by
importing this module. No provider secret is ever returned or serialized here.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time

from .certificate_cross_host_admission import validate as validate_owner

SCHEMA = "zog-protected-credential-delivery-request-v1"
REPLY_SCHEMA = "zog-protected-credential-delivery-receipt-v1"
PURPOSE = "issuer-cloudflare-dns01"
OPERATION = "deliver-approved-credential-once"
MAX_SECONDS = 60
_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class CloudflareDeliveryBlocked(RuntimeError):
    """Fixed error, safe for logs; never interpolate secret or response data."""

    def __init__(self):
        super().__init__("cloudflare-https-delivery-not-authorized")


def _deny():
    raise CloudflareDeliveryBlocked() from None


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, UnicodeError):
        _deny()


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _valid_id(value):
    return type(value) is str and _HEX32.fullmatch(value) is not None


def prepare(*, owner, binding, ledger, delivery, authorization, projection,
            client, owner_bytes, signer_pin_bytes, now, request_id,
            installed_issuer):
    """Pure strict eligibility and fixed HTTPS request. No fetch, install, token.

    All upstream snapshots must have been independently read/verified under
    the protected root owner lock: host-discover's signature/monotonic ledger,
    host-install's second owner ledger, station authorization, and the actual
    installed issuer grant/storage/source. A bool 'verified' supplied by an
    HTTP caller is NEVER sufficient.
    """
    try:
        admission = validate_owner(
            owner, binding, ledger, delivery, authorization, projection,
            client, owner_bytes=owner_bytes,
            signer_pin_bytes=signer_pin_bytes, now=now)
        if (type(installed_issuer) is not dict
                or set(installed_issuer) != {
                    "host_id", "installation_id", "state_volume_id",
                    "registry_id", "grant_id", "storage_id", "uid", "gid",
                    "software_view", "certificate_data_path",
                    "controller_record_sha256"}
                or not _valid_id(request_id)
                or type(now) is not int or now <= 0
                or authorization["expires_at"] <= now + MAX_SECONDS
                or owner["expires_at"] <= now + MAX_SECONDS):
            _deny()
        issuer = ledger["issuer"]
        for key in ("grant_id", "storage_id", "uid", "gid", "software_view",
                    "certificate_data_path", "controller_record_sha256"):
            if installed_issuer[key] != issuer[key]:
                _deny()
        for key in ("host_id", "installation_id", "state_volume_id", "registry_id"):
            if installed_issuer[key] != binding[key]:
                _deny()
        fqdn = owner["hostnames"][0]
        zone = owner["dns_zone"]
        if fqdn == zone or not fqdn.endswith("." + zone):
            _deny()
        if (authorization["zone_name"] != zone
                or authorization["credential_revision"] != client["credential_revision"]
                or client["purpose"] != PURPOSE):
            _deny()
        request = {
            "schema": SCHEMA, "operation": OPERATION, "purpose": PURPOSE,
            "request_id": request_id, "created_at": now,
            "expires_at": min(now + MAX_SECONDS, authorization["expires_at"],
                              owner["expires_at"]),
            "host_id": owner["host_id"],
            "host_fingerprint": client["host_fingerprint"],
            "installation_id": owner["installation_id"],
            "state_volume_id": binding["state_volume_id"],
            "registry_id": binding["registry_id"],
            "certificate_id": owner["certificate_id"],
            "fqdn": fqdn, "dns_zone": zone,
            "assignment_id": authorization["assignment_id"],
            "assignment_revision": authorization["assignment_revision"],
            "assignment_receipt_sha256": authorization["receipt_sha256"],
            "credential_id": authorization["credential_id"],
            "credential_revision": authorization["credential_revision"],
            "authorization_id": admission["authorization_id"],
            "owner_authority_sha256": client["owner_authority_sha256"],
            "policy_sha256": owner["policy_sha256"],
            "nginx_delivery_policy_sha256": admission["delivery_policy_sha256"],
            "issuer_grant_id": issuer["grant_id"],
            "issuer_storage_id": issuer["storage_id"],
            "issuer_uid": issuer["uid"],
            "issuer_gid": issuer["gid"],
            "transport_origin": client["https_origin"],
            "tls_authority_pin_sha256": client["tls_authority_pin_sha256"],
        }
        return request
    except (KeyError, TypeError, AttributeError, ValueError):
        _deny()


def check_receipt(request, reply, *, now):
    """Check a NONSECRET authenticated transport receipt, never secret bytes.

    Caller MUST also prove TLS peer and signed response authenticity in the
    independent common HTTPS layer. This pure comparison is NOT that proof.
    """
    try:
        if (type(request) is not dict or request.get("schema") != SCHEMA
                or type(reply) is not dict
                or set(reply) != {
                    "schema", "status", "purpose", "request_id",
                    "request_sha256", "host_id", "installation_id",
                    "state_volume_id", "registry_id",
                    "assignment_id", "assignment_revision",
                    "credential_id", "credential_revision",
                    "issuer_grant_id", "issuer_storage_id", "issuer_uid",
                    "expires_at"}
                or reply["schema"] != REPLY_SCHEMA
                or reply["status"] != "authorized-delivery"
                or reply["purpose"] != PURPOSE
                or reply["request_id"] != request["request_id"]
                or reply["request_sha256"] != _hash(request)
                or type(now) is not int or now < request["created_at"]
                or now >= min(reply["expires_at"], request["expires_at"])):
            _deny()
        for name in ("host_id", "installation_id", "state_volume_id",
                     "registry_id", "assignment_id", "assignment_revision",
                     "credential_id", "credential_revision",
                     "issuer_grant_id", "issuer_storage_id", "issuer_uid"):
            if reply[name] != request[name]:
                _deny()
        return {"schema": REPLY_SCHEMA, "status": "nonsecret-receipt-checked",
                "request_id": request["request_id"],
                "request_sha256": _hash(request),
                "credential_revision": request["credential_revision"],
                "credential_installed": False}
    except (KeyError, ValueError, TypeError, AttributeError):
        _deny()


def deliver_selected(*args, **kwargs):
    """Retired incompatible custom-wire endpoint; NEVER call transport.

    The protected receiver now exclusively owns host-identify canonical v1,
    including signature verification, ledger, secret-FD and receipt signing.
    There is intentionally no translation from legacy wire messages.
    """
    _deny()
