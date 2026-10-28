"""Pure, nonsecret, host-owner gate for a separately provisioned issuer bridge.

Cannot retrieve credentials or authorize SSH/Certbot. The root installer must
read each input through the protected root file-descriptor and installed-byte
gates, under the same owner lock, both before and after transfer.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .certificate_hostname_authority import validate as validate_owner

SCHEMA = "zog-host-deploy-cross-host-issuer-admission-v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
ROOT = "zog-issuer-cloudflare-credential-v1"
CLIENT = "zog-issuer-cross-host-client-v1"
PROJECTION = "zog-station-issuer-reader-authorization-v1"
LEDGER = "zog-host-install-certificate-owner-ledger-v1"
BINDING = "zog-host-deploy-managed-certificate-consumer-binding-v1"


class CredentialAdmissionBlocked(ValueError):
    """A fixed nonsecret denial, never output any credential or SSH material."""


def _deny():
    raise CredentialAdmissionBlocked("cross-host-issuer-admission-unavailable") from None


def _hash(value):
    try:
        return hashlib.sha256(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("ascii")).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        _deny()


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _deny()


def validate(owner, binding, ledger, delivery, authorization, projection, client,
             *, owner_bytes, signer_pin_bytes, now):
    """Require every independent owner/projection/policy identity to agree.

    This is *one* preflight input to root-control's existing privileged
    issuer_credentials install_from_fd; it does not install or copy a token.
    """
    try:
        if type(now) is not int or now <= 0:
            _deny()
        owner = validate_owner(owner, now=now)
        if (owner["origin"] != "managed"
                or owner["verified_by"] != "signed-host-discover"
                or owner["challenge"] != "dns-01"
                or owner["dns_mode"] != "local-cloudflare"
                or len(owner["hostnames"]) != 1):
            _deny()
        _exact(binding, (
            "schema host_id installation_id state_volume_id registry_id "
            "authority_key_id consumer service_id certificate_id hostnames "
            "policy_sha256 challenge dns_mode dns_zone credential_id "
            "credential_revision contact_email acme_directory").split())
        if binding["schema"] != BINDING or binding["consumer"] != "host-nginx-https":
            _deny()
        for key in ("host_id", "installation_id", "service_id",
                    "certificate_id", "hostnames", "policy_sha256", "challenge",
                    "dns_mode", "dns_zone", "credential_id", "credential_revision"):
            if binding[key] != owner[key]:
                _deny()
        _exact(ledger, (
            "schema installation_id state_volume_id registry_id authority_key_id "
            "service_id certificate_id binding_sha256 delivery_policy_sha256 "
            "issuer local_intent_sha256 revision operation_id assignment_sha256 "
            "owner_authority_sha256 status operations").split())
        if (ledger["schema"] != LEDGER or ledger["status"] != "approved"
                or ledger["revision"] != owner["revision"]
                or ledger["operation_id"] != owner["operation_id"]
                or ledger["owner_authority_sha256"] != _hash(owner)
                or ledger["binding_sha256"] != _hash(binding)
                or ledger["delivery_policy_sha256"] != _hash(delivery)):
            _deny()
        for key in ("installation_id", "state_volume_id", "registry_id",
                    "authority_key_id", "service_id", "certificate_id"):
            if ledger[key] != binding[key]:
                _deny()
        issuer = ledger["issuer"]
        _exact(issuer, (
            "storage_id grant_id uid gid software_view certificate_data_path "
            "controller_record_sha256").split())
        if (type(issuer["uid"]) is not int or issuer["uid"] < 1000
                or type(issuer["gid"]) is not int or issuer["gid"] < 1000):
            _deny()
        if (delivery.get("service_id") != owner["service_id"]
                or delivery.get("certificate_id") != owner["certificate_id"]
                or delivery.get("hostnames") != owner["hostnames"]
                or delivery.get("policy_sha256") != owner["policy_sha256"]
                or delivery.get("issuer_uid") != issuer["uid"]
                or delivery.get("peer_uid") != issuer["uid"]
                or delivery.get("issuer_state") != issuer["certificate_data_path"]):
            _deny()
        _exact(authorization, (
            "schema state project certificate_id assignment_id assignment_revision "
            "credential_id credential_revision zone_id zone_name grant_id storage_id "
            "policy_sha256 receipt_sha256 expires_at").split())
        if (authorization["schema"] != ROOT or authorization["state"] != "approved"
                or authorization["certificate_id"] != owner["certificate_id"]
                or type(authorization["expires_at"]) is not int
                or authorization["expires_at"] <= now
                or type(authorization["assignment_revision"]) is not int
                or authorization["assignment_revision"] < 1
                or type(authorization["credential_revision"]) is not int
                or authorization["credential_revision"] != owner["credential_revision"]
                or type(authorization["credential_id"]) is not str
                or UUID.fullmatch(authorization["credential_id"]) is None
                or owner["credential_id"] !=
                   "cloudflare-" + authorization["credential_id"].replace("-", "")
                or authorization["zone_name"] != owner["dns_zone"]
                or authorization["policy_sha256"] != owner["policy_sha256"]
                or authorization["grant_id"] != issuer["grant_id"]
                or authorization["storage_id"] != issuer["storage_id"]):
            _deny()
        for key in ("receipt_sha256", "policy_sha256"):
            if type(authorization[key]) is not str or HEX.fullmatch(authorization[key]) is None:
                _deny()
        _exact(projection, (
            "schema authorization origin installation_id host_id account_id "
            "owner_user_id").split())
        if (projection["schema"] != PROJECTION
                or projection["authorization"] != authorization
                or projection["origin"] != "managed"
                or projection["host_id"] != owner["host_id"]
                or projection["installation_id"] != owner["installation_id"]):
            _deny()
        _exact(client, (
            "schema project authorization_id host_id installation_id state_volume_id "
            "host_fingerprint registry_id assignment_id assignment_revision "
            "receipt_sha256 ssh_host ssh_port ssh_user ssh_identity ssh_known_hosts "
            "ssh_known_hosts_sha256 owner_authority_sha256 station_signer_pin_sha256").split())
        if (client["schema"] != CLIENT
                or client["project"] != authorization["project"]
                or client["authorization_id"] != _hash(authorization)
                or client["assignment_id"] != authorization["assignment_id"]
                or client["assignment_revision"] != authorization["assignment_revision"]
                or client["receipt_sha256"] != authorization["receipt_sha256"]
                or client["host_id"] != owner["host_id"]
                or client["installation_id"] != owner["installation_id"]
                or client["state_volume_id"] != binding["state_volume_id"]
                or client["registry_id"] != binding["registry_id"]
                or type(client["host_fingerprint"]) is not str
                or HEX.fullmatch(client["host_fingerprint"]) is None
                or type(owner_bytes) is not bytes or not owner_bytes
                or type(signer_pin_bytes) is not bytes or not signer_pin_bytes
                or hashlib.sha256(owner_bytes).hexdigest() != client["owner_authority_sha256"]
                or hashlib.sha256(signer_pin_bytes).hexdigest() != client["station_signer_pin_sha256"]):
            _deny()
        return {
            "schema": SCHEMA, "status": "source-bound-nonsecret-admission",
            "host_id": owner["host_id"],
            "installation_id": owner["installation_id"],
            "owner_revision": owner["revision"],
            "credential_revision": authorization["credential_revision"],
            "authorization_id": _hash(authorization),
            "delivery_policy_sha256": _hash(delivery),
            "installed_bytes_verified": False,
            "credential_transferred": False,
        }
    except (KeyError, TypeError, ValueError, AttributeError):
        _deny()
