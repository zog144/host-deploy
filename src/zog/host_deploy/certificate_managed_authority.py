"""Managed root checkpoint -> exact local HTTPS owner-authority receipt.

This is a *consumer*, never a station/UID-970 reader or a signing-key producer.
The host owner must install the signer pin and local consumer binding through
an independently authenticated root-only installer. Do not use a web request.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from urllib.parse import urlsplit

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
            or len(binding["acme_directory"]) > 2048):
        _deny()
    try:
        url = urlsplit(binding["acme_directory"])
        if (url.scheme != "https" or not url.hostname
                or url.username is not None or url.password is not None
                or url.port not in (None, 443) or not url.path.startswith("/")
                or url.query or url.fragment):
            _deny("managed-certificate-acme-directory-invalid")
    except ValueError:
        _deny("managed-certificate-acme-directory-invalid")
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


# These are canonical root-owner paths, not configurable web/user parameters.
# They are deliberately distinct from any UID-970 managed assignment path.
ROOT_OBSERVATION_PATH = "/state/host-discover-certificate-authority/authority.json"
ROOT_SIGNER_PIN_PATH = "/etc/zog/host-install/certificate-assignment-authority.json"
ROOT_CONSUMER_BINDING_PATH = "/etc/zog/host-deploy/certificate-managed-binding.json"
# The second monotonic owner ledger is installed by host-install, independent
# of host-discover's signed source checkpoint. Publication in progress is never
# authority for a fresh nginx generation.
ROOT_OWNER_AUTHORITY_PATH = "/state/host-install/certificate-owner-authority/authority.json"
ROOT_OWNER_LEDGER_PATH = "/state/host-install/certificate-owner-authority/ledger.json"
ROOT_OWNER_TRANSACTION_PATH = "/state/host-install/certificate-owner-authority/transaction.json"
OWNER_LEDGER_SCHEMA = "zog-host-install-certificate-owner-ledger-v1"


def _read_root_json(path, *, mode, limit, allow_missing=False):
    """Open a trusted root-owned path without symlink traversal or DAC drift."""
    if os.geteuid() != 0:
        _deny("managed-certificate-root-owner-required")
    if path not in (
        ROOT_OBSERVATION_PATH, ROOT_SIGNER_PIN_PATH, ROOT_CONSUMER_BINDING_PATH,
        ROOT_OWNER_AUTHORITY_PATH, ROOT_OWNER_LEDGER_PATH,
        ROOT_OWNER_TRANSACTION_PATH,
    ):
        _deny("managed-certificate-unreviewed-root-path")
    # Descriptor-walk every path component. Checking lstat(path) then
    # opening the full pathname would allow a directory replacement between
    # the two syscalls; O_NOFOLLOW only protects its final component.
    parts = Path(path).parts[1:]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in parts[:-1]:
            nextfd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                os.O_CLOEXEC, dir_fd=fd,
            )
            try:
                parent = os.fstat(nextfd)
                if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                        or parent.st_mode & 0o022):
                    _deny("managed-certificate-unsafe-root-ancestry")
            except BaseException:
                os.close(nextfd)
                raise
            os.close(fd)
            fd = nextfd
        try:
            desc = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
        except FileNotFoundError:
            if allow_missing and path == ROOT_OWNER_TRANSACTION_PATH:
                return None
            raise
        try:
            info = os.fstat(desc)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
                    or not 0 < info.st_size <= limit):
                _deny("managed-certificate-unsafe-root-file")
            raw = os.read(desc, limit + 1)
        finally:
            os.close(desc)
    finally:
        os.close(fd)
    if len(raw) > limit:
        _deny()
    def _unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _deny("managed-certificate-duplicate-root-field")
            result[key] = value
        return result

    def _reject_number(value):
        _deny("managed-certificate-invalid-root-number")

    try:
        result = json.loads(
            raw, object_pairs_hook=_unique_pairs, parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (TypeError, UnicodeError, ValueError, RecursionError):
        _deny("managed-certificate-malformed-root-record")
    return result


def _verified_owner_ledger(ledger, *, authority, observation, binding,
                           delivery_policy=None):
    """Fail closed on the independent installed host-install owner ledger."""
    required = {
        "schema", "installation_id", "state_volume_id", "registry_id",
        "authority_key_id", "service_id", "certificate_id", "binding_sha256",
        "delivery_policy_sha256", "issuer", "local_intent_sha256", "revision",
        "operation_id", "assignment_sha256", "owner_authority_sha256",
        "status", "operations",
    }
    if (type(ledger) is not dict or set(ledger) != required
            or ledger["schema"] != OWNER_LEDGER_SCHEMA):
        _deny("managed-certificate-owner-ledger-invalid")
    expected = {
        "installation_id": binding["installation_id"],
        "state_volume_id": binding["state_volume_id"],
        "registry_id": binding["registry_id"],
        "authority_key_id": binding["authority_key_id"],
        "service_id": binding["service_id"],
        "certificate_id": binding["certificate_id"],
        "binding_sha256": hashlib.sha256(_canonical(binding)).hexdigest(),
        "revision": authority["revision"],
        "operation_id": authority["operation_id"],
        "assignment_sha256": observation["assignment_sha256"],
        "owner_authority_sha256": hashlib.sha256(_canonical(authority)).hexdigest(),
        "status": authority["status"],
    }
    if any(ledger.get(key) != value for key, value in expected.items()):
        _deny("managed-certificate-owner-ledger-mismatch")
    for key in ("delivery_policy_sha256", "local_intent_sha256"):
        if type(ledger[key]) is not str or not _HEX.fullmatch(ledger[key]):
            _deny("managed-certificate-owner-ledger-invalid")
    issuer = ledger["issuer"]
    if (type(issuer) is not dict or set(issuer) != {
            "storage_id", "grant_id", "uid", "gid", "software_view",
            "certificate_data_path", "controller_record_sha256",
        } or type(issuer["uid"]) is not int or issuer["uid"] < 1000
          or type(issuer["gid"]) is not int or issuer["gid"] < 1000
          or type(issuer["storage_id"]) is not str
          or not re.fullmatch(r"[a-f0-9]{32}", issuer["storage_id"])
          or type(issuer["grant_id"]) is not str
          or not re.fullmatch(r"[a-f0-9]{32}", issuer["grant_id"])
          or type(issuer["software_view"]) is not str
          or not re.fullmatch(r"sha256:[a-f0-9]{64}", issuer["software_view"])
          or type(issuer["certificate_data_path"]) is not str
          or not issuer["certificate_data_path"].startswith("/")
          or type(issuer["controller_record_sha256"]) is not str
          or not _HEX.fullmatch(issuer["controller_record_sha256"])):
        _deny("managed-certificate-owner-ledger-invalid")
    operations = ledger["operations"]
    if type(operations) is not list or not 1 <= len(operations) <= 128:
        _deny("managed-certificate-owner-ledger-invalid")
    seen = set()
    last_revision = 0
    for entry in operations:
        if (type(entry) is not dict or set(entry) != {
                "revision", "operation_id", "assignment_sha256",
                "owner_authority_sha256", "status",
            } or type(entry["revision"]) is not int
                or entry["revision"] <= last_revision
                or entry["revision"] >= 2**53
                or type(entry["operation_id"]) is not str
                or entry["operation_id"] in seen
                or type(entry["assignment_sha256"]) is not str
                or not _HEX.fullmatch(entry["assignment_sha256"])
                or type(entry["owner_authority_sha256"]) is not str
                or not _HEX.fullmatch(entry["owner_authority_sha256"])
                or entry["status"] not in ("approved", "revoked")):
            _deny("managed-certificate-owner-ledger-invalid")
        _uuid(entry["operation_id"])
        if last_revision and entry["status"] == "approved" and (
                "revoked" in (x["status"] for x in operations[:len(seen)])):
            _deny("managed-certificate-owner-revocation-terminal")
        seen.add(entry["operation_id"])
        last_revision = entry["revision"]
    current = operations[-1]
    if any(current[key] != ledger[key] for key in (
            "revision", "operation_id", "assignment_sha256",
            "owner_authority_sha256", "status",
    )):
        _deny("managed-certificate-owner-ledger-invalid")
    if delivery_policy is not None:
        from .certificate_delivery import policy_validate
        policy = policy_validate(delivery_policy)
        if (hashlib.sha256(_canonical(policy)).hexdigest()
                != ledger["delivery_policy_sha256"]):
            _deny("managed-certificate-delivery-policy-ledger-mismatch")
        if (policy["issuer_uid"] != issuer["uid"]
                or policy["issuer_state"] != issuer["certificate_data_path"]):
            _deny("managed-certificate-issuer-ledger-mismatch")
    return ledger


def verify_current_managed_receipt(authority, *, now, delivery_policy=None):
    """Require a CURRENT separately signed root checkpoint before publication.

    The managed root producer retains the monotonic signed history. The
    installer remains responsible for a distinct durable *owner* history,
    including persistence and reboot; this function never writes it.
    """
    pin = _read_root_json(ROOT_SIGNER_PIN_PATH, mode=0o444, limit=2048)
    binding = _read_root_json(ROOT_CONSUMER_BINDING_PATH, mode=0o600, limit=8192)
    observed = _read_root_json(ROOT_OBSERVATION_PATH, mode=0o600, limit=65536)
    current = derive_managed_owner_authority(observed, pin, binding, now=now)
    if current != owner_validate(authority, now=now):
        _deny("managed-certificate-owner-receipt-stale")
    # The root-managed signer history and the host-install owner ledger are
    # independent. Neither a cached owner receipt nor a matching assignment
    # can bypass the installer's pending-transaction crash fence.
    ledger = _read_root_json(ROOT_OWNER_LEDGER_PATH, mode=0o600, limit=65536)
    installed = _read_root_json(ROOT_OWNER_AUTHORITY_PATH, mode=0o600, limit=8192)
    pending = _read_root_json(
        ROOT_OWNER_TRANSACTION_PATH, mode=0o600, limit=8192,
        allow_missing=True,
    )
    if pending is not None:
        _deny("managed-certificate-owner-recovery-pending")
    if installed != current:
        _deny("managed-certificate-installed-owner-mismatch")
    _verified_owner_ledger(
        ledger, authority=current, observation=observed, binding=binding,
        delivery_policy=delivery_policy,
    )
    return current
