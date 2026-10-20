"""Review-gated short-lived selected inspection coordinator.

This code deliberately has NO production CLI and NO host journal reader.
A controller-owned fixed broker must add 'inspect' and a privileged
invocation-scoped structured evidence reader before it can be enabled.
Its request identity is always distinct from the original renewal ID.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import re

from .certificate_renewal import (
    _binding, _canonical, _load, _locked, _value, HEX, REQUEST_ID,
    RenewalBlocked,
)

SCHEMA = "zog-host-deploy-selected-inspect-v1"
EVIDENCE_SCHEMA = "zog-controller-selected-inspect-evidence-v1"  # legacy fixture
TRUSTED_SCHEMA = "zog-trusted-issuer-inspection-v1"
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_UUID32 = re.compile(r"[0-9a-f]{32}\Z")
STATES = {"issued", "submitted", "awaiting-evidence", "verified", "blocked"}
_RECORD = "selected-inspection.json"


def _timestamp(value):
    if type(value) is not str or len(value) > 80:
        raise RenewalBlocked("inspection-time-invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise RenewalBlocked("inspection-time-invalid") from None
    if parsed.tzinfo is None:
        raise RenewalBlocked("inspection-time-invalid")
    return parsed.astimezone(timezone.utc)


def validate_scope(scope):
    required = {"certificate_id", "policy_sha256", "hostnames", "issuer_uid",
                "issuer_gid", "storage_id", "grant_id"}
    if (type(scope) is not dict or set(scope) != required
            or type(scope["certificate_id"]) is not str
            or _ID.fullmatch(scope["certificate_id"]) is None
            or type(scope["policy_sha256"]) is not str
            or HEX.fullmatch(scope["policy_sha256"]) is None
            or type(scope["hostnames"]) is not list
            or not 1 <= len(scope["hostnames"]) <= 20
            or scope["hostnames"] != sorted(set(scope["hostnames"]))
            or any(type(name) is not str or len(name) > 253 or
                   not all(_HOST.fullmatch(part) for part in name.split("."))
                   for name in scope["hostnames"])
            or any(type(scope[field]) is not int or scope[field] < 1000
                   for field in ("issuer_uid", "issuer_gid"))
            or any(type(scope[field]) is not str or
                   _UUID32.fullmatch(scope[field]) is None
                   for field in ("storage_id", "grant_id"))):
        raise RenewalBlocked("selected-inspection-scope-invalid")
    return json.loads(_canonical(scope))


def _read(fd, scope):
    try:
        handle = os.open(_RECORD, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(handle)
        import stat
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 8192):
            raise RenewalBlocked("selected-inspection-journal-unsafe")
        record = json.loads(os.read(handle, 8193))
    except (TypeError, UnicodeError, ValueError):
        raise RenewalBlocked("selected-inspection-journal-invalid") from None
    finally:
        os.close(handle)
    fields = {"schema", "scope", "phase", "request_id", "renewal_request_id",
              "issued_at", "runtime_id", "fingerprint", "outcome"}
    if (type(record) is not dict or set(record) != fields
            or record["schema"] != SCHEMA
            or record["scope"] != scope or record["phase"] not in STATES
            or type(record["request_id"]) is not str
            or REQUEST_ID.fullmatch(record["request_id"]) is None
            or (record["renewal_request_id"] is not None and
                (type(record["renewal_request_id"]) is not str or
                 REQUEST_ID.fullmatch(record["renewal_request_id"]) is None))
            or record["request_id"] == record["renewal_request_id"]
            or (record["runtime_id"] is not None and
                (type(record["runtime_id"]) is not str
                 or not 1 <= len(record["runtime_id"]) <= 80))
            or (record["fingerprint"] is not None and
                (type(record["fingerprint"]) is not str or
                 HEX.fullmatch(record["fingerprint"]) is None))):
        raise RenewalBlocked("selected-inspection-journal-mismatch")
    _timestamp(record["issued_at"])
    if ((record["phase"] == "verified" and (
            record["fingerprint"] is None
            or record["outcome"] not in ("issued", "renewed", "unchanged")
            or record["runtime_id"] is None))
            or (record["phase"] != "verified" and
                (record["fingerprint"] is not None or record["outcome"] is not None))):
        raise RenewalBlocked("selected-inspection-journal-mismatch")
    return record


def _save(fd, record):
    # Same protected owner journal semantics but a different filename;
    # never overwrite the authoritative renewal.json.
    raw = _canonical(record)
    if len(raw) > 8192:
        raise RenewalBlocked("selected-inspection-journal-oversize")
    filename = ".inspection-" + os.urandom(12).hex()
    descriptor = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(filename, _RECORD, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(filename, dir_fd=fd)
        except FileNotFoundError:
            pass


def _archive_verified(fd, record):
    """Retain the old inspection ID before another finite inspect runtime."""
    if record["phase"] != "verified":
        raise RenewalBlocked("previous-inspection-unresolved")
    name = "verified-inspection-" + record["request_id"] + ".json"
    raw = _canonical(record)
    try:
        descriptor = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    except FileExistsError:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            import stat
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1
                    or info.st_size > 8192 or os.read(descriptor, 8193) != raw):
                raise RenewalBlocked("inspection-history-conflict")
        finally:
            os.close(descriptor)
    else:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(fd)


def _original_renewal(fd, scope, original_id):
    prior = _load(fd, _binding(scope["policy_sha256"], scope["certificate_id"]))
    if prior and prior["phase"] not in ("verified", "blocked"):
        raise RenewalBlocked("inspection-blocked-by-active-renewal")
    if prior and prior["phase"] == "blocked":
        raise RenewalBlocked("inspection-blocked-by-uncertain-renewal")
    if original_id is not None:
        if (prior is None or prior["phase"] != "verified"
                or prior["request_id"] != original_id):
            raise RenewalBlocked("inspection-original-renewal-mismatch")
    return prior


def tick(directory, controller, scope, *, original_renewal_id=None,
         trusted_reader=None, trusted_renewal_observation=None,
         host_policy_digest=None, now=None):
    """Single bounded pass; no client-supplied issuer JSON may become evidence.

    trusted_reader, when implemented by controller/root-control, must derive
    evidence from the exact saved request + runtime + systemd invocation.
    Until that reviewed reader exists, completed inspect remains unverified.
    """
    scope = validate_scope(scope)
    if original_renewal_id is not None and (
            type(original_renewal_id) is not str
            or REQUEST_ID.fullmatch(original_renewal_id) is None):
        raise RenewalBlocked("inspection-original-id-invalid")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise RenewalBlocked("inspection-clock-invalid")
    current = current.astimezone(timezone.utc)
    with _locked(directory) as fd:
        _original_renewal(fd, scope, original_renewal_id)
        record = _read(fd, scope)
        if record and record["renewal_request_id"] != original_renewal_id:
            # Only a finished, recorded pre-renew check may be replaced by
            # a separate request-bound post-renew inspection.
            if record["phase"] != "verified":
                raise RenewalBlocked("previous-inspection-unresolved")
            _archive_verified(fd, record)
            record = None
        elif record and record["phase"] == "verified":
            elapsed = current - _timestamp(record["issued_at"])
            if elapsed <= timedelta(minutes=15):
                return dict(record)
            _archive_verified(fd, record)
            record = None
        if record is None:
            ident = controller.issue_application_request_id()
            if (type(ident) is not str or REQUEST_ID.fullmatch(ident) is None
                    or ident == original_renewal_id):
                raise RenewalBlocked("inspection-request-id-invalid")
            record = {
                "schema": SCHEMA, "scope": scope, "phase": "issued",
                "request_id": ident, "renewal_request_id": original_renewal_id,
                "issued_at": current.isoformat(), "runtime_id": None,
                "fingerprint": None, "outcome": None,
            }
            _save(fd, record)  # BEFORE controller starts the selected inspect
        if record["renewal_request_id"] != original_renewal_id:
            raise RenewalBlocked("inspection-original-renewal-mismatch")
        if record["phase"] == "blocked":
            raise RenewalBlocked("inspection-record-blocked")
        ident = record["request_id"]
        result = controller.application_request_result(ident)
        if result is None:
            if current - _timestamp(record["issued_at"]) > timedelta(hours=24):
                raise RenewalBlocked("inspection-controller-evidence-expired")
            # Broker does NOT currently permit inspect. This will fail closed,
            # retaining the exact original ID for a later reviewed implementation.
            controller.request_application_launch(
                "certify-manage", program_name="inspect", request_id=ident
            )
            record["phase"] = "submitted"
            _save(fd, record)
            return dict(record)
        if (_value(result, "request_id") != ident or
                _value(result, "application") != "certify-manage" or
                _value(result, "program_name") != "inspect" or
                _value(result, "operation") != "launch"):
            raise RenewalBlocked("inspection-controller-result-mismatch")
        phase = _value(result, "status")
        if phase == "pending":
            record["phase"] = "submitted"
            _save(fd, record)
            return dict(record)
        if phase != "satisfied":
            record["phase"] = "blocked"
            _save(fd, record)
            raise RenewalBlocked("inspection-controller-not-satisfied")
        runtime_id = _value(result, "runtime_id")
        if type(runtime_id) is not str or not 1 <= len(runtime_id) <= 80:
            raise RenewalBlocked("inspection-runtime-missing")
        record["runtime_id"] = runtime_id
        record["phase"] = "awaiting-evidence"
        _save(fd, record)
        authenticated = hasattr(controller, "inspect_issuer_result")
        if trusted_reader is None and authenticated:
            trusted_reader = controller.inspect_issuer_result
        if trusted_reader is None:
            return dict(record)
        # The controller's authenticated inspection API accepts only its saved
        # inspect request ID, never arbitrary path/invocation/boot selectors.
        evidence = (trusted_reader(ident) if authenticated
                    else trusted_reader(ident, runtime_id))
        if authenticated:
            from .certificate_authenticated_inspection import correlate as correlate_authenticated
            checked = correlate_authenticated(
                scope, ident, runtime_id, evidence,
                original_renewal_id=original_renewal_id,
                renewal_observation=trusted_renewal_observation,
                host_policy_digest=host_policy_digest, now=current,
            )
        else:
            checked = correlate(scope, ident, runtime_id, evidence,
                                original_renewal_id=original_renewal_id,
                                renewal_observation=trusted_renewal_observation,
                                now=current)
        if original_renewal_id is not None:
            original = _original_renewal(fd, scope, original_renewal_id)
            if (original["fingerprint"] != checked["fingerprint"]
                    or original["outcome"] != checked["outcome"]):
                raise RenewalBlocked("inspection-renewal-result-mismatch")
        record.update(phase="verified", fingerprint=checked["fingerprint"],
                      outcome=checked["outcome"])
        _save(fd, record)
        return dict(record)


def correlate(scope, inspect_id, runtime_id, evidence, *,
              original_renewal_id=None, renewal_observation=None, now=None):
    """Compare proposed controller provenance with actual certify-manage v1.

    The nested issuer_result fields are the IMPLEMENTED one-shot issuer
    producer contract. The enclosing controller-reader envelope is PROPOSED
    and must not be treated as authenticated until the owners publish it.
    """
    scope = validate_scope(scope)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise RenewalBlocked("inspection-clock-invalid")
    current = current.astimezone(timezone.utc)
    controller_fields = {"schema", "inspect_request_id", "runtime_id",
                         "invocation_id", "program", "storage_id", "grant_id",
                         "issuer_uid", "issuer_gid", "original_renewal_id",
                         "issuer_result"}
    if (type(evidence) is not dict or set(evidence) != controller_fields
            or len(_canonical(evidence)) > 8192
            or evidence["schema"] != EVIDENCE_SCHEMA
            or evidence["inspect_request_id"] != inspect_id
            or evidence["runtime_id"] != runtime_id
            or type(evidence["invocation_id"]) is not str
            or _UUID32.fullmatch(evidence["invocation_id"]) is None
            or evidence["program"] != "inspect"
            or any(evidence[field] != scope[field] for field in (
                "storage_id", "grant_id", "issuer_uid", "issuer_gid"))
            or evidence["original_renewal_id"] != original_renewal_id):
        raise RenewalBlocked("inspection-invocation-evidence-mismatch")
    value = evidence["issuer_result"]
    issuer_fields = {
        "schema", "certificate_id", "hostnames", "policy_sha256",
        "health", "certificate_fingerprint_sha256", "valid_from",
        "expires_at", "days_remaining", "operation", "outcome",
        "operation_updated_at", "issuer_verified", "observed_at", "tls_ready",
    }
    if (type(value) is not dict or set(value) != issuer_fields
            or value["schema"] != "zog-certify-inspection-result-v1"
            or value["certificate_id"] != scope["certificate_id"]
            or value["hostnames"] != scope["hostnames"]
            or value["policy_sha256"] != scope["policy_sha256"]
            or value["health"] != "valid"
            or value["issuer_verified"] is not True
            or value["tls_ready"] is not False
            or value["operation"] not in ("issue", "renew")
            or value["outcome"] not in ("issued", "renewed", "unchanged")
            or type(value["certificate_fingerprint_sha256"]) is not str
            or HEX.fullmatch(value["certificate_fingerprint_sha256"]) is None
            or type(value["days_remaining"]) is not int
            or value["days_remaining"] < 0):
        raise RenewalBlocked("inspection-invocation-certificate-invalid")
    updated = _timestamp(value["operation_updated_at"])
    observed = _timestamp(value["observed_at"])
    expires = _timestamp(value["expires_at"])
    valid_from = _timestamp(value["valid_from"])
    if (updated > observed + timedelta(minutes=2)
            or not current - timedelta(minutes=2) <= observed <= current + timedelta(minutes=2)
            or not valid_from <= current < expires):
        raise RenewalBlocked("inspection-invocation-evidence-stale")
    if original_renewal_id is not None:
        proof = renewal_observation
        if (type(proof) is not dict or proof.get("status") != "journal-ready"
                or proof.get("request_id") != original_renewal_id
                or proof.get("certificate_id") != scope["certificate_id"]
                or proof.get("policy_sha256") != scope["policy_sha256"]
                or proof.get("storage_id") != scope["storage_id"]
                or proof.get("grant_id") != scope["grant_id"]
                or proof.get("certificate_fingerprint_sha256") !=
                   value["certificate_fingerprint_sha256"]
                or proof.get("outcome") != value["outcome"]
                or proof.get("tls_ready") is not False
                or value["operation"] != "renew"
                or value["outcome"] not in ("renewed", "unchanged")
                or _timestamp(proof.get("journal_updated_at")) != updated):
            raise RenewalBlocked("inspection-original-renewal-proof-mismatch")
    return {
        "fingerprint": value["certificate_fingerprint_sha256"],
        "outcome": value["outcome"],
        "operation_updated_at": updated.isoformat(),
        "expires_at": expires.isoformat(),
        "days_remaining": value["days_remaining"],
        "tls_ready": False, "inspect_request_id": inspect_id,
        "runtime_id": runtime_id,
    }
