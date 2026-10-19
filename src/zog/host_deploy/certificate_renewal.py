"""Single-command certificate renewal coordinator (source-only, inert until wired).

Owner creates the protected journal and passes a trusted BoxControl instance.
A scheduler tick is a *single bounded invocation*, never a background loop.
The separate issuer-observation capability is intentionally mandatory before
considering a run verified; systemd's satisfied result is not TLS readiness.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


SCHEMA = "zog-host-deploy-cert-renewal-v1"
ATTESTATION_SCHEMA = "zog-certify-renewal-observation-v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
CERT_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9-]{1,200}\Z")
STATES = {"issued", "submitted", "awaiting-issuer", "verified", "blocked"}


class RenewalBlocked(RuntimeError):
    """No implicit retry after an uncertain or conflicting operation."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _value(obj, key):
    value = obj[key] if isinstance(obj, dict) else getattr(obj, key, None)
    return getattr(value, "value", value)


def _binding(policy_sha256, certificate_id):
    if (type(policy_sha256) is not str or not HEX.fullmatch(policy_sha256)
            or type(certificate_id) is not str or not CERT_ID.fullmatch(certificate_id)):
        raise RenewalBlocked("owner-authorization-invalid")
    return hashlib.sha256(_canonical({
        "application": "certify-manage", "program": "renew",
        "certificate_id": certificate_id, "policy_sha256": policy_sha256,
    })).hexdigest()


@contextmanager
def _locked(directory):
    """Private owner directory and exact no-follow journal namespace."""
    path = Path(directory)
    if not path.is_absolute() or ".." in path.parts:
        raise RenewalBlocked("journal-directory-invalid")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        stat_dir = os.fstat(fd)
        if stat_dir.st_uid != os.geteuid() or stat_dir.st_mode & 0o077:
            raise RenewalBlocked("journal-directory-unsafe")
        lock = os.open(".renewal.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=fd)
        try:
            info = os.fstat(lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise RenewalBlocked("journal-lock-unsafe")
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield fd
        finally:
            os.close(lock)
    finally:
        os.close(fd)


def _load(fd, binding):
    try:
        handle = os.open("renewal.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 8192):
            raise RenewalBlocked("journal-file-unsafe")
        value = json.loads(os.read(handle, 8193))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RenewalBlocked("journal-file-invalid") from exc
    finally:
        os.close(handle)
    if (type(value) is not dict or value.get("schema") != SCHEMA
            or value.get("binding") != binding
            or value.get("phase") not in STATES
            or type(value.get("request_id")) is not str
            or not REQUEST_ID.fullmatch(value["request_id"])
            or set(value) != {"schema", "binding", "phase", "request_id",
                               "fingerprint", "outcome", "issued_at"}):
        raise RenewalBlocked("journal-binding-or-state-mismatch")
    try:
        issued_at = datetime.fromisoformat(value["issued_at"])
        if issued_at.tzinfo is None:
            raise ValueError("timezone missing")
    except (ValueError, TypeError):
        raise RenewalBlocked("journal-issued-at-invalid") from None
    return value


def _save(fd, value):
    raw = _canonical(value)
    if len(raw) > 8192:
        raise RenewalBlocked("journal-too-large")
    temp = ".pending-" + uuid.uuid4().hex
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temp, "renewal.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temp, dir_fd=fd)
        except FileNotFoundError:
            pass


def _public(record):
    return {k: record[k] for k in ("schema", "phase", "request_id", "outcome", "fingerprint")}


def tick(directory, controller, *, policy_sha256, certificate_id,
         authorize_new=False, issuer_observation=None, minimum_interval_hours=24):
    """Queue or reconcile exactly one certificate renewal.

    authorize_new requires a separately reviewed scheduler/host owner decision.
    issuer_observation is a trusted host-owner callback (not client JSON)
    which must attest the *same* controller request and issuer state.
    """
    binding = _binding(policy_sha256, certificate_id)
    if type(minimum_interval_hours) is not int or not 24 <= minimum_interval_hours <= 720:
        raise RenewalBlocked("invalid-minimum-renewal-interval")
    with _locked(directory) as fd:
        record = _load(fd, binding)
        if record is None or record["phase"] == "verified":
            if (record is not None and
                    datetime.now(timezone.utc) -
                    datetime.fromisoformat(record["issued_at"]) <
                    timedelta(hours=minimum_interval_hours)):
                return _public(record)
            if not authorize_new:
                return _public(record) if record else {
                    "schema": SCHEMA, "phase": "idle", "request_id": None,
                    "outcome": None, "fingerprint": None,
                }
            if record is not None:
                historical_name = "verified-" + record["request_id"] + ".json"
                original = _canonical(record)
                try:
                    archive = os.open(
                        historical_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
                except FileExistsError:
                    archived = os.open(historical_name,
                                       os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=fd)
                    try:
                        info = os.fstat(archived)
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                                or info.st_mode & 0o077 or info.st_nlink != 1
                                or info.st_size > 8192 or os.read(archived, 8193) != original):
                            raise RenewalBlocked("historical-request-conflict")
                    finally:
                        os.close(archived)
                else:
                    with os.fdopen(archive, "wb") as stream:
                        stream.write(original)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.fsync(fd)
            request_id = controller.issue_application_request_id()
            if type(request_id) is not str or not REQUEST_ID.fullmatch(request_id):
                raise RenewalBlocked("invalid-controller-request-id")
            record = {"schema": SCHEMA, "binding": binding, "phase": "issued",
                      "request_id": request_id, "fingerprint": None, "outcome": None,
                      "issued_at": datetime.now(timezone.utc).isoformat()}
            # Durably retain the exact identity BEFORE submitting it.
            _save(fd, record)
        if record["phase"] == "blocked":
            raise RenewalBlocked("prior-renewal-requires-review")
        if record["phase"] in ("issued", "submitted"):
            request_id = record["request_id"]
            result = controller.application_request_result(request_id)
            if result is None:
                # Bounded retention: after the producer may have pruned its
                # evidence, never replay even the same ID as a new action.
                issued_at = datetime.fromisoformat(record["issued_at"])
                if datetime.now(timezone.utc) - issued_at > timedelta(hours=24):
                    raise RenewalBlocked("controller-evidence-expired")
                # Lost reply: repeat exact selector + controller-issued request ID.
                controller.request_application_launch(
                    "certify-manage", program_name="renew", request_id=request_id)
                record["phase"] = "submitted"
                _save(fd, record)
                return _public(record)
            if (_value(result, "request_id") != request_id
                    or _value(result, "application") != "certify-manage"
                    or _value(result, "program_name") != "renew"
                    or _value(result, "operation") != "launch"):
                raise RenewalBlocked("controller-result-identity-mismatch")
            status = _value(result, "status")
            if status == "pending":
                record["phase"] = "submitted"
                _save(fd, record)
                return _public(record)
            if status != "satisfied":
                record["phase"] = "blocked"
                _save(fd, record)
                raise RenewalBlocked("controller-renewal-not-satisfied")
            record["phase"] = "awaiting-issuer"
            _save(fd, record)
        # Controller completion is insufficient. Only a host-owner-
        # authenticated issuer inspection is accepted as evidence.
        if issuer_observation is None:
            return _public(record)
        observed = issuer_observation(record["request_id"])
        if observed is None:
            return _public(record)
        if (type(observed) is not dict
                or set(observed) != {"schema", "request_id", "certificate_id",
                                     "policy_sha256", "health", "operation",
                                     "outcome", "fingerprint_sha256"}
                or observed["schema"] != ATTESTATION_SCHEMA
                or observed["request_id"] != record["request_id"]
                or observed["certificate_id"] != certificate_id
                or observed["policy_sha256"] != policy_sha256
                or observed["health"] != "valid"
                or observed["operation"] != "renew"
                or observed["outcome"] not in ("renewed", "unchanged")
                or type(observed["fingerprint_sha256"]) is not str
                or HEX.fullmatch(observed["fingerprint_sha256"]) is None):
            record["phase"] = "blocked"
            _save(fd, record)
            raise RenewalBlocked("issuer-observation-not-proven")
        record["phase"] = "verified"
        record["outcome"] = observed["outcome"]
        record["fingerprint"] = observed["fingerprint_sha256"]
        _save(fd, record)
        return _public(record)
