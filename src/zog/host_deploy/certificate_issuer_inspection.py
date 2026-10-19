"""Root-pinned, secret-free certify-manage issuer inspection consumer.

The independent issuer-UID socket proves current X.509/key/chain/account
validity. It does NOT attest the controller request or nginx readiness.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import os
import re
import stat

from .certificate_renewal import RenewalBlocked

SCHEMA = "zog-host-deploy-issuer-inspection-policy-v1"
CERTIFICATE_SCHEMA = "zog-certify-inspection-v1"
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_NONCE = re.compile(r"[a-f0-9]{32}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _absolute(value):
    if (type(value) is not str or not value.startswith("/") or value == "/"
            or len(value) > 512 or any(x in ("", ".", "..") for x in value.split("/")[1:])):
        raise RenewalBlocked("inspection-policy-invalid")
    return value


def validate_policy(value):
    fields = {"schema", "socket_path", "issuer_uid", "caller_uid",
              "certificate_id", "policy_sha256", "hostnames"}
    if (type(value) is not dict or set(value) != fields
            or value.get("schema") != SCHEMA):
        raise RenewalBlocked("inspection-policy-invalid")
    _absolute(value["socket_path"])
    if (type(value["issuer_uid"]) is not int or value["issuer_uid"] < 1000
            or type(value["caller_uid"]) is not int or value["caller_uid"] < 1000
            or value["issuer_uid"] == value["caller_uid"]
            or type(value["certificate_id"]) is not str
            or _ID.fullmatch(value["certificate_id"]) is None
            or type(value["policy_sha256"]) is not str
            or _HEX.fullmatch(value["policy_sha256"]) is None
            or type(value["hostnames"]) is not list
            or not 1 <= len(value["hostnames"]) <= 20
            or any(type(host) is not str or len(host) > 253 or
                   not all(_HOST.fullmatch(label) for label in host.split("."))
                   for host in value["hostnames"])
            or value["hostnames"] != sorted(set(value["hostnames"]))):
        raise RenewalBlocked("inspection-policy-invalid")
    return json.loads(json.dumps(value, sort_keys=True))


def read_policy(path):
    """No symlinks, unsafe ancestors, non-root policy or mutable group policy."""
    filename = Path(_absolute(str(path)))
    parent = Path("/")
    for component in filename.parts[1:-1]:
        parent = parent / component
        try:
            info = parent.lstat()
        except OSError:
            raise RenewalBlocked("inspection-policy-unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise RenewalBlocked("inspection-policy-untrusted")
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022 or info.st_nlink != 1
                    or info.st_size > 8192):
                raise RenewalBlocked("inspection-policy-untrusted")
            raw = os.read(fd, 8193)
        finally:
            os.close(fd)
        return validate_policy(json.loads(raw))
    except (OSError, ValueError, TypeError, UnicodeError):
        raise RenewalBlocked("inspection-policy-unavailable") from None


def _time(value, field):
    if type(value) is not str or len(value) > 80:
        raise RenewalBlocked("inspection-" + field + "-invalid")
    try:
        observed = datetime.fromisoformat(value)
        if observed.tzinfo is None:
            raise ValueError("timezone absent")
    except (TypeError, ValueError, OverflowError):
        raise RenewalBlocked("inspection-" + field + "-invalid") from None
    return observed.astimezone(timezone.utc)


def _caller_uid():
    return os.geteuid()


def inspect_issuer(policy, *, client_factory=None, now=None):
    """Read fresh validated issuer-UID result; no implicit controller identity.

    The socket client independently authenticates SO_PEERCRED and nonce.
    Caller identity and certificate scope are pinned by root-owned policy.
    """
    policy = validate_policy(policy)
    if _caller_uid() != policy["caller_uid"]:
        raise RenewalBlocked("inspection-caller-identity-mismatch")
    if client_factory is None:
        from zog.certify_manage.inspection_client import IssuerInspectionClient
        client_factory = IssuerInspectionClient
    try:
        evidence = client_factory(
            policy["socket_path"], expected_issuer_uid=policy["issuer_uid"]
        ).inspect()
    except Exception:
        raise RenewalBlocked("inspection-unavailable") from None
    fields = {"schema", "nonce", "certificate_id", "hostnames", "policy_sha256",
              "health", "certificate_fingerprint_sha256", "valid_from", "expires_at",
              "days_remaining", "operation", "outcome", "operation_updated_at",
              "issuer_verified", "observed_at", "tls_ready"}
    if (type(evidence) is not dict or set(evidence) != fields
            or evidence["schema"] != CERTIFICATE_SCHEMA
            or type(evidence["nonce"]) is not str
            or _NONCE.fullmatch(evidence["nonce"]) is None
            or evidence["certificate_id"] != policy["certificate_id"]
            or evidence["policy_sha256"] != policy["policy_sha256"]
            or evidence["hostnames"] != policy["hostnames"]
            or evidence["tls_ready"] is not False
            or evidence["issuer_verified"] is not True
            or evidence["health"] != "valid"
            or evidence["operation"] not in ("issue", "renew")
            or evidence["outcome"] not in ("issued", "renewed", "unchanged")
            or type(evidence["certificate_fingerprint_sha256"]) is not str
            or _HEX.fullmatch(evidence["certificate_fingerprint_sha256"]) is None
            or type(evidence["days_remaining"]) is not int
            or evidence["days_remaining"] < 0):
        raise RenewalBlocked("inspection-evidence-unverified")
    current = (now or datetime.now(timezone.utc))
    if current.tzinfo is None:
        raise RenewalBlocked("inspection-clock-invalid")
    current = current.astimezone(timezone.utc)
    observed = _time(evidence["observed_at"], "observed-at")
    if not current - timedelta(seconds=15) <= observed <= current + timedelta(minutes=2):
        raise RenewalBlocked("inspection-evidence-stale")
    completed = _time(evidence["operation_updated_at"], "completion-time")
    if completed > observed + timedelta(minutes=2):
        raise RenewalBlocked("inspection-completion-in-future")
    expires = _time(evidence["expires_at"], "expiry")
    valid_from = _time(evidence["valid_from"], "validity-start")
    if not valid_from <= current < expires:
        raise RenewalBlocked("inspection-validity-unproven")
    return (
        SimpleNamespace(
            health="valid", certificate_id=evidence["certificate_id"],
            hostnames=tuple(evidence["hostnames"]),
            policy_sha256=evidence["policy_sha256"],
            fingerprint_sha256=evidence["certificate_fingerprint_sha256"],
            days_remaining=evidence["days_remaining"],
            expires_at=evidence["expires_at"], valid_from=evidence["valid_from"],
            detail=None, issuer_verified=True, tls_ready=False,
        ),
        {"operation": evidence["operation"], "outcome": evidence["outcome"]},
        completed,
    )


def inspection_checker(timer_policy, *, client_factory=None):
    """Callable compatible with timer.run(issuer_checker=...) after policy checks."""
    if timer_policy["issuer_inspection_policy_file"] is None:
        raise RenewalBlocked("inspection-authorization-required")
    approved = read_policy(timer_policy["issuer_inspection_policy_file"])
    if (approved["certificate_id"] != timer_policy["certificate_id"]
            or approved["policy_sha256"] != timer_policy["policy_sha256"]):
        raise RenewalBlocked("inspection-authorization-mismatch")
    return lambda _timer_policy: inspect_issuer(approved, client_factory=client_factory)
