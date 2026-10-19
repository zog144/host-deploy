"""Request-bound, authenticated issuer observation adapter.

Read-only: an observer's 'journal-ready' status proves a controller-owned
issuer journal, not the validity of the X.509 lineage or served TLS. This
module deliberately cannot claim certificate delivery or issue/stage/renew.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat

from .certificate_renewal import RenewalBlocked, REQUEST_ID

SCHEMA = "zog-host-deploy-issuer-observer-policy-v1"
OBSERVED = "zog-trusted-issuer-observation-v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HOST_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUNTIME = re.compile(r"[A-Za-z0-9-]{1,80}\Z")
_FIELDS = frozenset({
    "schema", "request_id", "runtime_id", "program", "storage_id",
    "grant_id", "issuer_uid", "issuer_gid", "policy_sha256",
    "host_policy_digest", "certificate_id", "certificate_fingerprint_sha256",
    "journal_updated_at", "outcome", "status", "tls_ready",
})


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or value == "/" or len(value) > 512
            or any(c in ("", ".", "..") for c in value.split("/")[1:])):
        raise RenewalBlocked("observer-authorization-invalid")
    return value


def validate_policy(value):
    fields = {
        "schema", "socket_path", "caller_uid", "certificate_id",
        "policy_sha256", "host_policy_digest", "storage_id", "grant_id",
        "issuer_uid", "issuer_gid",
    }
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != SCHEMA:
        raise RenewalBlocked("observer-authorization-invalid")
    _path(value["socket_path"])
    if (type(value["caller_uid"]) is not int or value["caller_uid"] < 1000
            or any(type(value[k]) is not int or value[k] < 1000
                   for k in ("issuer_uid", "issuer_gid"))
            or type(value["certificate_id"]) is not str
            or _ID.fullmatch(value["certificate_id"]) is None
            or any(type(value[k]) is not str or _HEX.fullmatch(value[k]) is None
                   for k in ("policy_sha256",))
            or any(type(value[k]) is not str or _HEX32.fullmatch(value[k]) is None
                   for k in ("storage_id", "grant_id"))
            or type(value["host_policy_digest"]) is not str
            or _HOST_DIGEST.fullmatch(value["host_policy_digest"]) is None):
        raise RenewalBlocked("observer-authorization-invalid")
    return json.loads(json.dumps(value, sort_keys=True))


def read_policy(path):
    """Root policy, never controlled by a client or issuer state mount."""
    path = Path(_path(str(path)))
    component = Path("/")
    for item in path.parts[1:-1]:
        component /= item
        try:
            info = component.lstat()
        except OSError:
            raise RenewalBlocked("observer-policy-unavailable") from None
        if (not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o022):
            raise RenewalBlocked("observer-policy-parent-untrusted")
    try:
        if path.is_symlink():
            raise RenewalBlocked("observer-policy-untrusted")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022 or info.st_nlink != 1
                    or info.st_size > 8192):
                raise RenewalBlocked("observer-policy-untrusted")
            raw = os.read(fd, 8193)
        finally:
            os.close(fd)
        return validate_policy(json.loads(raw))
    except (OSError, UnicodeError, ValueError, TypeError):
        raise RenewalBlocked("observer-policy-unavailable") from None


def _timestamp(value):
    if type(value) is not str or len(value) > 80:
        raise RenewalBlocked("issuer-observation-time-invalid")
    try:
        instant = datetime.fromisoformat(value)
    except ValueError:
        raise RenewalBlocked("issuer-observation-time-invalid") from None
    if instant.tzinfo is None:
        raise RenewalBlocked("issuer-observation-time-invalid")
    return instant.astimezone(timezone.utc)


def observe_request(policy, *, request_id, issued_at, controller_result,
                    client_factory=None, now=None):
    """Return a secret-free trust-rooted journal view, not an X.509 attestation.

    All identities are pinned by a root-owned policy; the only wire input to
    the box-control issuer observer is the exact controller request ID.
    The broker authenticates SO_PEERCRED and root-control derives the evidence.
    """
    policy = validate_policy(policy)
    if os.geteuid() != policy["caller_uid"]:
        raise RenewalBlocked("observer-caller-identity-mismatch")
    if type(request_id) is not str or REQUEST_ID.fullmatch(request_id) is None:
        raise RenewalBlocked("observer-request-id-invalid")
    started = _timestamp(issued_at)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if started > now + timedelta(minutes=2):
        raise RenewalBlocked("observer-intent-in-future")
    from .certificate_renewal import _value
    if (controller_result is None
            or _value(controller_result, "request_id") != request_id
            or _value(controller_result, "application") != "certify-manage"
            or _value(controller_result, "program_name") != "renew"
            or _value(controller_result, "operation") != "launch"):
        raise RenewalBlocked("observer-controller-request-mismatch")
    if _value(controller_result, "status") != "satisfied":
        raise RenewalBlocked("observer-controller-not-satisfied")
    runtime_id = _value(controller_result, "runtime_id")
    if type(runtime_id) is not str or _RUNTIME.fullmatch(runtime_id) is None:
        raise RenewalBlocked("observer-runtime-identity-missing")
    if client_factory is None:
        from zog.box_control.issuer_observer_client import IssuerObserverClient
        client_factory = IssuerObserverClient
    try:
        evidence = client_factory(policy["socket_path"]).observe_issuer_request(request_id)
    except Exception:
        raise RenewalBlocked("issuer-observer-unavailable") from None
    if (type(evidence) is not dict or set(evidence) != _FIELDS
            or evidence.get("schema") != OBSERVED
            or evidence.get("request_id") != request_id
            or evidence.get("runtime_id") != runtime_id
            or evidence.get("program") != "renew"
            or evidence.get("tls_ready") is not False
            or evidence.get("certificate_id") != policy["certificate_id"]
            or evidence.get("policy_sha256") != policy["policy_sha256"]
            or evidence.get("host_policy_digest") != policy["host_policy_digest"]
            or evidence.get("storage_id") != policy["storage_id"]
            or evidence.get("grant_id") != policy["grant_id"]
            or type(evidence.get("issuer_uid")) is not int
            or evidence["issuer_uid"] != policy["issuer_uid"]
            or type(evidence.get("issuer_gid")) is not int
            or evidence["issuer_gid"] != policy["issuer_gid"]):
        raise RenewalBlocked("issuer-observation-binding-mismatch")
    status = evidence.get("status")
    if status not in ("ongoing", "stale", "uncertain", "journal-ready"):
        raise RenewalBlocked("issuer-observation-status-invalid")
    if status != "journal-ready":
        # Incomplete/failed evidence can never authorize stage or delivery.
        return {"status": status, "request_id": request_id, "tls_ready": False}
    if (evidence.get("outcome") not in ("renewed", "unchanged")
            or type(evidence.get("certificate_fingerprint_sha256")) is not str
            or _HEX.fullmatch(evidence["certificate_fingerprint_sha256"]) is None):
        raise RenewalBlocked("issuer-observation-result-invalid")
    updated = _timestamp(evidence.get("journal_updated_at"))
    if updated < started or updated > now + timedelta(minutes=2):
        raise RenewalBlocked("issuer-observation-stale")
    return {
        "schema": OBSERVED, "status": "journal-ready",
        "request_id": request_id, "runtime_id": runtime_id,
        "certificate_id": policy["certificate_id"],
        "policy_sha256": policy["policy_sha256"],
        "certificate_fingerprint_sha256": evidence["certificate_fingerprint_sha256"],
        "outcome": evidence["outcome"], "journal_updated_at": updated.isoformat(),
        "storage_id": policy["storage_id"], "grant_id": policy["grant_id"],
        "tls_ready": False,
    }
