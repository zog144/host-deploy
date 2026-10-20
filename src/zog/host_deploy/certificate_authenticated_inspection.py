"""Host-owned correlation for UID-pinned box/root-control inspect results.

The envelope is obtained only via IssuerLifecycleClient.inspect_issuer_result:
a saved invocation and SO_PEERCRED authenticated reader, never caller JSON.
"""
from datetime import datetime, timedelta, timezone
import json
import re

from .certificate_renewal import RenewalBlocked
from .certificate_selected_inspection import validate_scope

TRUSTED = "zog-trusted-issuer-inspection-v1"
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_UUID = re.compile(r"[a-f0-9]{32}\Z")


def _time(value):
    if type(value) is not str or len(value) > 80:
        raise RenewalBlocked("trusted-inspection-time-invalid")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise RenewalBlocked("trusted-inspection-time-invalid") from None
    if result.utcoffset() is None:
        raise RenewalBlocked("trusted-inspection-time-invalid")
    return result.astimezone(timezone.utc)


def correlate(scope, inspect_id, runtime_id, evidence, *,
              original_renewal_id=None, renewal_observation=None,
              host_policy_digest=None, now=None):
    scope = validate_scope(scope)
    current = now or datetime.now(timezone.utc)
    if current.utcoffset() is None:
        raise RenewalBlocked("trusted-inspection-time-invalid")
    current = current.astimezone(timezone.utc)
    fields = {"schema", "request_id", "runtime_id", "program", "boot_id",
              "invocation_id", "storage_id", "grant_id", "issuer_uid", "issuer_gid",
              "host_policy_digest", "inspection", "status", "tls_ready"}
    # This expected digest must be provided from separately approved local
    # root-owner policy, never learned from the observation being checked.
    # In particular a station-owned UID-970 projection cannot select it.
    if (type(evidence) is not dict or set(evidence) != fields
            or len(json.dumps(evidence, sort_keys=True)) > 8192
            or evidence["schema"] != TRUSTED
            or evidence["request_id"] != inspect_id
            or evidence["runtime_id"] != runtime_id
            or evidence["program"] != "inspect"
            or evidence["status"] != "verified"
            or evidence["tls_ready"] is not False
            or type(host_policy_digest) is not str
            or not _DIGEST.fullmatch(host_policy_digest)
            or evidence["host_policy_digest"] != host_policy_digest
            or any(evidence[k] != scope[k] for k in
                   ("storage_id", "grant_id", "issuer_uid", "issuer_gid"))
            or any(type(evidence[k]) is not str
                   or _UUID.fullmatch(evidence[k].replace("-", "").lower()) is None
                   for k in ("boot_id", "invocation_id"))):
        raise RenewalBlocked("trusted-inspection-invocation-mismatch")
    result = evidence["inspection"]
    if (type(result) is not dict
            or result.get("schema") != "zog-certify-inspection-result-v1"
            or result.get("certificate_id") != scope["certificate_id"]
            or result.get("policy_sha256") != scope["policy_sha256"]
            or result.get("hostnames") != scope["hostnames"]
            or result.get("health") != "valid"
            or result.get("issuer_verified") is not True
            or result.get("tls_ready") is not False
            or result.get("operation") not in ("issue", "renew")
            or result.get("outcome") not in ("issued", "renewed", "unchanged")
            or type(result.get("certificate_fingerprint_sha256")) is not str
            or not _HEX.fullmatch(result["certificate_fingerprint_sha256"])
            or type(result.get("days_remaining")) is not int
            or result["days_remaining"] < 0):
        raise RenewalBlocked("trusted-inspection-certificate-invalid")
    observed = _time(result.get("observed_at"))
    updated = _time(result.get("operation_updated_at"))
    valid_from = _time(result.get("valid_from"))
    expires = _time(result.get("expires_at"))
    if (observed > current + timedelta(minutes=2)
            or current - observed > timedelta(minutes=15)
            or updated > observed + timedelta(minutes=2)
            or valid_from > current or expires <= current):
        raise RenewalBlocked("trusted-inspection-stale")
    if original_renewal_id is not None:
        proof = renewal_observation
        if (type(proof) is not dict
                or proof.get("schema") != "zog-trusted-issuer-observation-v1"
                or proof.get("status") != "journal-ready"
                or proof.get("request_id") != original_renewal_id
                or proof.get("certificate_id") != scope["certificate_id"]
                or proof.get("policy_sha256") != scope["policy_sha256"]
                or proof.get("host_policy_digest") != host_policy_digest
                or proof.get("storage_id") != scope["storage_id"]
                or proof.get("grant_id") != scope["grant_id"]
                or proof.get("certificate_fingerprint_sha256")
                   != result["certificate_fingerprint_sha256"]
                or proof.get("outcome") != result["outcome"]
                or proof.get("tls_ready") is not False
                or result["operation"] != "renew"
                or result["outcome"] not in ("renewed", "unchanged")
                or _time(proof.get("journal_updated_at")) != updated):
            raise RenewalBlocked("trusted-inspection-renewal-mismatch")
    return {"fingerprint": result["certificate_fingerprint_sha256"],
            "outcome": result["outcome"],
            "operation_updated_at": updated.isoformat(),
            "expires_at": expires.isoformat(),
            "days_remaining": result["days_remaining"],
            "tls_ready": False, "inspect_request_id": inspect_id,
            "runtime_id": runtime_id, "invocation_id": evidence["invocation_id"]}
