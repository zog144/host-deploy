"""Fail-closed selected stage → private receipt → owner nginx delivery.

This is a companion to certificate_renewal.tick, not another renew scheduler.
Stage is separately authorized through an owner-controlled policy and the
existing box-control selected-program API. The consumer bridge authenticates
SO_PEERCRED and owns nginx. Lost delivery replies are never auto-replayed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ipaddress
import socket
import stat

from .certificate_renewal import (
    _binding, _canonical, _load, _locked, _save, _value, HEX, REQUEST_ID,
    RenewalBlocked,
)
from .certificate_delivery import REQUEST_SCHEMA, SCHEMA as DELIVERY_SCHEMA
from .certificate_renewal_timer import _issuer_verification

SCHEMA = "zog-host-deploy-renewal-publication-v1"
POLICY_SCHEMA = "zog-host-deploy-renewal-publication-policy-v1"
RECEIPT_SCHEMA = "zog-certify-publication-candidate-v1"
STATES = frozenset({"stage-issued", "stage-submitted", "awaiting-stage",
                    "stage-verified", "delivery-uncertain", "complete", "blocked"})
MAX_RECORD = 8192


def validate_policy(policy):
    expected = {"schema", "certificate_id", "policy_sha256", "service_id",
                "issuer_state", "issuer_policy_file", "socket_path",
                "stage_program", "approved_stage", "hostnames"}
    if not isinstance(policy, dict) or set(policy) != expected or policy.get("schema") != POLICY_SCHEMA:
        raise RenewalBlocked("publication-policy-invalid")
    from .certificate_delivery import ID, _absolute
    if (policy["stage_program"] != "stage" or policy["approved_stage"] is not True
            or not isinstance(policy["certificate_id"], str)
            or ID.fullmatch(policy["certificate_id"]) is None
            or not isinstance(policy["service_id"], str)
            or ID.fullmatch(policy["service_id"]) is None
            or not isinstance(policy["policy_sha256"], str)
            or HEX.fullmatch(policy["policy_sha256"]) is None
            or not isinstance(policy["hostnames"], list)
            or not policy["hostnames"]
            or len(policy["hostnames"]) > 20
            or not all(isinstance(n, str) and
                       re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}", n)
                       and ".." not in n for n in policy["hostnames"])
            or sorted(set(policy["hostnames"])) != policy["hostnames"]):
        raise RenewalBlocked("publication-policy-invalid")
    for hostname in policy["hostnames"]:
        if (hostname.startswith("-") or hostname.endswith("-") or
                hostname.startswith(".") or hostname.endswith(".")
                or any(not 1 <= len(label) <= 63 or label.startswith("-")
                       or label.endswith("-") for label in hostname.split("."))):
            raise RenewalBlocked("publication-policy-invalid")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise RenewalBlocked("publication-policy-invalid")
    try:
        for name in ("issuer_state", "issuer_policy_file", "socket_path"):
            _absolute(policy[name])
    except Exception:
        raise RenewalBlocked("publication-policy-invalid") from None
    return json.loads(_canonical(policy))


def _policy_digest(policy):
    return hashlib.sha256(_canonical(validate_policy(policy))).hexdigest()


def _receipt(policy, fingerprint):
    """Issuer-UID-only inspection; root bridge independently verifies PEM."""
    from zog.certify_manage.security import protected_file_read, trusted_policy
    from zog.certify_manage.model import Authorization
    try:
        auth = Authorization.from_dict(json.loads(trusted_policy(
            Path(policy["issuer_policy_file"]))))
        if (auth.certificate_id != policy["certificate_id"]
                or auth.fingerprint != policy["policy_sha256"]
                or list(auth.hostnames) != policy["hostnames"]):
            raise RenewalBlocked("stage-issuer-identity-mismatch")
        data = protected_file_read(
            Path(policy["issuer_state"]),
            Path("publications") / policy["certificate_id"] /
            fingerprint / "receipt.json",
            MAX_RECORD, private=True,
        )
        receipt = json.loads(data)
    except RenewalBlocked:
        raise
    except Exception:
        raise RenewalBlocked("stage-receipt-unavailable") from None
    required = {"schema", "certificate_id", "policy_sha256",
                "certificate_fingerprint_sha256", "hostnames", "expires_at",
                "fullchain_sha256", "key_sha256", "state"}
    if (type(receipt) is not dict or set(receipt) != required
            or receipt.get("schema") != RECEIPT_SCHEMA
            or receipt.get("state") != "issuer-private-unbound"
            or receipt.get("certificate_id") != policy["certificate_id"]
            or receipt.get("policy_sha256") != policy["policy_sha256"]
            or receipt.get("certificate_fingerprint_sha256") != fingerprint
            or receipt.get("hostnames") != policy["hostnames"]
            or any(type(receipt.get(k)) is not str or HEX.fullmatch(receipt[k]) is None
                   for k in ("fullchain_sha256", "key_sha256"))):
        raise RenewalBlocked("stage-receipt-binding-mismatch")
    # Do not return filenames, keys, challenge/account tokens or raw PEM.
    return {"fingerprint": fingerprint, "receipt_digest": hashlib.sha256(data).hexdigest()}


def _send_to_owner(policy, fingerprint):
    """Unix peer gets only exact selected identities; owner verifies candidate and TLS."""
    request = _canonical({
        "schema": REQUEST_SCHEMA, "certificate_id": policy["certificate_id"],
        "service_id": policy["service_id"], "fingerprint": fingerprint
    }) + b"\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(150)
            client.connect(policy["socket_path"])
            client.sendall(request)
            response = bytearray()
            while len(response) <= 4096 and not response.endswith(b"\n"):
                chunk = client.recv(4097 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
    except (OSError, TimeoutError):
        raise RenewalBlocked("delivery-outcome-uncertain") from None
    if len(response) > 4096 or not response.endswith(b"\n"):
        raise RenewalBlocked("delivery-outcome-uncertain")
    try:
        result = json.loads(response)
    except (UnicodeError, ValueError):
        raise RenewalBlocked("delivery-outcome-uncertain") from None
    if (type(result) is not dict or result.get("schema") != DELIVERY_SCHEMA
            or result.get("state") != "browser-verified"
            or result.get("fingerprint") != fingerprint
            or result.get("service_id") != policy["service_id"]
            or type(result.get("idempotent")) is not bool):
        raise RenewalBlocked("delivery-outcome-uncertain")
    return True


def _load_publication(fd, digest):
    try:
        handle = os.open("renewal-publication.json",
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size > MAX_RECORD):
            raise RenewalBlocked("publication-journal-unsafe")
        raw = os.read(handle, MAX_RECORD + 1)
        record = json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        raise RenewalBlocked("publication-journal-invalid") from None
    finally:
        os.close(handle)
    fields = {"schema", "policy_digest", "renewal_id", "fingerprint",
              "stage_id", "stage_issued_at", "phase", "receipt_digest"}
    if (type(record) is not dict or set(record) != fields
            or record["schema"] != SCHEMA or record["policy_digest"] != digest
            or record["phase"] not in STATES
            or type(record["renewal_id"]) is not str
            or REQUEST_ID.fullmatch(record["renewal_id"]) is None
            or type(record["fingerprint"]) is not str
            or HEX.fullmatch(record["fingerprint"]) is None
            or type(record["stage_id"]) is not str
            or REQUEST_ID.fullmatch(record["stage_id"]) is None
            or type(record["stage_issued_at"]) is not str
            or (record["receipt_digest"] is not None and
                (type(record["receipt_digest"]) is not str or
                 HEX.fullmatch(record["receipt_digest"]) is None))):
        raise RenewalBlocked("publication-journal-identity-mismatch")
    if (record["phase"] in {"stage-verified", "delivery-uncertain", "complete"}
            and record["receipt_digest"] is None):
        raise RenewalBlocked("publication-journal-identity-mismatch")
    try:
        instant = datetime.fromisoformat(record["stage_issued_at"])
        if instant.tzinfo is None:
            raise ValueError("timezone missing")
    except (ValueError, TypeError):
        raise RenewalBlocked("publication-journal-invalid") from None
    return record


def _save_publication(fd, record):
    raw = _canonical(record)
    if len(raw) > MAX_RECORD:
        raise RenewalBlocked("publication-journal-too-large")
    name = ".publication-" + os.urandom(16).hex()
    handle = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.rename(name, "renewal-publication.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def _archive(fd, record):
    path = "published-" + record["renewal_id"] + ".json"
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    except FileExistsError:
        reader = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(reader)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077
                    or info.st_size > MAX_RECORD
                    or os.read(reader, MAX_RECORD + 1) != _canonical(record)):
                raise RenewalBlocked("publication-history-conflict")
        finally:
            os.close(reader)
    else:
        with os.fdopen(handle, "wb") as out:
            out.write(_canonical(record))
            out.flush()
            os.fsync(out.fileno())
        os.fsync(fd)


def check_renewal_fence(directory, policy_sha256, certificate_id):
    """No later renewal while prior changed fingerprint lacks consumer acceptance."""
    with _locked(directory) as fd:
        renewed = _load(fd, _binding(policy_sha256, certificate_id))
        if renewed is None or renewed["phase"] != "verified" or renewed["outcome"] != "renewed":
            return
        try:
            handle = os.open("renewal-publication.json", os.O_RDONLY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        except FileNotFoundError:
            raise RenewalBlocked("previous-renewal-not-delivered") from None
        try:
            info = os.fstat(handle)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1 or
                    info.st_size > MAX_RECORD):
                raise RenewalBlocked("publication-journal-unsafe")
            record = json.loads(os.read(handle, MAX_RECORD + 1))
        except (UnicodeError, ValueError, TypeError):
            raise RenewalBlocked("publication-journal-invalid") from None
        finally:
            os.close(handle)
        if (type(record) is not dict or record.get("schema") != SCHEMA
                or record.get("phase") != "complete"
                or record.get("renewal_id") != renewed["request_id"]
                or record.get("fingerprint") != renewed["fingerprint"]):
            raise RenewalBlocked("previous-renewal-not-delivered")


def advance(directory, controller, policy, *, stage_observer=_receipt,
            delivery_client=_send_to_owner):
    """One bounded step in the exact selected staging/publication process.

    Calling it is authorized only by a reviewed root policy and the issuer UID.
    No resubmission after delivery uncertainty; manual operator recovery only.
    """
    policy = validate_policy(policy)
    digest = _policy_digest(policy)
    with _locked(directory) as fd:
        renewed = _load(fd, _binding(policy["policy_sha256"], policy["certificate_id"]))
        if renewed is None or renewed["phase"] != "verified":
            raise RenewalBlocked("renewal-not-verified")
        if renewed["outcome"] == "unchanged":
            return {"state": "unchanged-no-delivery", "renewal_id": renewed["request_id"]}
        if renewed["outcome"] != "renewed" or not isinstance(renewed["fingerprint"], str):
            raise RenewalBlocked("renewal-outcome-invalid")
        identity = renewed["request_id"]
        fingerprint = renewed["fingerprint"]
        record = _load_publication(fd, digest)
        if record is not None and record["renewal_id"] != identity:
            if record["phase"] != "complete":
                raise RenewalBlocked("previous-publication-unresolved")
            _archive(fd, record)
            record = None
        if record is None:
            stage_id = controller.issue_application_request_id()
            if (type(stage_id) is not str or REQUEST_ID.fullmatch(stage_id) is None
                    or stage_id == identity):
                raise RenewalBlocked("stage-request-id-invalid")
            record = {"schema": SCHEMA, "policy_digest": digest,
                      "renewal_id": identity, "fingerprint": fingerprint,
                      "stage_id": stage_id,
                      "stage_issued_at": datetime.now(timezone.utc).isoformat(),
                      "phase": "stage-issued", "receipt_digest": None}
            _save_publication(fd, record)  # before selected controller mutation
        if record["fingerprint"] != fingerprint:
            raise RenewalBlocked("publication-fingerprint-conflict")
        if record["phase"] in {"delivery-uncertain", "blocked"}:
            raise RenewalBlocked("delivery-recovery-required")
        if record["phase"] == "complete":
            return {"state": "browser-verified", "renewal_id": identity,
                    "fingerprint": fingerprint, "idempotent": True}
        if record["phase"] in {"stage-issued", "stage-submitted"}:
            stage_id = record["stage_id"]
            result = controller.application_request_result(stage_id)
            if result is None:
                if (datetime.now(timezone.utc) -
                        datetime.fromisoformat(record["stage_issued_at"]) >
                        timedelta(hours=24)):
                    raise RenewalBlocked("stage-controller-evidence-expired")
                controller.request_application_launch(
                    "certify-manage", program_name="stage", request_id=stage_id)
                record["phase"] = "stage-submitted"
                _save_publication(fd, record)
                return {"state": "stage-submitted", "stage_id": stage_id,
                        "renewal_id": identity}
            if (_value(result, "request_id") != stage_id
                    or _value(result, "application") != "certify-manage"
                    or _value(result, "program_name") != "stage"
                    or _value(result, "operation") != "launch"):
                raise RenewalBlocked("stage-controller-identity-mismatch")
            status = _value(result, "status")
            if status == "pending":
                return {"state": "stage-pending", "stage_id": stage_id,
                        "renewal_id": identity}
            if status != "satisfied":
                record["phase"] = "blocked"
                _save_publication(fd, record)
                raise RenewalBlocked("stage-controller-unsatisfied")
            record["phase"] = "awaiting-stage"
            _save_publication(fd, record)
        if record["phase"] == "awaiting-stage":
            inspected = stage_observer(policy, fingerprint)
            if (type(inspected) is not dict or set(inspected) !=
                    {"fingerprint", "receipt_digest"}
                    or inspected["fingerprint"] != fingerprint
                    or type(inspected["receipt_digest"]) is not str
                    or HEX.fullmatch(inspected["receipt_digest"]) is None):
                raise RenewalBlocked("stage-receipt-unproven")
            record["receipt_digest"] = inspected["receipt_digest"]
            record["phase"] = "stage-verified"
            _save_publication(fd, record)
        if record["phase"] == "stage-verified":
            # Delivery may have committed even if the reply is lost.
            record["phase"] = "delivery-uncertain"
            _save_publication(fd, record)
            try:
                if delivery_client(policy, fingerprint) is not True:
                    raise RenewalBlocked("delivery-outcome-uncertain")
            except Exception:
                raise RenewalBlocked("delivery-recovery-required") from None
            record["phase"] = "complete"
            _save_publication(fd, record)
            return {"state": "browser-verified", "renewal_id": identity,
                    "fingerprint": fingerprint, "idempotent": False}
        raise RenewalBlocked("publication-state-invalid")
