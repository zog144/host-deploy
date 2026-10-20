"""Root-owner authority receipt for local HTTPS consumer binding.

Only the host owner installs this file after verifying either a signed
host-discover assignment or authenticated standalone-local administrator intent.
This module does not authenticate a web form or fetch DNS credentials.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid

SCHEMA = "zog-host-deploy-certificate-owner-authority-v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class AuthorityBlocked(ValueError):
    pass


def _fail():
    raise AuthorityBlocked("host-certificate-authority-invalid")


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _hostname(value):
    if (type(value) is not str or not 1 <= len(value) <= 253
            or value != value.lower() or value.endswith(".")
            or "." not in value or "*" in value
            or any(not _LABEL.fullmatch(part) for part in value.split("."))):
        _fail()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _fail()
    return value


def _uuid(value):
    try:
        if value != str(uuid.UUID(value)):
            _fail()
    except (ValueError, TypeError, AttributeError):
        _fail()
    return value


def validate(value, *, now=None):
    fields = {"schema", "origin", "verified_by", "host_id",
              "installation_id", "operation_id", "revision", "status",
              "approved_at", "expires_at", "revoked_at", "certificate_id",
              "service_id", "hostnames", "policy_sha256", "challenge",
              "dns_mode", "dns_zone", "credential_id", "credential_revision"}
    if type(value) is not dict or set(value) != fields or value["schema"] != SCHEMA:
        _fail()
    if value["origin"] not in ("managed", "standalone-local"):
        _fail()
    expected = ("signed-host-discover" if value["origin"] == "managed"
                else "authenticated-local-admin")
    if value["verified_by"] != expected:
        _fail()
    _uuid(value["host_id"])
    _uuid(value["installation_id"])
    _uuid(value["operation_id"])
    if (type(value["revision"]) is not int or not 1 <= value["revision"] < 2**53
            or value["status"] not in ("approved", "revoked")
            or type(value["approved_at"]) is not int
            or type(value["expires_at"]) is not int
            or value["approved_at"] <= 0
            or value["expires_at"] <= value["approved_at"]
            or value["expires_at"] - value["approved_at"] > 31*86400
            or (value["status"] == "approved" and value["revoked_at"] is not None)
            or (value["status"] == "revoked" and
                (type(value["revoked_at"]) is not int
                 or value["revoked_at"] < value["approved_at"]))):
        _fail()
    for key in ("certificate_id", "service_id"):
        if type(value[key]) is not str or not _ID.fullmatch(value[key]):
            _fail()
    if type(value["policy_sha256"]) is not str or not _HEX.fullmatch(value["policy_sha256"]):
        _fail()
    names = value["hostnames"]
    if (type(names) is not list or not 1 <= len(names) <= 20
            or names != sorted(set(names))):
        _fail()
    for host in names:
        _hostname(host)
    if value["challenge"] not in ("http-01", "dns-01"):
        _fail()
    if value["challenge"] == "http-01":
        if any(value[k] is not None for k in (
                "dns_mode", "dns_zone", "credential_id", "credential_revision")):
            _fail()
    else:
        if value["dns_mode"] not in ("local-cloudflare", "command-center-broker"):
            _fail()
        zone = _hostname(value["dns_zone"])
        if any(host != zone and not host.endswith("." + zone) for host in names):
            _fail()
        if value["dns_mode"] == "local-cloudflare":
            if (type(value["credential_id"]) is not str
                    or not _ID.fullmatch(value["credential_id"])
                    or type(value["credential_revision"]) is not int
                    or value["credential_revision"] <= 0):
                _fail()
        elif (value["credential_id"] is not None
              or value["credential_revision"] is not None):
            _fail()
    if now is not None and (type(now) not in (int, float)
                            or value["approved_at"] > now + 300
                            or value["expires_at"] <= now
                            or value["status"] != "approved"):
        raise AuthorityBlocked("host-certificate-authority-stale-or-revoked")
    return json.loads(_canon(value))


def digest(value):
    return hashlib.sha256(_canon(validate(value))).hexdigest()


def read_owned(path, *, now=None):
    """Root-owned protected file; refuse writable or symlink ancestry."""
    path = Path(path)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        _fail()
    p = Path("/")
    for name in path.parts[1:-1]:
        p /= name
        info = p.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size > 8192):
            _fail()
        raw = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    try:
        return validate(json.loads(raw), now=now)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AuthorityBlocked("host-certificate-authority-invalid") from exc


def compare_revision(previous, current):
    """Refuse replay, conflict, revocation reversal or silent origin switch."""
    current = validate(current)
    if previous is None:
        return True
    previous = validate(previous)
    stable = ("host_id", "installation_id", "origin", "certificate_id",
              "service_id")
    if any(previous[k] != current[k] for k in stable):
        raise AuthorityBlocked("host-certificate-authority-conflict")
    if current["revision"] < previous["revision"]:
        raise AuthorityBlocked("host-certificate-authority-stale")
    if current["revision"] == previous["revision"]:
        if digest(current) != digest(previous):
            raise AuthorityBlocked("host-certificate-authority-conflict")
        return False
    if current["operation_id"] == previous["operation_id"]:
        raise AuthorityBlocked("host-certificate-authority-operation-replayed")
    if previous["status"] == "revoked" and current["status"] != "revoked":
        raise AuthorityBlocked("host-certificate-authority-revocation-terminal")
    return True


def authorize_consumer(authority, delivery_policy, *, now=None):
    value = validate(authority, now=now)
    if (value["status"] != "approved"
            or value["service_id"] != delivery_policy.get("service_id")
            or value["certificate_id"] != delivery_policy.get("certificate_id")
            or value["hostnames"] != delivery_policy.get("hostnames")
            or value["policy_sha256"] != delivery_policy.get("policy_sha256")):
        raise AuthorityBlocked("host-certificate-consumer-unauthorized")
    return {"schema": SCHEMA, "authority_digest": digest(value),
            "revision": value["revision"], "operation_id": value["operation_id"],
            "consumer": value["service_id"], "certificate_id": value["certificate_id"],
            "hostnames": list(value["hostnames"])}
