"""Signed compiler-Host graphical catalogue handoff (read-only on gateway).

The command-center never reads compiler /owner-state, never obtains issuer
private keys, and never treats an SSM/SQS response as a trusted source. A
separately installed compiler root owner may export the exactly accepted
catalogue under a Host-installed Ed25519 signing key. The receiving gateway
requires an independently installed public-key pin and boot/epoch approval.
Not a compiler admission or a transport implementation.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import task_catalogue
from .graphics_generation_chain import TASKS, _hash, validate_policy

CONTRACT = "zog-host-deploy-graphical-chain-export-v1"
PIN = "zog-host-deploy-graphical-chain-remote-owner-pin-v1"
_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{32}\Z")
_FIELDS = {"schema", "task", "host_id", "installation_id", "lane",
           "lane_owner", "boot_id", "chain_policy_sha256",
           "catalogue", "catalogue_sha256", "receipt_sha256",
           "published_at", "expires_at", "epoch"}
_ENVELOPE = {"payload", "signature"}
_PIN = {"schema", "host_id", "installation_id", "lane", "lane_owner",
        "boot_id", "chain_policy_sha256", "original_catalogue_sha256",
        "public_key", "epoch"}
MAX_BYTES = 65536


class GraphicalExportBlocked(ValueError):
    pass


def _deny(reason):
    raise GraphicalExportBlocked("graphical-chain-untrusted-export: " + reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _json(raw):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        _deny("oversized or absent export")
    def unique(pairs):
        value = {}
        for k, v in pairs:
            if k in value:
                _deny("duplicate JSON key")
            value[k] = v
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _deny("non-finite JSON"))
    except (ValueError, TypeError, UnicodeError):
        _deny("malformed export")


def _read_public_pin(path):
    """Root-installed 0444 nonsecret authorization (never root 0600 STATE)."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        _deny("pin path unsafe")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                _deny("mutable pin ancestry")
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=fd)
        try:
            st = os.fstat(leaf)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                    or stat.S_IMODE(st.st_mode) != 0o444
                    or st.st_nlink != 1 or not 0 < st.st_size <= 8192):
                _deny("untrusted installed pin")
            raw = os.read(leaf, 8193)
            if len(raw) > 8192:
                _deny("oversized pin")
        finally:
            os.close(leaf)
        return _json(raw)
    except OSError:
        _deny("installed pin unreadable")
    finally:
        os.close(fd)


def _b64(s, length):
    if type(s) is not str or len(s) > 200:
        _deny("invalid key/signature")
    try:
        raw = base64.b64decode(s, validate=True)
    except (ValueError, TypeError):
        _deny("invalid key/signature")
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != s:
        _deny("noncanonical key/signature")
    return raw


def _time(s):
    if type(s) is not str or len(s) > 80:
        _deny("unbounded timestamp")
    try:
        parsed = datetime.fromisoformat(s)
        if parsed.utcoffset() is None:
            _deny("timestamp lacks timezone")
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        _deny("invalid timestamp")


def verify(raw, pin, *, task, now=None):
    """Verify export against separately installed Host/public-key/boot epoch."""
    if type(pin) is not dict or set(pin) != _PIN or pin["schema"] != PIN:
        _deny("root public pin absent")
    if task not in TASKS or any(
        type(pin[k]) is not str or not pin[k] for k in
        ("host_id", "installation_id", "lane", "lane_owner", "boot_id")
    ):
        _deny("unapproved task/Host")
    if (not _SHA.fullmatch(pin["chain_policy_sha256"])
            or not _SHA.fullmatch(pin["original_catalogue_sha256"])
            or type(pin["epoch"]) is not int or pin["epoch"] < 1
            or not _UUID.fullmatch(pin["boot_id"].replace("-", "").lower())):
        _deny("invalid owner epoch or policy")
    body = _json(raw)
    if type(body) is not dict or set(body) != _ENVELOPE:
        _deny("envelope schema changed")
    payload = body["payload"]
    if type(payload) is not dict or set(payload) != _FIELDS:
        _deny("owner payload incomplete")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    key = Ed25519PublicKey.from_public_bytes(_b64(pin["public_key"], 32))
    try:
        key.verify(_b64(body["signature"], 64), _canonical(payload))
    except InvalidSignature:
        _deny("wrong compiler Host signature")
    for field in ("host_id", "installation_id", "lane", "lane_owner",
                  "boot_id", "chain_policy_sha256", "epoch"):
        if payload.get(field) != pin[field] or type(payload[field]) is not type(pin[field]):
            _deny("foreign Host or revoked owner epoch")
    if payload["schema"] != CONTRACT or payload["task"] != task:
        _deny("task/schema mismatch")
    if not _SHA.fullmatch(payload["receipt_sha256"]):
        _deny("invalid owner receipt")
    if not _SHA.fullmatch(payload["catalogue_sha256"]):
        _deny("invalid catalogue hash")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    published, expiry = _time(payload["published_at"]), _time(payload["expires_at"])
    if published > current or expiry <= current or (expiry - published).total_seconds() > 900:
        _deny("expired, future, or overlong Host export")
    try:
        catalogue = task_catalogue.validate(payload["catalogue"])
    except (ValueError, KeyError, TypeError):
        _deny("invalid task catalogue")
    if (_hash(catalogue) != payload["catalogue_sha256"]
            or set(catalogue["tasks"]) != {task}
            or catalogue["tasks"][task]["lane"] != pin["lane"]
            or catalogue["tasks"][task]["lane_owner"] != pin["lane_owner"]
            or (task == TASKS[0] and
                payload["catalogue_sha256"] != pin["original_catalogue_sha256"])):
        _deny("catalogue differs from signed Host authority")
    return catalogue, payload["catalogue_sha256"]


def sign_host_export(payload, installed_signing_key):
    """Root-only owner signing primitive; not a gateway- or request-side API."""
    if os.geteuid() != 0:
        raise PermissionError("compiler root owner only")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if type(installed_signing_key) is not bytes or len(installed_signing_key) != 32:
        _deny("uninstalled private signing key")
    if type(payload) is not dict or set(payload) != _FIELDS:
        _deny("invalid owner export")
    # Signed bytes cannot claim a verified receipt without the *separate*
    # native reader proving it before this primitive is called.
    signature = Ed25519PrivateKey.from_private_bytes(
        installed_signing_key).sign(_canonical(payload))
    return _canonical({"payload": payload, "signature":
                       base64.b64encode(signature).decode("ascii")})
