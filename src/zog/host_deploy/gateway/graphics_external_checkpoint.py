"""Mandatory independently signed live antirollback checkpoint for graphical keys.

This gateway cannot create an authority. A protected installer must pin the
separate checkpoint issuer and provision the actual online relay/issuer. The
relay merely transports an Ed25519 proof from a different rollback domain.
No caller can inject a reader, key, response, endpoint or disable the check.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

CHECKPOINT_PIN = "/etc/zog/host-deploy/graphical-external-checkpoint-pin-v1.json"
CHECKPOINT_SOCKET = "/run/zog/host-deploy/graphical-external-checkpoint.sock"
PIN_SCHEMA = "zog-host-install-external-checkpoint-relay-pin-v1"
CHECKPOINT_SCHEMA = "zog-host-install-graphical-external-monotonic-checkpoint-v1"
REQUEST_SCHEMA = "zog-graphical-external-checkpoint-read-v1"
DOMAIN = b"zog-graphical-external-checkpoint-v1\x00"
FIELDS = frozenset(("schema", "host_id", "installation_id", "epoch", "pin_sha256",
                    "approval_sha256", "sequence", "nonce", "signature_ed25519"))
PIN_FIELDS = frozenset(("schema", "host_id", "installation_id",
                        "external_public_key", "external_key_sha256", "relay_uid"))
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_BYTES = 8192


class CheckpointBlocked(ValueError):
    pass


def _deny():
    raise CheckpointBlocked("independent graphical checkpoint unavailable") from None


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, UnicodeError):
        _deny()


def _parse(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES: _deny()
    def unique(pairs):
        value = {}
        for k, v in pairs:
            if k in value: _deny()
            value[k] = v
        return value
    try:
        record = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: _deny())
        if type(record) is not dict or _canonical(record) != raw:
            _deny()
        return record
    except (UnicodeError, TypeError, ValueError, OverflowError):
        _deny()


def _installed_pin():
    """No-follow exact fixed root-owned 0444 file and all ancestors."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = Path(CHECKPOINT_PIN).parts[1:]
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            st = os.fstat(descriptor)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                    or st.st_mode & 0o022):
                _deny()
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=descriptor)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                    or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o444
                    or st.st_nlink != 1 or not 0 < st.st_size <= MAX_BYTES):
                _deny()
            raw = os.read(fd, MAX_BYTES+1)
            if len(raw) != st.st_size: _deny()
        finally:
            os.close(fd)
    except OSError:
        _deny()
    finally:
        os.close(descriptor)
    pin = _parse(raw)
    if (set(pin) != PIN_FIELDS or pin["schema"] != PIN_SCHEMA
            or type(pin["host_id"]) is not str or not pin["host_id"]
            or type(pin["installation_id"]) is not str or not pin["installation_id"]
            or type(pin["relay_uid"]) is not int
            or not 1000 <= pin["relay_uid"] < 2**31
            or type(pin["external_key_sha256"]) is not str
            or HEX.fullmatch(pin["external_key_sha256"]) is None):
        _deny()
    try:
        key = base64.b64decode(pin["external_public_key"], validate=True)
    except (ValueError, TypeError):
        _deny()
    if (len(key) != 32 or
            base64.b64encode(key).decode("ascii") != pin["external_public_key"]
            or hashlib.sha256(key).hexdigest() != pin["external_key_sha256"]):
        _deny()
    return pin, key


def _exchange(nonce, pin):
    """Local Unix relay UID + signed online checkpoint, never an offline cache."""
    request = _canonical({
        "schema": REQUEST_SCHEMA, "nonce": nonce,
        "host_id": pin["host_id"], "installation_id": pin["installation_id"]
    })
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(3.0)
            peer.connect(CHECKPOINT_SOCKET)
            packed = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", packed)
            if uid != pin["relay_uid"]: _deny()
            peer.sendall(request + b"\n")
            reply = bytearray()
            while len(reply) <= MAX_BYTES:
                part = peer.recv(min(4096, MAX_BYTES+1-len(reply)))
                if not part: break
                reply.extend(part)
            if not reply or len(reply) > MAX_BYTES: _deny()
            return bytes(reply).strip()
    except OSError:
        _deny()


def checked_snapshot(raw, *, nonce, pin, key, current):
    """Independent Host/installation/nonce/highwater; old local snapshots deny."""
    record = _parse(raw)
    if (set(record) != FIELDS or record["schema"] != CHECKPOINT_SCHEMA
            or type(nonce) is not str or
            re.fullmatch(r"[a-f0-9]{48}", nonce) is None
            or record["nonce"] != nonce
            or record["host_id"] != pin["host_id"]
            or record["installation_id"] != pin["installation_id"]
            or type(record["epoch"]) is not int or record["epoch"] < 1
            or type(record["sequence"]) is not int or record["sequence"] < 1
            or type(record["pin_sha256"]) is not str
            or HEX.fullmatch(record["pin_sha256"]) is None
            or type(record["approval_sha256"]) is not str
            or HEX.fullmatch(record["approval_sha256"]) is None):
        _deny()
    try:
        signature = base64.b64decode(record["signature_ed25519"], validate=True)
        if (len(signature) != 64 or
                base64.b64encode(signature).decode("ascii") !=
                record["signature_ed25519"]):
            _deny()
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature, DOMAIN + _canonical({
                k: v for k, v in record.items() if k != "signature_ed25519"
            }))
    except (ValueError, TypeError, InvalidSignature):
        _deny()
    if (record["host_id"] != current["host_id"]
            or record["installation_id"] != current["installation_id"]
            or record["epoch"] != current["epoch"]
            or record["pin_sha256"] != hashlib.sha256(_canonical(current)).hexdigest()):
        _deny()
    return record


def require_current(current):
    """One fresh online signed check. Called before and after authority use."""
    if (type(current) is not dict or
            type(current.get("epoch")) is not int or
            not 1 <= current["epoch"] < 2**53):
        _deny()
    pin, key = _installed_pin()
    try:
        host_key = base64.b64decode(current["public_key"], validate=True)
    except (ValueError, TypeError, KeyError):
        _deny()
    if (key == host_key or pin["host_id"] != current.get("host_id")
            or pin["installation_id"] != current.get("installation_id")):
        _deny()
    nonce = secrets.token_hex(24)
    return checked_snapshot(_exchange(nonce, pin), nonce=nonce,
                            pin=pin, key=key, current=current)
