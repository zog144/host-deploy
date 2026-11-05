"""Selected read-only Task C trust/history broker consumer.

The gateway never receives S3/SSM credentials or original operator keys.
Source deployment is deliberately disabled pending an independently approved
native pin for the separate root-owned broker and its installed source/roles.
"""
import base64
import hashlib
import json
import os
import re
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from . import graphics_owner_observation_v2 as v2

SCHEMA = "zog-graphical-task-c-trust-history-v1"
DOMAIN = b"zog-graphical-task-c-trust-history-v1\0"
SOCKET = "/run/zog/graphical-owner-trust.sock"
PIN = Path("/etc/zog/graphical-owner/gateway-trust-pin.json")
MAX_FRAME = 8192
MAX_PIN = 2048
# Must be frozen into a separately reviewed exact installed consumer. NEVER
# take this pin SHA from the gateway ledger, RPC, environment or SSM request.
APPROVED_PIN_SHA256 = None
TRUST_KEYS = frozenset(("public_key", "public_key_sha256",
    "owner_request_sha256", "scope_sha256", "host_id", "installation_id",
    "state_volume_id", "authority_epoch"))
ORIGINAL_KEYS = frozenset((
    "request_id", "original_request_sha256", "origin_repository",
    "origin_issue_number", "origin_trigger_actor", "operation_id", "stage",
    "ordinal", "binding_sha256", "remote_request_sha256"))
PIN_KEYS = frozenset(("schema","broker_public_key","owner_observation_public_key",
                      "original_checkpoint_sha256","installed_owner_source",
                      "installed_broker_source","installation_id",
                      "state_volume_id","scope_sha256"))
WIRE_KEYS = frozenset(("schema","nonce","action","original",
                       "selected_trust","current_history","pin_sha256",
                       "signature_ed25519"))
HEX64 = re.compile(r"[a-f0-9]{64}\Z")

class TrustUnavailable(RuntimeError):
    pass

def deny():
    raise TrustUnavailable("protected original trust and independent S3 history unavailable")

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")

def _unique(pairs):
    result = {}
    for k,v in pairs:
        if k in result: deny()
        result[k]=v
    return result

def _decoded(raw):
    try:
        value=json.loads(raw,object_pairs_hook=_unique,
                         parse_constant=lambda _:deny())
        if canonical(value)!=raw: deny()
        return value
    except (ValueError,TypeError,UnicodeError,OverflowError):
        deny()

def _protected_path(path, is_socket=False):
    path=Path(path)
    for directory in (Path("/"),Path("/run") if is_socket else Path("/etc"),
                      path.parent):
        try: info=os.lstat(directory)
        except OSError: deny()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode)&0o022):
            deny()
    try: info=os.lstat(path)
    except OSError: deny()
    if info.st_uid!=0 or (stat.S_ISSOCK(info.st_mode) if is_socket
                           else stat.S_ISREG(info.st_mode)) is False:
        deny()
    if is_socket:
        if stat.S_IMODE(info.st_mode)!=0o660: deny()
    elif stat.S_IMODE(info.st_mode)!=0o644 or info.st_nlink!=1:
        deny()

def selected_pin():
    """Read exact installed public pin with a separately approved SHA.

    A root-owned file is not itself proof of original operator approval; Work
    must attest the fixed SHA and installed-byte custody independently.
    """
    if type(APPROVED_PIN_SHA256) is not str or not v2.match(
            APPROVED_PIN_SHA256,v2.SHA):
        deny()
    _protected_path(PIN)
    try:
        fd=os.open(PIN,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o644 or (
                    not stat.S_ISREG(info.st_mode)) or info.st_size>MAX_PIN:
                deny()
            raw=os.read(fd,MAX_PIN+1)
        finally:os.close(fd)
    except OSError:
        deny()
    if (not raw or len(raw)>MAX_PIN or
            "sha256:"+hashlib.sha256(raw).hexdigest()!=APPROVED_PIN_SHA256):
        deny()
    row=_decoded(raw)
    if (type(row) is not dict or set(row)!=PIN_KEYS or
            row["schema"]!="zog-graphical-task-c-gateway-trust-pin-v1" or
            any(not v2.match(row[k],HEX64) for k in
                ("broker_public_key","owner_observation_public_key",
                 "installation_id","state_volume_id")) or
            not v2.match(row["scope_sha256"],v2.SHA) or
            not v2.match(row["original_checkpoint_sha256"],v2.SHA) or
            row["installed_owner_source"]!="5ad7d5ed72d1b72edc767a658de28506791a74d4" or
            not v2.match(row["installed_broker_source"],HEX64)):
        deny()
    return row,APPROVED_PIN_SHA256

@dataclass(frozen=True)
class AttestedSelection:
    trust: v2.SelectedOwnerTrust
    current_history: dict

def verify_broker_reply(raw, *, nonce, action, original, pin, pin_sha256):
    if (type(raw) is not bytes or not 0<len(raw)<=MAX_FRAME
            or type(original) is not dict or set(original)!=ORIGINAL_KEYS
            or action not in v2.ACTIONS or not v2.match(nonce,v2.H48)):
        deny()
    row=_decoded(raw)
    if (type(row) is not dict or set(row)!=WIRE_KEYS or row["schema"]!=SCHEMA
            or row["nonce"]!=nonce or row["action"]!=action
            or row["original"]!=original or row["pin_sha256"]!=pin_sha256
            or type(row["selected_trust"]) is not dict
            or set(row["selected_trust"])!=TRUST_KEYS
            or type(row["current_history"]) is not dict
            or set(row["current_history"])!={"sequence","history_sha256","revoked"}):
        deny()
    try:
        signature=base64.b64decode(row["signature_ed25519"],validate=True)
        if (len(signature)!=64 or
                base64.b64encode(signature).decode("ascii")!=row["signature_ed25519"]):
            deny()
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(pin["broker_public_key"])).verify(
                signature,DOMAIN+canonical({k:v for k,v in row.items()
                                            if k!="signature_ed25519"}))
        trusted=row["selected_trust"]
        selected=v2.SelectedOwnerTrust(
            public_key=bytes.fromhex(trusted["public_key"]),
            public_key_sha256=trusted["public_key_sha256"],
            owner_request_sha256=trusted["owner_request_sha256"],
            scope_sha256=trusted["scope_sha256"],
            host_id=trusted["host_id"],
            installation_id=trusted["installation_id"],
            state_volume_id=trusted["state_volume_id"],
            authority_epoch=trusted["authority_epoch"]).validate()
        if (trusted["public_key"]!=pin["owner_observation_public_key"] or
                trusted["installation_id"]!=pin["installation_id"] or
                trusted["state_volume_id"]!=pin["state_volume_id"] or
                trusted["scope_sha256"]!=pin["scope_sha256"]):
            deny()
        hist=row["current_history"]
        if (type(hist["sequence"]) is not int or hist["sequence"]<1
                or not v2.match(hist["history_sha256"],v2.SHA)
                or type(hist["revoked"]) is not bool or hist["revoked"]):
            deny()
        return AttestedSelection(selected,hist)
    except (ValueError,KeyError,TypeError,InvalidSignature,OverflowError):
        deny()

def _recv(peer):
    raw=bytearray()
    while len(raw)<MAX_FRAME+1:
        try: part=peer.recv(min(4096,MAX_FRAME+1-len(raw)))
        except (OSError,TimeoutError):deny()
        if not part:break
        raw.extend(part)
        if b"\n" in part:break
    if not raw.endswith(b"\n") or raw.count(b"\n")!=1 or len(raw)>MAX_FRAME:
        deny()
    return bytes(raw[:-1])

def select_original(original, *, action):
    """Post-owner-response broker check, read-only; never supplies sender grant."""
    if type(original) is not dict or set(original)!=ORIGINAL_KEYS: deny()
    pin,pin_sha=selected_pin()
    nonce=os.urandom(24).hex()
    req={"schema":SCHEMA,"nonce":nonce,"action":action,"original":original,
         "pin_sha256":pin_sha}
    payload=canonical(req)+b"\n"
    if len(payload)>MAX_FRAME: deny()
    _protected_path(SOCKET,is_socket=True)
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(5)
            peer.connect(SOCKET)
            pid,uid,gid=struct.unpack("3i",peer.getsockopt(
                socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
            if pid<=0 or uid!=0:deny()
            _protected_path(SOCKET,is_socket=True)
            peer.sendall(payload)
            raw=_recv(peer)
    except (OSError,TimeoutError,struct.error):
        deny()
    return verify_broker_reply(raw,nonce=nonce,action=action,
                               original=original,pin=pin,pin_sha256=pin_sha)
