"""Mandatory current graphical signing-key checkpoint verification.

No caller-supplied reader, key, socket, cache or fallback exists. The
independently installed root-owned checkpoint anchor is a native prerequisite.
This consumer has NO privilege to install or reset that anchor/issuer.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ANCHOR="/etc/zog/host-deploy/graphical-external-checkpoint-authority-v1.json"
SOCKET="/run/zog/host-deploy/graphical-external-checkpoint.sock"
SCHEMA="zog-host-install-graphical-external-monotonic-checkpoint-v1"
DOMAIN=b"zog-graphical-external-checkpoint-v1\x00"
ANCHOR_SCHEMA="zog-host-deploy-graphical-external-checkpoint-authority-v1"
FIELDS={"schema","host_id","installation_id","epoch","sequence",
        "pin_sha256","approval_sha256","nonce","signature_ed25519"}
HEX=re.compile(r"[0-9a-f]{64}\Z")

class CheckpointUnavailable(ValueError):
    pass

def _deny():
    raise CheckpointUnavailable("graphical external checkpoint unavailable") from None

def _canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def _parse(raw):
    if type(raw) is not bytes or not 0<len(raw)<=8192:_deny()
    def unique(pairs):
        row={}
        for k,v in pairs:
            if k in row:_deny()
            row[k]=v
        return row
    try:
        row=json.loads(raw,object_pairs_hook=unique,
                       parse_constant=lambda _: _deny())
        if type(row) is not dict or _canonical(row)!=raw:_deny()
        return row
    except (ValueError,TypeError,UnicodeError,OverflowError):
        _deny()

def _read_anchor():
    parts=Path(ANCHOR).parts[1:]
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|
                        os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nxt
            info=os.fstat(fd)
            if info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:_deny()
        leaf=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            st=os.fstat(leaf)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1
                    or (st.st_uid,st.st_gid)!=(0,0)
                    or stat.S_IMODE(st.st_mode)!=0o444
                    or not 0<st.st_size<=8192):
                _deny()
            raw=os.read(leaf,8193)
            if len(raw)!=st.st_size:_deny()
        finally:
            os.close(leaf)
        anchor=_parse(raw)
        if (set(anchor)!={"schema","public_key","public_key_sha256",
                          "peer_uid","operator_key_sha256"}
                or anchor["schema"]!=ANCHOR_SCHEMA
                or type(anchor["peer_uid"]) is not int
                or not 1000<=anchor["peer_uid"]<2**31
                or type(anchor["operator_key_sha256"]) is not str
                or not HEX.fullmatch(anchor["operator_key_sha256"])):
            _deny()
        try:
            key=base64.b64decode(anchor["public_key"],validate=True)
        except (ValueError,TypeError):
            _deny()
        if (len(key)!=32 or base64.b64encode(key).decode()!=anchor["public_key"]
                or hashlib.sha256(key).hexdigest()!=anchor["public_key_sha256"]
                or anchor["public_key_sha256"]==anchor["operator_key_sha256"]):
            _deny()
        return anchor,key,raw
    except OSError:
        _deny()
    finally:
        os.close(fd)

def _query_checkpoint(nonce,host_id,installation_id,uid):
    request=_canonical({"schema":"zog-graphical-checkpoint-read-v1",
                        "nonce":nonce,"host_id":host_id,
                        "installation_id":installation_id})
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(3)
            peer.connect(SOCKET)
            _,actual_uid,_=struct.unpack("3i",peer.getsockopt(
                socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if actual_uid!=uid:_deny()
            peer.sendall(request+b"\n")
            reply=bytearray()
            while len(reply)<=8192:
                data=peer.recv(min(4096,8193-len(reply)))
                if not data:break
                reply.extend(data)
        if not 0<len(reply)<=8192:_deny()
        return bytes(reply).strip()
    except OSError:
        _deny()

def require_current_checkpoint(pin):
    """Mandatory fresh independently signed read, never a caller callback."""
    if type(pin) is not dict:_deny()
    anchor,key,original=_read_anchor()
    nonce=os.urandom(24).hex()
    body=_parse(_query_checkpoint(nonce,pin.get("host_id"),
        pin.get("installation_id"),anchor["peer_uid"]))
    if (set(body)!=FIELDS or body["schema"]!=SCHEMA
            or body["nonce"]!=nonce
            or body["host_id"]!=pin.get("host_id")
            or body["installation_id"]!=pin.get("installation_id")
            or body["epoch"]!=pin.get("epoch")
            or type(body["epoch"]) is not int or body["epoch"]<1
            or type(body["sequence"]) is not int or body["sequence"]<1
            or body["pin_sha256"]!=hashlib.sha256(_canonical(pin)).hexdigest()
            or type(body["approval_sha256"]) is not str
            or not HEX.fullmatch(body["approval_sha256"])
            or hashlib.sha256(base64.b64decode(
                pin["public_key"],validate=True)).hexdigest()==
                anchor["public_key_sha256"]):
        _deny()
    try:
        proof=base64.b64decode(body["signature_ed25519"],validate=True)
        if (len(proof)!=64 or base64.b64encode(proof).decode()!=
                body["signature_ed25519"]):
            _deny()
        Ed25519PublicKey.from_public_bytes(key).verify(proof,DOMAIN+
            _canonical({k:v for k,v in body.items() if k!="signature_ed25519"}))
    except (InvalidSignature,ValueError,TypeError,KeyError):
        _deny()
    # Key rotation of the checkpoint anchor during the request is a HOLD.
    # The native installer must separately guarantee nonrollback of anchor.
    if _read_anchor()[2]!=original:_deny()
    return body
