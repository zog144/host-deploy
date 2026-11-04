"""Installed-only root graphical owner IPC, never a gateway-side SSM sender.

Source-only consumer; no installed pin or original operator approval exists in
ordinary environments. All endpoint, signing key, Host/installation/boot and
original operation selection inputs come from root-installed files, NEVER an
RPC caller, gateway request or environment variable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphics_protected_owner_handoff as selected

RPC_SCHEMA = "zog-graphical-owner-native-ipc-v1"
OBS_SCHEMA = "zog-graphical-owner-native-observation-v1"
DOMAIN = b"zog-graphical-owner-native-observation-v1\0"
PIN = Path("/etc/zog/graphical-owner/gateway-client.json")
APPROVALS = Path("/etc/zog/graphical-owner/gateway-approvals.json")
SOCKET = Path("/run/zog/graphical-owner.sock")
OWNER_SOURCE_SHA = "4a84cc347e7a82b08d21398a62689aff91be9e30"
MAX_WIRE = 16384


class NativeOwnerHold(RuntimeError):
    pass


def hold():
    raise NativeOwnerHold("native graphical owner or original operation unavailable")


def canonical(row):
    return json.dumps(row,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")


def parse(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE:
        hold()
    def unique(pairs):
        obj={}
        for k,v in pairs:
            if k in obj:
                hold()
            obj[k]=v
        return obj
    try:
        row=json.loads(raw,object_pairs_hook=unique,
                       parse_constant=lambda _:hold())
        if type(row) is not dict or canonical(row)!=raw:
            hold()
        return row
    except (ValueError,TypeError,UnicodeError,OverflowError):
        hold()


def _protected_file(path):
    """Root-published read-only public data. No gateway-controlled paths."""
    if not path.is_absolute() or ".." in path.parts:
        hold()
    cursor=Path("/")
    for part in path.parts[1:-1]:
        cursor=cursor/part
        st=os.lstat(cursor)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=0
                or st.st_mode&0o022):
            hold()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
                info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o644 or
                not 0<info.st_size<=MAX_WIRE):
            hold()
        data=os.read(fd,MAX_WIRE+1)
        if len(data)!=info.st_size:
            hold()
        return parse(data)
    except OSError:
        hold()
    finally:
        os.close(fd)


def _boot_id():
    try:
        boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        hold()
    if not boot or len(boot)>64:
        hold()
    return boot


class NativeOwnerClient:
    def __init__(self):
        pin=_protected_file(PIN)
        if (set(pin) != {"schema","root_source_sha","owner_public_key_b64",
                         "owner_key_sha256","boot_id","host_id",
                         "installation_id","state_volume_id",
                         "client_uid","client_gid","owner_uid","owner_gid",
                         "socket","enabled"} or
                pin["schema"]!="zog-graphical-native-owner-gateway-pin-v1" or
                pin["root_source_sha"]!=OWNER_SOURCE_SHA or
                pin["socket"]!=str(SOCKET) or
                pin["enabled"] is not True or
                pin["boot_id"]!=_boot_id() or
                pin["owner_uid"]!=0 or pin["owner_gid"]!=0 or
                pin["client_uid"]!=os.geteuid() or
                pin["client_gid"]!=os.getegid()):
            hold()
        try:
            key=base64.b64decode(pin["owner_public_key_b64"],validate=True)
            if len(key)!=32 or "sha256:"+hashlib.sha256(key).hexdigest() != pin["owner_key_sha256"]:
                hold()
            Ed25519PublicKey.from_public_bytes(key)
        except (TypeError,ValueError):
            hold()
        self.pin=pin
        self.public_key=key

    def _connect(self):
        try:
            info=os.lstat(SOCKET)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0
                    or stat.S_IMODE(info.st_mode)!=0o660):
                hold()
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            sock.settimeout(8)
            sock.connect(str(SOCKET))
            pid,uid,gid=struct.unpack(
                "3i",sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            now=os.lstat(SOCKET)
            if (pid<1 or uid!=0 or gid!=0 or
                    (now.st_dev,now.st_ino)!=(info.st_dev,info.st_ino)):
                sock.close()
                hold()
            return sock
        except (OSError,ValueError,struct.error):
            hold()

    def _exchange(self, *, action, request, approval=None, nonce=None):
        raw=canonical({"schema":RPC_SCHEMA,"action":action,
                       "request":request,"approval":approval,"nonce":nonce})
        if len(raw)>MAX_WIRE:
            hold()
        with self._connect() as sock:
            if sock.send(raw)!=len(raw):
                hold()
            try:
                value,anc,flags,_=sock.recvmsg(MAX_WIRE+1,0)
            except (OSError,TimeoutError):
                hold()
            if (anc or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)):
                hold()
            return parse(value)

    def _approval(self, binding, gateway_request_id, step):
        approved=_protected_file(APPROVALS)
        if (set(approved) != {"schema","protected_selection",
                             "requests","approvals","boot_id"} or
                approved["schema"] != "zog-graphical-gateway-installed-approvals-v1" or
                approved["boot_id"]!=self.pin["boot_id"] or
                type(approved["requests"]) is not dict or
                type(approved["approvals"]) is not dict):
            hold()
        actual=selected.selected_owner_request(
            binding,gateway_request_id,step,
            protected_selection=approved["protected_selection"])
        if (actual["host_id"]!=self.pin["host_id"] or
                actual["installation_id"]!=self.pin["installation_id"] or
                actual["state_volume_id"]!=self.pin["state_volume_id"]):
            hold()
        original=approved["requests"].get(actual["operation_id"])
        signature=approved["approvals"].get(actual["operation_id"])
        if original != actual or type(signature) is not dict:
            hold()
        return actual,signature

    def verify_observation(self, reply, *, request, nonce, expected_command=None):
        if (type(reply) is not dict or
                set(reply) != {"schema","scope_sha256","nonce",
                               "operation_id","request_sha256","outcome",
                               "command_id","revoked","signature_ed25519"} or
                reply["schema"]!=OBS_SCHEMA or reply["nonce"]!=nonce or
                reply["operation_id"]!=request["operation_id"] or
                reply["request_sha256"]!="sha256:"+hashlib.sha256(canonical(request)).hexdigest() or
                reply["outcome"] not in ("CLAIMED_UNCERTAIN","SENT_ORIGINAL") or
                type(reply["revoked"]) is not bool or
                reply["revoked"] or
                (reply["outcome"]=="CLAIMED_UNCERTAIN" and
                 reply["command_id"] is not None) or
                (reply["outcome"]=="SENT_ORIGINAL" and
                 (type(reply["command_id"]) is not str or
                  not 1<=len(reply["command_id"])<=128)) or
                (expected_command is not None and reply["command_id"]!=expected_command)):
            hold()
        try:
            sig=base64.b64decode(reply["signature_ed25519"],validate=True)
            if len(sig)!=64:
                hold()
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                sig,DOMAIN+canonical({
                    k:v for k,v in reply.items() if k!="signature_ed25519"}))
        except (InvalidSignature,ValueError,TypeError,KeyError):
            hold()
        return {"outcome":reply["outcome"],
                "command_id":reply["command_id"]}

    def submit_original(self, binding, request_id, step):
        request,signed_approval=self._approval(binding,request_id,step)
        reply=self._exchange(action="submit",request=request,
                             approval=signed_approval,nonce=None)
        if (set(reply)!={"outcome","command_id"} or
                reply["outcome"]!="SENT_ORIGINAL" or
                type(reply["command_id"]) is not str):
            hold()
        nonce=secrets.token_hex(24)
        observation=self._exchange(action="observe",request=request,nonce=nonce)
        validated=self.verify_observation(
            observation,request=request,nonce=nonce,
            expected_command=reply["command_id"])
        if validated["outcome"]!="SENT_ORIGINAL":
            hold()
        return validated["command_id"]


def selected_sender(root,binding,step):
    """A native installed owner, not arbitrary caller callback or script."""
    client=NativeOwnerClient()
    request_id=binding["request_id"]
    return lambda _untrusted_script,seconds:client.submit_original(
        binding,request_id,step)


def selected_preflight(root,binding,step,stage_binding):
    """Preflight requires a distinct independently approved operation.

    Native preflight command admission/result verification is not yet wired.
    Do NOT turn a signed stage claim into a bypassable preflight grant.
    """
    hold()
