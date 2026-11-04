"""Narrow, fail-closed graphical operation-owner IPC consumer.

This is a client protocol, not a protected owner installation. The root-owned
server must reconstruct authority independently; the gateway sends only an
original frozen operation identity, never a script, SSM credentials or a signer.
"""
import json
import os
import secrets
import socket
import stat
import struct

SOCKET_DIR = "/run/zog"
SOCKET_PATH = SOCKET_DIR + "/graphical-operation-owner.sock"
SCHEMA = "zog-graphical-owner-ipc-v1"
MAX_FRAME = 8192

class OwnerUnavailable(RuntimeError):
    pass

def _deny():
    raise OwnerUnavailable("protected graphical operation owner unavailable or invalid")

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")

def _check_path():
    # All ancestors of the root-installed endpoint must remain root-owned.
    # The installation owner must separately protect service/source identity.
    # Directories must not be group/world-writable, but the socket itself
    # NEEDS its exact root-installed 0660 mode for the dedicated client group.
    # Applying the directory prohibition to the socket would reject every
    # legitimate host-install Task C Unix endpoint.
    for path in ("/run", SOCKET_DIR):
        try:
            info = os.lstat(path)
        except OSError:
            _deny()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                (info.st_mode & 0o022)):
            _deny()
    try:
        endpoint = os.lstat(SOCKET_PATH)
    except OSError:
        _deny()
    if (not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 or
            stat.S_IMODE(endpoint.st_mode) != 0o660):
        _deny()

def _read_frame(sock):
    data = bytearray()
    while len(data) < MAX_FRAME + 1:
        try:
            chunk = sock.recv(min(4096, MAX_FRAME + 1 - len(data)))
        except (OSError, TimeoutError):
            _deny()
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_FRAME or not data.endswith(b"\n") or data.count(b"\n") != 1:
        _deny()
    return bytes(data[:-1])

def _exchange(*, action, request_id, original_request_sha256,
              origin_repository, origin_issue_number, origin_trigger_actor,
              operation_id, stage, ordinal,
              binding_sha256, remote_request_sha256):
    """Ask the independently installed owner to handle one ORIGINAL operation.

    The server MUST verify peer admission, independently authenticated original
    mapping, signed operator approval, current authority, stage-once grant,
    revocation and monotonic claim before its own fixed SSM sender.
    This client reply is NOT an authorization token.
    """
    import re
    if (any(type(x) is not str or re.fullmatch(r"[a-f0-9]{32}", x) is None
            for x in (request_id, operation_id))
            or type(stage) is not str
            or stage not in ("capabilities", "snapshot", "submit", "inspect")
            or type(ordinal) is not int or not 0 <= ordinal < 64
            or any(type(x) is not str or re.fullmatch(r"[a-f0-9]{64}", x) is None
                   for x in (binding_sha256, remote_request_sha256, original_request_sha256))
            or origin_repository != 'zog144/host-deploy'
            or type(origin_issue_number) is not int
            or not 1 <= origin_issue_number <= 2147483647
            or type(origin_trigger_actor) is not str
            or not 1 <= len(origin_trigger_actor) <= 100
            or re.fullmatch(r'[A-Za-z0-9-]+', origin_trigger_actor) is None):
        _deny()
    nonce = secrets.token_hex(24)
    if action not in ("submit-original", "preflight-original"):
        _deny()
    request = {"schema": SCHEMA, "action": action,
               "request_id": request_id, "operation_id": operation_id,
               "original_request_sha256": original_request_sha256,
               "origin_repository": origin_repository,
               "origin_issue_number": origin_issue_number,
               "origin_trigger_actor": origin_trigger_actor,
               "stage": stage, "ordinal": ordinal,
               "binding_sha256": binding_sha256,
               "remote_request_sha256": remote_request_sha256, "nonce": nonce}
    payload = _canonical(request) + b"\n"
    if len(payload) > MAX_FRAME:
        _deny()
    _check_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)
            peer.connect(SOCKET_PATH)
            # Root peer is necessary, NOT sufficient: native installer must
            # attest the selected binary, service, and protected state.
            pid, uid, gid = struct.unpack("3i", peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != 0 or pid <= 0:
                _deny()
            _check_path()
            peer.sendall(payload)
            raw = _read_frame(peer)
    except (OSError, TimeoutError, struct.error):
        _deny()
    try:
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    _deny()
                value[key] = item
            return value
        reply = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda x: _deny())
        if (type(reply) is not dict or
                set(reply) != {"schema", "nonce", "operation_id", "status", "command_id"}
                or reply["schema"] != SCHEMA or reply["nonce"] != nonce
                or reply["operation_id"] != operation_id
                or reply["status"] != ("sent-original" if action == "submit-original" else "preflight-ready")
                or type(reply["command_id"]) is not str
                or not 1 <= len(reply["command_id"]) <= 128
                or any(ord(c) < 33 or ord(c) > 126
                       for c in reply["command_id"])
                or _canonical(reply) != raw):
            _deny()
        return reply
    except (ValueError, TypeError, UnicodeError):
        _deny()

def preflight_original(*, request_id, original_request_sha256,
                       origin_repository, origin_issue_number, origin_trigger_actor,
                       operation_id, stage, ordinal,
                       binding_sha256, remote_request_sha256):
    """Request the owner's separately approved original preflight operation.

    A preflight SSM command has its OWN irrevocable operation claim. The
    owner must reconstruct that preflight ID and the exact fixed command from
    protected original GitHub authorization, never trust client-selected code.
    """
    result = _exchange(action="preflight-original", request_id=request_id,
                       original_request_sha256=original_request_sha256,
                       origin_repository=origin_repository,
                       origin_issue_number=origin_issue_number,
                       origin_trigger_actor=origin_trigger_actor,
                       operation_id=operation_id, stage=stage, ordinal=ordinal,
                       binding_sha256=binding_sha256,
                       remote_request_sha256=remote_request_sha256)
    if result["status"] != "preflight-ready" or result["command_id"] is None:
        _deny()
    # A root UID and a matching nonce are not sufficient current-authority
    # attestation. Do not manufacture authenticated=True from an unsigned
    # response. The native owner must supply a verifier integrated with the
    # protected monotonic issuer and the originally approved preflight result.
    _deny()

# Important: the above preflight API is intentionally held until the installed
# server supports preflight-original with a separate irreversible operation ID.

def submit_original(*, request_id, original_request_sha256,
                    origin_repository, origin_issue_number, origin_trigger_actor,
                    operation_id, stage, ordinal,
                    binding_sha256, remote_request_sha256):
    response = _exchange(action="submit-original", request_id=request_id,
                         original_request_sha256=original_request_sha256,
                         origin_repository=origin_repository,
                         origin_issue_number=origin_issue_number,
                         origin_trigger_actor=origin_trigger_actor,
                         operation_id=operation_id, stage=stage, ordinal=ordinal,
                         binding_sha256=binding_sha256,
                         remote_request_sha256=remote_request_sha256)
    return response["command_id"]
