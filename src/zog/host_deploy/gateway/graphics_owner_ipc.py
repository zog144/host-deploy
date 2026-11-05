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
SCHEMA = "zog-graphical-owner-ipc-v1"  # request frame; signed response is v2
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

def _trusted_selection_for_original(original, *, action):
    """Must be replaced by native installed-key/original-mapping reader.

    No gateway-controlled path, environment variable, IPC response or test
    convenience may become production authority. Until native installation
    attests signed operation mapping + pinned owner key this remains HOLD.
    """
    _deny()


def _current_external_history(selection):
    """Independent fresh S3 history read, NOT from gateway STATE or IPC reply."""
    _deny()


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
    if action not in ("submit-original", "preflight-original", "observe-original"):
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
    from . import graphics_owner_observation_v2 as v2
    original = {key: value for key, value in request.items()
                if key not in ("schema", "action", "nonce")}
    try:
        selection = _trusted_selection_for_original(original, action=action)
        history = _current_external_history(selection)
        return v2.verify(raw, action=action, nonce=nonce,
                         operation_id=operation_id,
                         original_request_sha256=original_request_sha256,
                         selected_trust=selection, current_history=history)
    except v2.OwnerObservationDenied:
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
    if result["status"] == "preflight-pending":
        # This is a READ-ONLY check of the original claim, never another send.
        result = observe_original(
            request_id=request_id, original_request_sha256=original_request_sha256,
            origin_repository=origin_repository,
            origin_issue_number=origin_issue_number,
            origin_trigger_actor=origin_trigger_actor,
            operation_id=operation_id, stage=stage, ordinal=ordinal,
            binding_sha256=binding_sha256,
            remote_request_sha256=remote_request_sha256)
    if (result["status"] != "preflight-ready" or
            result["ssm_state"] != "success" or
            result["command_id"] is None):
        _deny()
    return {"contract": "zog-protected-graphical-preflight-observation-v1",
            "ready": True, "mutation": False, "authenticated": True}

# Important: the above preflight API is intentionally held until the installed
# server supports preflight-original with a separate irreversible operation ID.

def observe_original(*, request_id, original_request_sha256,
                     origin_repository, origin_issue_number, origin_trigger_actor,
                     operation_id, stage, ordinal,
                     binding_sha256, remote_request_sha256):
    """Never creates a claim or sends an SSM command."""
    return _exchange(action="observe-original", request_id=request_id,
                     original_request_sha256=original_request_sha256,
                     origin_repository=origin_repository,
                     origin_issue_number=origin_issue_number,
                     origin_trigger_actor=origin_trigger_actor,
                     operation_id=operation_id, stage=stage, ordinal=ordinal,
                     binding_sha256=binding_sha256,
                     remote_request_sha256=remote_request_sha256)


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
    if (response["status"] not in ("stage-pending", "stage-succeeded")
            or response["ssm_state"] not in ("pending", "success")
            or response["command_id"] is None):
        _deny()
    return response["command_id"]
