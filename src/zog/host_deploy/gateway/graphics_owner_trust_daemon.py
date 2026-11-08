"""Systemd socket-activated Task C trust/history broker; source-only admission.

This service can serve an independently installed read-only authority without
granting the gateway any checkpoint-write or SSM credential. The production
constructor remains denied until root-control/host-install native admission
selects real original authority and the separate GetObject-only credential.

The exposed functions are strictly source-test seams, not RPC authority.
"""
from __future__ import annotations

import os
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import graphics_owner_trust_history as protocol
from . import graphics_owner_trust_service as attest

SOCKET = protocol.SOCKET
FRAME_MAX = protocol.MAX_FRAME
# Only an independently reviewed installed source change, NOT configuration,
# can enable this. No environment variable/CLI flag/test fixture unlocks it.
NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED = False


def hold():
    protocol.deny()


@dataclass(frozen=True)
class InstalledReadOnlyAuthority:
    """Opaque, installed source-selected dependencies, never IPC input."""
    registry: object
    issuer_evidence: dict
    issuer_public_key: bytes
    observation_public_key: bytes
    checkpoint: object
    signed_pin: dict
    broker_signer: object
    installed_source_sha256: str
    original_checkpoint: dict
    gateway_uid: int
    gateway_gid: int
    gateway_executable_sha256: str
    gateway_cgroup: str
    backend_recheck: object = None


def _activated_socket():
    """Accept exactly one systemd AF_UNIX SOCK_STREAM listener, no bind fallback."""
    if (os.geteuid() != 0 or
            os.environ.get("LISTEN_PID") != str(os.getpid()) or
            os.environ.get("LISTEN_FDS") != "1" or
            os.environ.get("LISTEN_FDNAMES") not in (None, "trust-history")):
        hold()
    try:
        listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
        if (listener.getsockname() != SOCKET or
                listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1 or
                listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM):
            hold()
        protocol._protected_path(SOCKET, is_socket=True)
        return listener
    except (OSError, ValueError):
        hold()


def _peer_identity(connection, authority):
    """Root-selected gateway identity, never a received identity string."""
    if (type(authority.gateway_uid) is not int or authority.gateway_uid < 1000
            or type(authority.gateway_gid) is not int or authority.gateway_gid <= 0
            or not protocol.v2.match(authority.gateway_executable_sha256,
                                     protocol.v2.SHA)
            or type(authority.gateway_cgroup) is not str
            or not authority.gateway_cgroup.startswith("/system.slice/")
            or not authority.gateway_cgroup.endswith(".service")):
        hold()
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0 or uid != authority.gateway_uid or gid != authority.gateway_gid:
            hold()
        # The exact observed process image and cgroup are checked by a
        # separately protected native peer inspector. Fail-closed until it
        # produces an identity-bound accepted witness.
        return pid
    except (OSError, struct.error):
        hold()


def _native_peer_witness(pid, authority):
    """Delegated to root-control installed peer verifier; never guess a PID."""
    from zog.root_control.graphical_task_c_native import installed_peer
    installed_peer(pid, {
        "gateway_uid": authority.gateway_uid,
        "gateway_gid": authority.gateway_gid,
        "gateway_executable_sha256": authority.gateway_executable_sha256,
        "gateway_cgroup": authority.gateway_cgroup,
    })


def _request(connection):
    """Read exactly one bounded canonical newline frame."""
    raw = bytearray()
    while len(raw) <= FRAME_MAX:
        try:
            part = connection.recv(min(4096, FRAME_MAX + 1 - len(raw)))
        except (OSError, TimeoutError):
            hold()
        if not part:
            break
        raw.extend(part)
        if b"\n" in part:
            break
    if (len(raw) < 2 or len(raw) > FRAME_MAX
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1):
        hold()
    return protocol._decoded(bytes(raw[:-1]))


def serve_connection(connection, authority, *, now=None):
    """Positive only for independently selected, read-only native authority.

    Neither the request nor a gateway caller can select S3 role, signer,
    original mapping, compiled source, approval or checkpoint genesis.
    """
    if type(authority) is not InstalledReadOnlyAuthority:
        hold()
    pid = _peer_identity(connection, authority)
    _native_peer_witness(pid, authority)
    if authority.original_checkpoint.get("schema") == (
            "zog-task-c-installation-storage-authority-v1"):
        # The v3 trusted provider, not the gateway IPC, supplies this reader.
        # A retained mapping signature alone does not attest mounted STATE.
        if not callable(authority.backend_recheck):
            hold()
        observed = authority.backend_recheck()
        if (type(observed) is not dict or
                set(observed) != {
                    "backend", "registry_sha256",
                    "installation_scope_sha256", "native_observer_sha256",
                    "observation_sha256"}
                or observed["installation_scope_sha256"] !=
                    authority.checkpoint.scope or
                observed["registry_sha256"] !=
                    authority.checkpoint.registry_sha):
            hold()
    frame = _request(connection)
    if now is None:
        now = int(time.time())
    if type(now) is not int:
        hold()
    response = attest.attest_original(
        frame, registry=authority.registry,
        issuer_evidence=authority.issuer_evidence,
        issuer_public_key=authority.issuer_public_key,
        now=now,
        observation_public_key=authority.observation_public_key,
        checkpoint=authority.checkpoint,
        signed_pin=authority.signed_pin,
        broker_signer=authority.broker_signer,
        installed_source_sha256=authority.installed_source_sha256,
        independently_retained_original_checkpoint=authority.original_checkpoint,
    )
    wire = protocol.canonical(response) + b"\n"
    if len(wire) > FRAME_MAX:
        hold()
    connection.sendall(wire)
    return response


def installed_runtime():
    """Select root-control PR40's original-authority constructor only.

    The root provider verifies genuine installed operator/issuer grants,
    source and gateway identity, separately anchored original checkpoint,
    pinned broker signer and an exclusively read-only S3 session. No gateway
    frame, environment option or fallback provides any of these inputs.

    This callable is deliberately not reachable from main() while the native
    admission gate is false; source interoperability is not service approval.
    """
    if not NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED:
        hold()
    from zog.root_control.graphical_task_c_trust_authority import (
        installed_readonly_authority,
    )
    selected = installed_readonly_authority()
    if type(selected) is not InstalledReadOnlyAuthority:
        hold()
    return selected


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        hold()
    if not NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED:
        hold()
    selected = installed_runtime()
    if type(selected) is not InstalledReadOnlyAuthority:
        hold()
    listener = _activated_socket()
    with listener:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                hold()
            with conn:
                conn.settimeout(5)
                try:
                    serve_connection(conn, selected)
                except (protocol.TrustUnavailable, ValueError, OSError,
                        TimeoutError):
                    # Denial is not a signed observation or a send grant.
                    try:
                        conn.sendall(b'{"error":"trust-broker-denied"}\n')
                    except OSError:
                        pass


if __name__ == "__main__":
    main()
