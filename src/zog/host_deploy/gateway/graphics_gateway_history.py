"""Root-only authenticated original gateway request/dispatch authority.

Local copied gateway ledger is NOT provenance. A distinct Command-Center
signer, independently pinned by the compiler-Host installer, must sign exact
original request, dispatch and completed pipeline digests before promotion.
Native receiver/transport installation is separately gated.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re

from . import graphics_generation_chain as chain
from . import fresh_native_owner as native

SCHEMA = "host-deploy-graphical-gateway-history-grant-v1"
PIN = "host-deploy-graphical-command-center-history-issuer-v1"
_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
_ID = re.compile(r"[a-f0-9]{32}\Z")
_LANE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")


class HistoryAuthorityBlocked(RuntimeError):
    pass


def _deny():
    raise HistoryAuthorityBlocked("graphical-original-gateway-history-unauthenticated")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _hash(value):
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _key(text):
    if type(text) is not str:
        _deny()
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        _deny()
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        _deny()
    return raw


def _pin(policy):
    record = chain._read_locked(chain.STORE / "gateway-history-issuer-v1.json")
    expected = {"schema", "host_id", "installation_id", "lane",
                "boot_id", "epoch", "source_revision", "monthly_pin_identity",
                "chain_policy_sha256", "public_key", "revoked"}
    if (type(record) is not dict or set(record) != expected
            or record["schema"] != PIN
            or record["revoked"] is not False
            or type(record["epoch"]) is not int or record["epoch"] < 1
            or record["boot_id"] != native._boot()
            or any(record.get(k) != policy.get(k) for k in (
                "host_id", "installation_id", "lane",
                "source_revision", "monthly_pin_identity"))
            or record["chain_policy_sha256"] != chain._hash(policy)):
        _deny()
    _key(record["public_key"])
    return record


def _verify(grant, pin, policy, request_id, request, dispatch, progress):
    if type(grant) is not dict or set(grant) != {"payload", "signature"}:
        _deny()
    payload = grant["payload"]
    expected = {"schema", "request_id", "request_sha256", "dispatch_sha256",
                "progress_sha256", "pipeline_id", "task", "host_id",
                "installation_id", "lane", "boot_id", "epoch",
                "source_revision", "monthly_pin_identity",
                "chain_policy_sha256", "sequence"}
    if type(payload) is not dict or set(payload) != expected:
        _deny()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        sig = base64.b64decode(grant["signature"], validate=True)
        if len(sig) != 64:
            _deny()
        Ed25519PublicKey.from_public_bytes(_key(pin["public_key"])).verify(
            sig, _canonical(payload))
    except (ValueError, TypeError, InvalidSignature):
        _deny()
    if (payload["schema"] != SCHEMA
            or payload["request_id"] != request_id
            or not _ID.fullmatch(request_id)
            or payload["task"] not in chain.TASKS[:2]
            or type(payload["lane"]) is not str
            or not _LANE.fullmatch(payload["lane"])
            or payload["task"] != request.get("request", {}).get(
                "parameters", {}).get("task")
            or payload["pipeline_id"] != progress.get("pipeline_id")
            or payload["request_sha256"] != _hash(request)
            or payload["dispatch_sha256"] != _hash(dispatch)
            or payload["progress_sha256"] != _hash(progress)
            or type(payload["sequence"]) is not int
            or payload["sequence"] < 1
            or any(payload.get(k) != pin[k] for k in (
                "host_id", "installation_id", "lane", "boot_id", "epoch",
                "source_revision", "monthly_pin_identity",
                "chain_policy_sha256"))):
        _deny()
    return payload


def verify_history(state_directory, policy, request_id, request, dispatch, progress):
    """Refuse unsigned, missing, altered, revoked or rebooted source history."""
    if os.geteuid() != 0:
        raise PermissionError("protected graphical gateway history root only")
    from .fresh_budget_guard import _protected_root
    _protected_root(chain.STORE)
    _protected_root(state_directory)
    pin = _pin(policy)
    grant_path = Path(state_directory) / "grants" / (request_id + ".json")
    return _verify(chain._read_locked(grant_path), pin, policy,
                   request_id, request, dispatch, progress)


def _once(path, raw):
    """First writer survives crashes; no replacement or automatic repair."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            _deny()
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def install_history_grant(state_directory, policy, signed_grant,
                          request_id, request, dispatch, progress):
    """Root owner only; same lock as worker admission, one Host stage forever.

    Missing or partial stage/grant is a permanent HOLD for independent
    reconciliation. A replaced command-center DynamicUser ledger cannot
    fabricate another original request or overwrite a signed owner claim.
    """
    if os.geteuid() != 0:
        raise PermissionError("graphical history installation root only")
    from .fresh_budget_guard import _protected_root
    from . import fresh_canary_owner as canary
    _protected_root(state_directory)
    with canary.locked(native):
        pin = _pin(policy)
        accepted = _verify(signed_grant, pin, policy,
                           request_id, request, dispatch, progress)
        directory = Path(state_directory) / "grants"
        stages = Path(state_directory) / "stage-once"
        _protected_root(directory)
        _protected_root(stages)
        stage = stages / (accepted["lane"] + "--" + accepted["task"] + ".json")
        grant = directory / (request_id + ".json")
        # Existing stale, partial or symlink file: never rewrite or retry.
        if stage.exists() or stage.is_symlink() or grant.exists() or grant.is_symlink():
            _deny()
        stage_record = _canonical({
            "schema": "host-deploy-protected-graphical-stage-claim-v1",
            "host_id": accepted["host_id"],
            "installation_id": accepted["installation_id"],
            "boot_id": accepted["boot_id"], "epoch": accepted["epoch"],
            "request_id": request_id, "task": accepted["task"],
            "lane": accepted["lane"],
            "grant_sha256": _hash(signed_grant),
            "dispatch_sha256": accepted["dispatch_sha256"],
            "sequence": accepted["sequence"],
        })
        # Stage marker is committed FIRST. A crash before the grant
        # permanently blocks a second request; do not make a new marker.
        _once(stage, stage_record)
        _once(grant, _canonical(signed_grant))
        return _hash(signed_grant)
