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
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import socket
import struct

from . import task_catalogue
from .graphics_generation_chain import TASKS, _hash, validate_policy

CONTRACT = "zog-host-deploy-graphical-chain-export-v1"
PIN = "zog-host-deploy-graphical-chain-remote-owner-pin-v1"
_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{32}\Z")
_FIELDS = {"schema", "task", "host_id", "installation_id", "lane",
           "lane_owner", "boot_id", "chain_policy_sha256",
           "catalogue", "catalogue_sha256", "receipt", "receipt_sha256",
           "published_at", "expires_at", "epoch"}
_ENVELOPE = {"payload", "signature"}
_PIN = {"schema", "host_id", "installation_id", "lane", "lane_owner",
        "boot_id", "chain_policy_sha256", "original_catalogue_sha256",
        "public_key", "epoch", "source_revision", "monthly_pin_identity",
        "first_base_generation_id", "first_receipt_sha256", "relay_uid"}
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
            or not _SHA.fullmatch(pin["first_receipt_sha256"])
            or type(pin["relay_uid"]) is not int
            or not 1000 <= pin["relay_uid"] < 2**31
            or not _SHA.fullmatch(pin["monthly_pin_identity"])
            or not re.fullmatch(r"[0-9a-f]{64}", pin["first_base_generation_id"])
            or type(pin["source_revision"]) is not str
            or not re.fullmatch(r"[0-9a-f]{40}", pin["source_revision"])
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
    receipt = payload["receipt"]
    if (type(receipt) is not dict
            or not _SHA.fullmatch(payload["receipt_sha256"])
            or _hash(receipt) != payload["receipt_sha256"]
            or receipt.get("catalogue_sha256") != payload["catalogue_sha256"]
            or receipt.get("source_revision") != pin["source_revision"]
            or receipt.get("monthly_pin_identity") != pin["monthly_pin_identity"]
            or receipt.get("host_id") != pin["host_id"]
            or receipt.get("installation_id") != pin["installation_id"]
            or receipt.get("lane") != pin["lane"]
            or receipt.get("lane_owner") != pin["lane_owner"]
            or receipt.get("compiler_authorized") is not False):
        _deny("protected receipt differs from signed catalogue")
    if task == TASKS[0]:
        if (payload["receipt_sha256"] != pin["first_receipt_sha256"]
                or receipt.get("accepted_base_generation_id")
                    != pin["first_base_generation_id"]):
            _deny("original fonts receipt differs")
    elif (receipt.get("schema") != "host-deploy-graphics-chain-step-installed-v1"
          or receipt.get("task") != task
          or receipt.get("status") != "installed-not-compiler-admission"
          or receipt.get("selection_generation_id")
            != pin["first_base_generation_id"]
          or receipt.get("graphical_predecessor_generation_id")
            != payload["catalogue"]["tasks"][task]["arguments"]["graphical_predecessor"]
          or receipt.get("chain_policy_sha256") != pin["chain_policy_sha256"]):
        _deny("successor protected receipt differs")
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
            or catalogue["tasks"][task]["source_revision"] != pin["source_revision"]
            or catalogue["tasks"][task]["monthly_pin_identity"] != pin["monthly_pin_identity"]
            or catalogue["tasks"][task]["arguments"]["selection"] != pin["first_base_generation_id"]
            or (task == TASKS[0] and
                payload["catalogue_sha256"] != pin["original_catalogue_sha256"])):
        _deny("catalogue differs from signed Host authority")
    return catalogue, payload["catalogue_sha256"]


def _owner_once(path, raw):
    """No-replace root 0600 write and parent fsync; crash leaves HOLD."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            _deny("short native export receipt")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def sign_host_export(*args, **kwargs):
    """Retired unsafe arbitrary-payload signer: root callers cannot mint claims."""
    _deny("arbitrary root payload signing is forbidden")


def issue_native_step_export(*, task, published_at, expires_at):
    """Root only: derive every signed field from native protected files.

    Source-only fixed owner entrypoint; a genuine installer must create/rotate
    root-owned key and epoch state before any native export is possible.
    """
    if os.geteuid() != 0:
        raise PermissionError("compiler root owner only")
    if task not in TASKS:
        _deny("unreviewed compiler task")
    from . import graphics_generation_chain as chain
    from . import graphics_catalogue_owner as first
    from . import fresh_canary_owner as canary
    from . import fresh_native_owner as owner
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with canary.locked(owner):
        policy = chain.validate_policy(chain._read_locked(chain.POLICY))
        if not chain._verified_native_owner(policy):
            _deny("native worker owner unavailable")
        try:
            epoch = chain._read_locked(chain.STORE / "graphical-export-epoch-v1.json")
        except (OSError, ValueError):
            _deny("protected Host epoch not installed")
        if (type(epoch) is not dict or set(epoch) != {
                "schema", "host_id", "installation_id", "lane", "lane_owner",
                "boot_id", "epoch", "chain_policy_sha256", "source_revision",
                "monthly_pin_identity", "public_key_sha256"
            } or epoch["schema"] != "host-deploy-graphical-export-epoch-v1"
            or any(epoch.get(key) != policy.get(key) for key in (
                "host_id", "installation_id", "lane", "lane_owner",
                "source_revision", "monthly_pin_identity"))
            or epoch["boot_id"] != owner._boot()
            or epoch["chain_policy_sha256"] != chain._hash(policy)
            or type(epoch["epoch"]) is not int or epoch["epoch"] < 1):
            _deny("protected Host epoch unavailable or revoked")
        catalogue, digest = chain.load_installed_step(
            task, policy_sha256=chain._hash(policy))
        receipt_path = (first.RECEIPT if task == TASKS[0]
                        else chain.FILES[task][1])
        receipt = chain._read_locked(receipt_path)
        if (receipt.get("catalogue_sha256") != digest
                or receipt.get("compiler_authorized") is not False):
            _deny("protected installed receipt differs")
        if (task == TASKS[0] and
                chain._hash(receipt) != policy["first_receipt_sha256"]):
            _deny("original receipt changed")
        keypath = chain.STORE / "graphical-export-signing-key-v1.json"
        try:
            key = chain._read_locked(keypath)
        except (OSError, ValueError):
            _deny("protected signer not installed")
        if (type(key) is not dict or set(key) != {"schema", "private_key"}
                or key["schema"] != "host-deploy-graphical-export-private-key-v1"):
            _deny("protected private signer unavailable")
        private = _b64(key["private_key"], 32)
        signer = Ed25519PrivateKey.from_private_bytes(private)
        from cryptography.hazmat.primitives import serialization
        pub = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if epoch["public_key_sha256"] != "sha256:" + hashlib.sha256(pub).hexdigest():
            _deny("issuer key differs from protected Host epoch")
        payload = {
            "schema": CONTRACT, "task": task,
            "host_id": policy["host_id"],
            "installation_id": policy["installation_id"],
            "lane": policy["lane"], "lane_owner": policy["lane_owner"],
            "boot_id": epoch["boot_id"], "epoch": epoch["epoch"],
            "chain_policy_sha256": chain._hash(policy),
            "catalogue": catalogue, "catalogue_sha256": digest,
            "receipt": receipt, "receipt_sha256": chain._hash(receipt),
            "published_at": published_at, "expires_at": expires_at,
        }
        if (_time(expires_at) <= _time(published_at)
                or (_time(expires_at)-_time(published_at)).total_seconds() > 300):
            _deny("protected exporter interval invalid")
        signature = signer.sign(_canonical(payload))
        wire = _canonical({"payload": payload,
                           "signature": base64.b64encode(signature).decode("ascii")})
        # A live epoch issuer may acknowledge ONLY an export which this
        # protected root owner actually published. No arbitrary relay digest.
        from .fresh_budget_guard import _protected_root
        publications = chain.STORE / "graphical-export-publications"
        _protected_root(publications)
        digest = hashlib.sha256(wire).hexdigest()
        _owner_once(publications / (digest + ".json"), _canonical({
            "schema": "host-deploy-protected-graphical-export-publication-v1",
            "export_sha256": "sha256:" + digest,
            "task": task, "host_id": epoch["host_id"],
            "installation_id": epoch["installation_id"],
            "boot_id": epoch["boot_id"], "epoch": epoch["epoch"],
            "chain_policy_sha256": epoch["chain_policy_sha256"],
            "catalogue_sha256": payload["catalogue_sha256"],
            "receipt_sha256": payload["receipt_sha256"],
            "expires_at": expires_at,
        }))
        return wire




def verify_live_ack(raw, pin, *, nonce, export_digest, task, now=None):
    """Distinct signed online reply; a cached export cannot prove live epoch."""
    if (type(nonce) is not str or not re.fullmatch(r"[a-f0-9]{64}", nonce)
            or type(export_digest) is not str or not _SHA.fullmatch(export_digest)
            or task not in TASKS):
        _deny("invalid live challenge")
    body = _json(raw)
    if type(body) is not dict or set(body) != _ENVELOPE:
        _deny("live Host proof missing")
    proof = body["payload"]
    required = {"schema", "nonce", "export_sha256", "task", "host_id",
                "installation_id", "lane", "lane_owner", "boot_id", "epoch",
                "chain_policy_sha256", "sequence", "observed_at", "expires_at"}
    if type(proof) is not dict or set(proof) != required:
        _deny("live Host proof incomplete")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    pub = Ed25519PublicKey.from_public_bytes(_b64(pin["public_key"], 32))
    try:
        pub.verify(_b64(body["signature"], 64), _canonical(proof))
    except InvalidSignature:
        _deny("wrong live Host signer")
    if (proof["schema"] != "host-deploy-graphical-live-epoch-v1"
            or proof["nonce"] != nonce
            or proof["export_sha256"] != export_digest
            or proof["task"] != task
            or type(proof["sequence"]) is not int or proof["sequence"] < 1
            or any(type(proof.get(k)) is not type(pin[k])
                   or proof[k] != pin[k] for k in (
                   "host_id", "installation_id", "lane", "lane_owner",
                   "boot_id", "epoch", "chain_policy_sha256"))):
        _deny("live Host boot, epoch or export differs")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    observed, expiry = _time(proof["observed_at"]), _time(proof["expires_at"])
    if (observed > now or expiry <= now or
            not 0 < (expiry - observed).total_seconds() <= 5):
        _deny("live Host proof stale or revoked")
    return proof


def _query_live_owner(pin, *, nonce, digest, task):
    """Always ask independent local relay for a *new* Host-signed nonce.

    The relay is transport, never authority. No relay => fail closed.
    The native root installer must separately install/review the relay and
    its UID/pin, and remote compiler root must sign only fresh epoch state.
    """
    endpoint = "/run/zog/host-deploy/graphical-host-epoch.sock"
    request = _canonical({"schema": "host-deploy-graphical-live-request-v1",
                          "nonce": nonce, "export_sha256": digest, "task": task})
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(3)
            peer.connect(endpoint)
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", credentials)
            if uid != pin["relay_uid"]:
                _deny("untrusted local epoch relay UID")
            peer.sendall(request + b"\n")
            reply = bytearray()
            while len(reply) <= 8192:
                data = peer.recv(min(4096, 8193-len(reply)))
                if not data:
                    break
                reply.extend(data)
            if not 0 < len(reply) <= 8192:
                _deny("live Host epoch response absent or oversized")
        return bytes(reply).strip()
    except (OSError, ValueError):
        _deny("live Host epoch relay unavailable")



def load_selected_step(directory, pin_path, task, policy_sha256):
    """Command-center source path: only signed, fresh compiler-Host exports.

    Transport is the existing authorized Host-to-command-center channel;
    receiving filesystem bytes is not authority. Neither root-only compiler
    policy nor a private Host signing key is read by the gateway.
    """
    if task not in TASKS or not isinstance(policy_sha256, str):
        _deny("unsupported task or missing pinned policy")
    pin = _read_public_pin(pin_path)
    if pin.get("chain_policy_sha256") != policy_sha256:
        _deny("original owner policy was revoked or changed")
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        _deny("missing gateway export cache")
    from .task_catalogue import TaskCatalogueError
    target = root / (task + ".json")
    if target.is_symlink():
        _deny("export entry is a symlink")
    try:
        with target.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
    except OSError:
        _deny("authenticated Host export missing")
    selected = verify(raw, pin, task=task)
    # Request a cryptographically new online nonce bound to *these exact*
    # export bytes. A stale cache or stale public pin is not sufficient.
    nonce = os.urandom(32).hex()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    live = _query_live_owner(pin, nonce=nonce, digest=digest, task=task)
    verify_live_ack(live, pin, nonce=nonce, export_digest=digest, task=task)
    return selected



def issue_native_live_epoch_ack(challenge_raw):
    """Fixed protected Host challenge entrypoint; not a network service.

    Respond only to a fresh nonce for an independently published export.
    Use native worker lock and durable nonce claims, not caller-provided
    epoch, source, signer or sequence. A crash retains the nonce HOLD.
    """
    if os.geteuid() != 0:
        raise PermissionError("compiler live epoch issuer root only")
    challenge = _json(challenge_raw)
    if (type(challenge) is not dict
            or set(challenge) != {"schema", "nonce", "export_sha256", "task"}
            or challenge["schema"] != "host-deploy-graphical-live-request-v1"
            or type(challenge["nonce"]) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", challenge["nonce"])
            or type(challenge["export_sha256"]) is not str
            or not _SHA.fullmatch(challenge["export_sha256"])
            or challenge["task"] not in TASKS):
        _deny("untrusted live epoch challenge")
    from . import graphics_generation_chain as chain
    from . import fresh_canary_owner as canary
    from . import fresh_native_owner as owner
    from .fresh_budget_guard import _protected_root
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    with canary.locked(owner):
        policy = chain.validate_policy(chain._read_locked(chain.POLICY))
        if not chain._verified_native_owner(policy):
            _deny("native worker epoch owner unavailable")
        try:
            epoch = chain._read_locked(chain.STORE / "graphical-export-epoch-v1.json")
        except (OSError, ValueError):
            _deny("protected epoch not installed")
        if (epoch.get("boot_id") != owner._boot()
                or epoch.get("chain_policy_sha256") != chain._hash(policy)
                or epoch.get("host_id") != policy["host_id"]
                or epoch.get("installation_id") != policy["installation_id"]
                or type(epoch.get("epoch")) is not int
                or epoch["epoch"] < 1):
            _deny("revoked compiler Host epoch")
        published = chain.STORE / "graphical-export-publications"
        nonces = chain.STORE / "graphical-live-nonces"
        _protected_root(published)
        _protected_root(nonces)
        digest = challenge["export_sha256"]
        try:
            receipt = chain._read_locked(
                published / (digest.split(":", 1)[1] + ".json"))
        except (OSError, ValueError):
            _deny("unknown or revoked protected export publication")
        if (type(receipt) is not dict
                or receipt.get("schema") !=
                  "host-deploy-protected-graphical-export-publication-v1"
                or receipt.get("export_sha256") != digest
                or receipt.get("task") != challenge["task"]
                or receipt.get("host_id") != policy["host_id"]
                or receipt.get("installation_id") != policy["installation_id"]
                or receipt.get("chain_policy_sha256") != chain._hash(policy)
                or receipt.get("boot_id") != epoch["boot_id"]
                or receipt.get("epoch") != epoch["epoch"]
                or _time(receipt["expires_at"]) <= datetime.now(timezone.utc)):
            _deny("publication not current in protected boot")
        try:
            key = chain._read_locked(
                chain.STORE / "graphical-export-signing-key-v1.json")
        except (OSError, ValueError):
            _deny("live Host signer not installed")
        if (type(key) is not dict or
                key.get("schema") != "host-deploy-graphical-export-private-key-v1"):
            _deny("wrong protected live signing key")
        private = Ed25519PrivateKey.from_private_bytes(
            _b64(key.get("private_key"), 32))
        pub = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if "sha256:" + hashlib.sha256(pub).hexdigest() != epoch["public_key_sha256"]:
            _deny("live issuer key rotated without epoch")
        entries = list(nonces.iterdir())
        if len(entries) >= 10000:
            _deny("bounded live nonce history exhausted; rotate epoch")
        for entry in entries:
            if (entry.is_symlink() or not entry.is_file()
                    or not re.fullmatch(r"[a-f0-9]{64}\.json", entry.name)):
                _deny("protected nonce ledger tampered")
        sequence = len(entries) + 1
        # Claim nonce before returning; even a lost response cannot replay it.
        _owner_once(nonces / (challenge["nonce"] + ".json"), _canonical({
            "schema": "host-deploy-protected-live-nonce-v1",
            "nonce": challenge["nonce"], "sequence": sequence,
            "export_sha256": digest, "boot_id": epoch["boot_id"],
            "epoch": epoch["epoch"]}))
        now = datetime.now(timezone.utc)
        proof = {
            "schema": "host-deploy-graphical-live-epoch-v1",
            "nonce": challenge["nonce"], "export_sha256": digest,
            "task": challenge["task"], "host_id": policy["host_id"],
            "installation_id": policy["installation_id"],
            "lane": policy["lane"], "lane_owner": policy["lane_owner"],
            "boot_id": epoch["boot_id"], "epoch": epoch["epoch"],
            "chain_policy_sha256": chain._hash(policy),
            "sequence": sequence, "observed_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=4)).isoformat(),
        }
        signature = private.sign(_canonical(proof))
        return _canonical({"payload": proof,
                           "signature": base64.b64encode(signature).decode("ascii")})
