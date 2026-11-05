"""Verify root-control Task C signed-v2 original-operation observations.

Source consumer ONLY. The native installer must supply independently pinned
observation key, original owner request digest, current Host/STATE/epoch and a
fresh S3 checkpoint witness. No gateway journal or IPC frame can supply trust.
"""
import base64
import hashlib
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "zog-graphical-task-c-owner-observation-v2"
DOMAIN = b"zog-graphical-task-c-owner-observation-v2\0"
FIELDS = frozenset((
    "schema", "action", "nonce", "operation_id", "request_sha256",
    "original_request_sha256", "scope_sha256", "host_id", "installation_id",
    "state_volume_id", "authority_epoch", "command_id", "ssm_state",
    "status", "revoked", "checkpoint_sequence", "checkpoint_head_sha256",
    "signature_ed25519",
))
H32 = re.compile(r"[a-f0-9]{32}\Z")
H48 = re.compile(r"[a-f0-9]{48}\Z")
H64 = re.compile(r"[a-f0-9]{64}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
CMD = re.compile(r"[A-Za-z0-9-]{1,128}\Z")
ACTIONS = frozenset(("submit-original", "preflight-original", "observe-original"))

class OwnerObservationDenied(RuntimeError):
    pass

def deny():
    raise OwnerObservationDenied("protected graphical owner v2 observation not independently verified")

def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")

def match(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None

@dataclass(frozen=True)
class SelectedOwnerTrust:
    """Installer-provided trust, NEVER derived from gateway STATE or reply.

    Native selection must separately authenticate installed public key, mapping,
    Host/installation/STATE/epoch and current external checkpoint readback.
    """
    public_key: bytes
    public_key_sha256: str
    owner_request_sha256: str
    scope_sha256: str
    host_id: str
    installation_id: str
    state_volume_id: str
    authority_epoch: int

    def validate(self):
        if (type(self.public_key) is not bytes or len(self.public_key) != 32
                or not match(self.public_key_sha256, SHA)
                or self.public_key_sha256 !=
                "sha256:" + hashlib.sha256(self.public_key).hexdigest()
                or any(not match(x, SHA) for x in
                       (self.owner_request_sha256, self.scope_sha256))
                or any(not match(x, H64) for x in
                       (self.host_id, self.installation_id, self.state_volume_id))
                or type(self.authority_epoch) is not int
                or not 1 <= self.authority_epoch < 2**53):
            deny()
        return self

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            deny()
        result[key] = value
    return result

def verify(raw, *, action, nonce, operation_id, original_request_sha256,
           selected_trust, current_history):
    """Return verified status, never permission to call SendCommand.

    current_history must be a FRESH independent checkpoint read of the SAME
    installed S3 scope after the owner operation; neither a cached gateway
    checkpoint nor the signed reply is acceptable provenance.
    """
    if (type(raw) is not bytes or not 1 <= len(raw) <= 8192
            or action not in ACTIONS or not match(nonce, H48)
            or not match(operation_id, H32)
            or not match(original_request_sha256, H64)
            or type(selected_trust) is not SelectedOwnerTrust
            or type(current_history) is not dict
            or set(current_history) != {"sequence", "history_sha256", "revoked"}
            or type(current_history["sequence"]) is not int
            or current_history["sequence"] < 1
            or not match(current_history["history_sha256"], SHA)
            or type(current_history["revoked"]) is not bool):
        deny()
    selected_trust.validate()
    try:
        row = json.loads(raw, object_pairs_hook=_unique,
                         parse_constant=lambda _: deny())
        if (type(row) is not dict or set(row) != FIELDS
                or canonical(row) != raw
                or row["schema"] != SCHEMA
                or row["action"] != action
                or row["nonce"] != nonce
                or row["operation_id"] != operation_id
                or row["original_request_sha256"] != original_request_sha256
                or row["request_sha256"] != selected_trust.owner_request_sha256
                or row["scope_sha256"] != selected_trust.scope_sha256
                or any(row[k] != getattr(selected_trust, k) for k in
                       ("host_id", "installation_id", "state_volume_id",
                        "authority_epoch"))
                or type(row["revoked"]) is not bool or row["revoked"]
                or current_history["revoked"]
                or type(row["checkpoint_sequence"]) is not int
                or row["checkpoint_sequence"] != current_history["sequence"]
                or row["checkpoint_head_sha256"] != current_history["history_sha256"]
                or not match(row["checkpoint_head_sha256"], SHA)
                or not match(row["signature_ed25519"], re.compile(r"[A-Za-z0-9+/]{86}==\Z"))):
            deny()
        command_id = row["command_id"]
        state = row["ssm_state"]
        status = row["status"]
        if (state not in ("uncertain", "pending", "success", "failed")
                or type(state) is not str
                or type(status) is not str
                or status not in ("claimed-uncertain", "preflight-ready",
                                  "preflight-failed", "preflight-pending",
                                  "stage-succeeded", "stage-failed", "stage-pending")
                or (command_id is not None and not match(command_id, CMD))
                or (command_id is None) != (state == "uncertain")
                or (status == "claimed-uncertain") != (state == "uncertain")):
            deny()
        is_preflight = action == "preflight-original" or (
            action == "observe-original" and status.startswith("preflight-"))
        if (action == "submit-original" and not status.startswith("stage-")
                or action == "preflight-original" and
                not status.startswith("preflight-") and status != "claimed-uncertain"
                or status == "preflight-ready" and state != "success"
                or status == "preflight-failed" and state != "failed"
                or status == "preflight-pending" and state != "pending"
                or status == "stage-succeeded" and state != "success"
                or status == "stage-failed" and state != "failed"
                or status == "stage-pending" and state != "pending"):
            deny()
        signature = base64.b64decode(row["signature_ed25519"], validate=True)
        if (len(signature) != 64 or
                base64.b64encode(signature).decode("ascii") != row["signature_ed25519"]):
            deny()
        signed = {key: value for key, value in row.items()
                  if key != "signature_ed25519"}
        Ed25519PublicKey.from_public_bytes(selected_trust.public_key).verify(
            signature, DOMAIN + canonical(signed))
        return {"status": status, "ssm_state": state,
                "command_id": command_id,
                "checkpoint_sequence": row["checkpoint_sequence"],
                "checkpoint_head_sha256": row["checkpoint_head_sha256"]}
    except (ValueError, KeyError, TypeError, UnicodeError, OverflowError,
            InvalidSignature):
        deny()
