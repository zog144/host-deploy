"""Read-only protected Task C trust/history broker source contract.

This is a SOURCE adapter, not a selected native service. host-install must
install its exact module and pin, original signed registry/GitHub issuer,
independent GetObject-only S3 role and signing key. No owner SSM or S3 write
credentials are accepted. Do not add a service main() without native review.
"""
import base64
import hashlib
import json
import os
import re
from . import graphics_owner_trust_history as client

def denied():
    client.deny()

def attest_original(frame, *, registry, issuer_evidence, issuer_public_key,
                    now, observation_public_key, checkpoint, signed_pin,
                    broker_signer, installed_source_sha256,
                    independently_retained_original_checkpoint):
    """Read original mapping and CURRENT independent external S3 head.

    All arguments except 'frame' must be supplied by a separate installed
    root authority, not a request, gateway environment or IPC client. The
    checkpoint must be constructed with GetObject-only independent credentials
    and immutable original S3 origin. This function never calls SendCommand.
    """
    from zog.root_control import graphical_task_c_owner as taskc
    from zog.root_control import graphical_task_c_origin as origin
    from zog.root_control import graphical_operation_owner_source as owner
    from zog.root_control.graphical_s3_checkpoint import S3AppendOnlyCheckpoint

    if (os.geteuid()!=0 or type(frame) is not dict
            or set(frame)!={"schema","nonce","action","original","pin_sha256"}
            or frame["schema"]!=client.SCHEMA
            or frame["action"] not in client.v2.ACTIONS
            or not client.v2.match(frame["nonce"],client.v2.H48)
            or type(frame["original"]) is not dict
            or set(frame["original"])!=client.ORIGINAL_KEYS
            or not client.v2.match(frame["pin_sha256"],client.v2.SHA)
            or type(signed_pin) is not dict or set(signed_pin)!=client.PIN_KEYS
            or type(observation_public_key) is not bytes
            or len(observation_public_key)!=32
            or signed_pin["owner_observation_public_key"]!=
               observation_public_key.hex()
            or type(installed_source_sha256) is not str
            or installed_source_sha256!=signed_pin["installed_broker_source"]
            or not isinstance(registry,taskc.ProtectedOriginalRegistry)
            or not isinstance(checkpoint,S3AppendOnlyCheckpoint)
            or not callable(getattr(broker_signer,"sign",None))):
        denied()

    # Source custody and original issuer evidence are independent of request.
    installed_pin_sha256="sha256:"+hashlib.sha256(client.canonical(
        signed_pin)).hexdigest()
    if frame["pin_sha256"]!=installed_pin_sha256:
        denied()
    origin.verify_installed_evidence(
        issuer_evidence,registry=registry,
        pinned_issuer_key=issuer_public_key,now=now)
    original=frame["original"]
    parsed=taskc.parse_frame(taskc.canonical({
        "schema":taskc.IPC_SCHEMA,
        "nonce":frame["nonce"],
        "action":frame["action"],**original})+b"\n")
    item=registry.select(parsed)
    request=item["owner_request"]
    scope=owner.digest(owner.scope_from_request(request))
    if (scope!=signed_pin["scope_sha256"]
            or request["installation_id"]!=signed_pin["installation_id"]
            or request["state_volume_id"]!=signed_pin["state_volume_id"]
            or checkpoint.scope!=scope):
        denied()

    # Independent installer verifies local reservation and retained external
    # anchor first. A different prefix with the same genesis is NOT equivalent.
    source=independently_retained_original_checkpoint
    if (type(source) is not dict or
            set(source)!={
                "schema","host_id","installation_id","state_volume_id",
                "checkpoint_account_id","checkpoint_region",
                "checkpoint_bucket","checkpoint_prefix",
                "checkpoint_scope_sha256","checkpoint_genesis_sha256",
                "checkpoint_role_arn","root_source_revision"}
            or source["schema"]!="zog-task-c-original-checkpoint-installation-v1"
            or "sha256:"+hashlib.sha256(client.canonical(source)).hexdigest()!=
               signed_pin["original_checkpoint_sha256"]
            or source["host_id"]!=request["host_id"]
            or source["installation_id"]!=request["installation_id"]
            or source["state_volume_id"]!=request["state_volume_id"]
            or source["checkpoint_scope_sha256"]!=scope
            or source["checkpoint_account_id"]!=checkpoint.account
            or source["checkpoint_bucket"]!=checkpoint.bucket
            or source["checkpoint_prefix"]!=checkpoint.prefix
            or source["checkpoint_genesis_sha256"]!=checkpoint.genesis_sha
            or source["root_source_revision"]!=
               "5ad7d5ed72d1b72edc767a658de28506791a74d4"):
        denied()
    # Region and role come only from independently installed read-only S3
    # credential selection; the gateway never supplies a role or AWS endpoint.
    # Fresh read of exact existing immutable history: no bootstrap, listing,
    # cached last-seen value, PUT, credential fallback or discovery.
    head=checkpoint.current_witness(scope)
    if (type(head) is not dict or set(head)!={"sequence","history_sha256","revoked"}
            or type(head["sequence"]) is not int or head["sequence"]<1
            or type(head["revoked"]) is not bool or head["revoked"]
            or not client.v2.match(head["history_sha256"],client.v2.SHA)):
        denied()
    trust={
        "public_key":observation_public_key.hex(),
        "public_key_sha256":"sha256:"+hashlib.sha256(observation_public_key).hexdigest(),
        "owner_request_sha256":owner.digest(request),
        "scope_sha256":scope,
        "host_id":request["host_id"],
        "installation_id":request["installation_id"],
        "state_volume_id":request["state_volume_id"],
        "authority_epoch":request["authority_epoch"],
    }
    body={"schema":client.SCHEMA,"nonce":frame["nonce"],
          "action":frame["action"],"original":original,
          "selected_trust":trust,"current_history":head,
          "pin_sha256":installed_pin_sha256}
    from .graphics_owner_trust_history import DOMAIN,canonical
    signature=broker_signer.sign(DOMAIN+canonical(body))
    if type(signature) is not bytes or len(signature)!=64:denied()
    result={**body,"signature_ed25519":base64.b64encode(signature).decode("ascii")}
    if len(canonical(result))+1>client.MAX_FRAME:denied()
    return result
