"""Exact v3 root/deploy read-only broker integration; synthetic S3 and keys."""
import copy
import sys
from pathlib import Path

import pytest

from zog.host_deploy.gateway import graphics_owner_trust_service as service
from zog.host_deploy.gateway import graphics_owner_trust_history as history
from zog.root_control import graphical_operation_owner_source as owner
from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_task_c_v3_readonly as v3
from zog.root_control.graphical_s3_installation_checkpoint import (
    S3InstallationCheckpoint)
from zog.root_control.graphical_task_c_trust_authority import GetObjectOnly

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"companions/root-control/tests"))
from test_graphical_task_c_v3_readonly import selected
from test_graphical_s3_checkpoint import Remote


def fixture():
    row=selected()
    approved={}
    for entry in row["registry"].entries.values():
        req=entry["owner_request"]
        scope=owner.digest(owner.scope_from_request(req))
        approved.setdefault(scope,{})[req["operation_id"]]=owner.digest(req)
    assert len(approved)==1
    scope=next(iter(approved))
    record=row["storage_record"]
    remote=Remote()
    key=record["checkpoint_prefix"]+"000000.json"
    remote.rows[key]=owner.canonical(storage.prospective_genesis(
        record["installation_scope_sha256"],record["registry_sha256"]))
    checkpoint=S3InstallationCheckpoint(
        GetObjectOnly(remote),bucket=record["checkpoint_bucket"],
        prefix=record["checkpoint_prefix"],
        account_id=record["checkpoint_account_id"],
        installation_scope_sha256=record["installation_scope_sha256"],
        registry_sha256=record["registry_sha256"],
        genesis_sha256=record["checkpoint_genesis_sha256"],approved=approved)
    selected_entry=next(iter(row["registry"].entries.values()))
    original=selected_entry["original"]
    frame={
        "schema":history.SCHEMA, "nonce":"9"*48,
        "action":"observe-original", "original":original,
        "pin_sha256":row["pin_sha"],
    }
    return row,remote,checkpoint,frame


def attest(monkeypatch,row,checkpoint,frame):
    monkeypatch.setattr(service.os,"geteuid",lambda:0)
    return service.attest_original(
        frame,registry=row["registry"],issuer_evidence=row["evidence"],
        issuer_public_key=row["issuer_key"],now=400,
        observation_public_key=row["observation_public"],
        checkpoint=checkpoint,signed_pin=row["pin"],
        broker_signer=row["broker_signer"],
        installed_source_sha256=row["selected_broker_sha"][7:],
        independently_retained_original_checkpoint=row["storage_record"])


def test_v3_pinned_getobject_only_genesis_is_signed_without_sending(monkeypatch):
    row,remote,checkpoint,frame=fixture()
    assert v3.verify_installation_broker_selection(**row)[0] == (
        row["storage_record"]["checkpoint_reader_role_arn"])
    assert checkpoint.scope != row["pin"]["scope_sha256"]
    assert not hasattr(checkpoint.client,"put_object")
    assert not hasattr(checkpoint.client,"list_objects_v2")
    assert not hasattr(checkpoint.client,"send_command")
    signed=attest(monkeypatch,row,checkpoint,frame)
    assert signed["current_history"]=={
        "sequence":0,"history_sha256":checkpoint.genesis_sha,"revoked":False}
    assert signed["selected_trust"]["scope_sha256"] == (
        row["pin"]["scope_sha256"])
    raw=history.canonical(signed)
    original_pin=history.APPROVED_PIN_SHA256
    try:
        history.APPROVED_PIN_SHA256=row["pin_sha"]
        selection=history.verify_broker_reply(
            raw,nonce=frame["nonce"],action=frame["action"],
            original=frame["original"],pin=row["pin"],
            pin_sha256=row["pin_sha"])
        assert selection.current_history["sequence"]==0
    finally:
        history.APPROVED_PIN_SHA256=original_pin
    assert remote.puts==0


@pytest.mark.parametrize("tamper",(
    "v2_pin","wrong_scope","wrong_record","different_prefix",
    "unapproved_operation","missing_genesis","denied_get","revoked","wrong_root_identity",
))
def test_v3_never_substitutes_scopes_or_unverified_storage(
        monkeypatch,tamper):
    row,remote,checkpoint,frame=fixture()
    if tamper=="v2_pin":
        row["pin"]["schema"]=history.PIN_SCHEMA_V2
    elif tamper=="wrong_scope":
        row["pin"]["scope_sha256"]="sha256:"+"f"*64
    elif tamper=="wrong_record":
        row["storage_record"]["checkpoint_genesis_sha256"]="sha256:"+"f"*64
    elif tamper=="different_prefix":
        row["storage_record"]["checkpoint_prefix"]="another/"
    elif tamper=="unapproved_operation":
        checkpoint.approved.clear()
    elif tamper=="missing_genesis":
        remote.rows.clear()
    elif tamper=="denied_get":
        remote.denied=True
    elif tamper=="revoked":
        scope=row["pin"]["scope_sha256"]
        first=checkpoint._scan_installation()
        from zog.root_control.graphical_s3_installation_checkpoint import SCHEMA
        remote.rows[checkpoint.prefix+"000001.json"]=owner.canonical({
            "schema":SCHEMA,
            "installation_scope_sha256":checkpoint.scope,
            "sequence":1,"previous_sha256":first[1],
            "action":"revoke","operation_scope_sha256":scope,
            "operation_id":None,"request_sha256":None,
        })
    elif tamper=="wrong_root_identity":
        row["storage_record"]["registry_sha256"]="sha256:"+"f"*64
    with pytest.raises((history.TrustUnavailable,owner.OperationDenied)):
        attest(monkeypatch,row,checkpoint,frame)
    assert remote.puts==0


def test_old_v2_pin_cannot_admit_zero_history(monkeypatch):
    row,_,checkpoint,frame=fixture()
    signed=attest(monkeypatch,row,checkpoint,frame)
    pin={**row["pin"],"schema":history.PIN_SCHEMA_V2}
    with pytest.raises(history.TrustUnavailable):
        history.verify_broker_reply(
            history.canonical(signed),
            nonce=frame["nonce"],action=frame["action"],
            original=frame["original"],pin=pin,
            pin_sha256=row["pin_sha"])
