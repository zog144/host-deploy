"""Only selected root-control PR29/30 can issue graphical SSM SendCommand.

No network, protected ledger, actual provider or privileged owner is installed.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.host_deploy.gateway import generic_pipeline as generic
from zog.host_deploy.gateway import graphics_protected_owner_handoff as handoff
from test_gateway_generic_pipeline import GATEWAY, mock_environment

ROOT=Path(__file__).resolve().parents[1]
selected=ROOT/"companion-root-control/src/zog/root_control/graphical_operation_owner_source.py"
spec=importlib.util.spec_from_file_location("selected_owner",selected)
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)

def data():
    source={"repository":"zog144/image-build","revision":"b"*40}
    binding={"source":source,"lane":"graphical-lane",
             "target":{"instance_id":"i-0123456789abcdef0","region":"us-east-1"},
             "monthly_pin_identity":"sha256:"+"c"*64,
             "task_catalogue_identity":"sha256:"+"d"*64,
             "task":{"entries":[],"pin_date":"2026-10-01","arguments":{"mode":"image"}}}
    req={"schema":"image-build-remote-operation-v1",
         "operation_id":"e"*32,"operation":"pipeline.submit","source":source,
         "arguments":{"mode":"image","recipe_snapshot":"sha256:"+"a"*64}}
    step={"name":"submit","ordinal":0,"operation_id":"e"*32,
          "request":req,"request_sha256":hashlib.sha256(
              json.dumps(req,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
    protect={"host_id":"1"*64,"installation_id":"2"*64,
             "state_volume_id":"3"*64,
             "task":"graphics-x11-core-image-v1",
             "base_generation_id":"4"*64,
             "predecessor_receipt_sha256":"sha256:"+"5"*64,
             "stage_once_receipt_sha256":"sha256:"+"6"*64,
             "authority_epoch":7,"authority_pin_sha256":"sha256:"+"8"*64,
             "approval_sha256":"sha256:"+"9"*64}
    return binding,step,protect

def test_selected_root30_original_request_exact_and_signed_source_approval():
    binding,step,protect=data()
    request=handoff.selected_owner_request(binding,GATEWAY,step,
                                            protected_selection=protect)
    validated=owner.validate_request(request)
    assert validated["source_revision"]=="b"*40
    assert validated["original_request_sha256"]=="sha256:"+hashlib.sha256(
        json.dumps(binding,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    assert validated["stage_once_receipt_sha256"]==protect["stage_once_receipt_sha256"]
    assert validated["remote_request_sha256"]=="sha256:"+step["request_sha256"]
    signer=Ed25519PrivateKey.generate()
    body={"schema":owner.APPROVAL_SCHEMA,"approval_id":"a"*32,
          "request_sha256":owner.digest(validated),
          "scope_sha256":owner.digest(owner.scope_from_request(validated)),
          "expires_at":600}
    grant={**body,"signature_ed25519":__import__("base64").b64encode(
        signer.sign(owner.APPROVAL_DOMAIN+owner.canonical(body))).decode("ascii")}
    pub=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    assert owner.verify_original_operator_approval(
        validated,grant,externally_pinned_operator_key=pub,
        expected_approval_id="a"*32,now=400)["request_sha256"]==owner.digest(validated)
    calls=[]
    ledger=owner.SyntheticExternalLedger(
        owner.scope_from_request(validated),
        independently_approved_operations={validated["operation_id"]:owner.digest(validated)})
    selected_owner=owner.SourceOnlyProtectedOwner(
        ledger,test_sender=lambda item:calls.append(item) or "original-ssm-id",
        test_signer=Ed25519PrivateKey.generate())
    assert selected_owner.submit_once(validated)["outcome"]=="SENT_ORIGINAL"
    with pytest.raises(owner.OperationDenied):
        selected_owner.submit_once(validated)
    assert len(calls)==1

@pytest.mark.parametrize("change",[
    lambda b,p,s:b["source"].update(revision="0"*40),
    lambda b,p,s:b.update(monthly_pin_identity="sha256:"+"0"*64),
    lambda b,p,s:b.update(task_catalogue_identity="sha256:"+"0"*64),
    lambda b,p,s:b.update(target={"instance_id":"wrong","region":"us-east-1"}),
    lambda b,p,s:p.update(state_volume_id="0"*64),
    lambda b,p,s:p.update(authority_epoch=8),
])
def test_coherent_gateway_rollback_cannot_reuse_original_approved_operation(change):
    binding,step,protect=data()
    original=owner.validate_request(handoff.selected_owner_request(
        binding,GATEWAY,step,protected_selection=protect))
    changed_binding=copy.deepcopy(binding)
    changed_protected=copy.deepcopy(protect)
    changed_step=copy.deepcopy(step)
    change(changed_binding,changed_protected,changed_step)
    changed_step["request"]["source"]=changed_binding["source"]
    changed_step["request_sha256"]=hashlib.sha256(
        json.dumps(changed_step["request"],sort_keys=True,
                   separators=(",",":")).encode()).hexdigest()
    modified=owner.validate_request(handoff.selected_owner_request(
        changed_binding,GATEWAY,changed_step,protected_selection=changed_protected))
    assert owner.digest(modified)!=owner.digest(original)
    ledger=owner.SyntheticExternalLedger(
        owner.scope_from_request(original),
        independently_approved_operations={original["operation_id"]:owner.digest(original)})
    sends=[]
    selected_owner=owner.SourceOnlyProtectedOwner(
        ledger,test_sender=lambda x:sends.append(x) or "sent",
        test_signer=Ed25519PrivateKey.generate())
    with pytest.raises(owner.OperationDenied):
        selected_owner.submit_once(modified)
    assert sends==[]

def test_default_protected_route_blocks_direct_gateway_send_before_claim(tmp_path,monkeypatch):
    original=generic._selected_protected_owner_sender
    Host,seen=mock_environment(monkeypatch)
    monkeypatch.setattr(generic,"_selected_protected_owner_sender",original)
    assert generic.advance(tmp_path,GATEWAY,host_factory=Host)["phase"]=="active"
    with pytest.raises(RuntimeError,match="protected graphical operation owner required"):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert seen==[]
    assert not list((tmp_path/"generic-operation-send-intents").glob("*.json"))
    # Direct SendCommand was never attempted despite the fixture Host exposing it.
    source=(ROOT/"src/zog/host_deploy/gateway/generic_pipeline.py").read_text()
    assert "command_id = host.submit_command(" not in source

def test_missing_protected_selection_never_becomes_first_seen_approval():
    b,s,p=data()
    with pytest.raises(handoff.ProtectedSendOwnerHold):
        handoff.selected_owner_request(b,GATEWAY,s,protected_selection={})
    with pytest.raises(handoff.ProtectedSendOwnerHold):
        handoff.selected_owner_request(b,GATEWAY,s,protected_selection=None)
