"""Host-deploy PR18 frozen stage to root-control PR28 owner data source check."""
import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.host_deploy.gateway import graphics_protected_owner_handoff as handoff
from zog.host_deploy.gateway import graphics_operation_send_intent as intent

ROOT=Path(__file__).resolve().parents[1]
src=ROOT/"companion-root-control/src/zog/root_control/graphical_send_fence_contract.py"
spec=importlib.util.spec_from_file_location("root_send_contract",src)
owner_module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner_module)

GENERATION="a"*64
REQUEST_ID="b"*32
def binding():
    return {"task_catalogue_identity":"sha256:"+"c"*64,
            "source":{"repository":"zog144/image-build","revision":"d"*40},
            "lane":"graphical","target":{"instance_id":"i-0123456789abcdef0","region":"us-east-1"},
            "monthly_pin_identity":"sha256:"+"e"*64,
            "task":{"entries":[],"pin_date":"2026-10-01","arguments":{"mode":"image"}}}

def stage():
    request={"schema":"image-build-remote-operation-v1","operation_id":"f"*32,
             "operation":"pipeline.submit",
             "source":binding()["source"],
             "arguments":{"mode":"image","recipe_snapshot":"sha256:"+"a"*64}}
    return {"operation_id":"f"*32,"name":"submit","ordinal":0,
            "request_sha256":hashlib.sha256(intent._canonical(request)).hexdigest(),
            "request":request}

def scope():
    return {"host_id":"1"*32,"host_fingerprint":"2"*64,
            "installation_id":"3"*32,"state_volume_id":"4"*64,
            "registry_id":"5"*32,"controller_id":"6"*32,"authority_epoch":9}

class SeparateCAS:
    def __init__(self):self.history={};self.counter=0;self.revoked=False
    def claim_once(self,s,digest,operation):
        if self.revoked or operation in self.history:raise RuntimeError("replayed")
        self.counter+=1
        receipt={"sequence":self.counter,"operation_id":operation,"claim_hash":digest,
                 "status":"claimed","epoch":s["authority_epoch"]}
        self.history[operation]=receipt
        return dict(receipt)
    def revoke(self,s):
        self.revoked=True;self.counter+=1
        return {"sequence":self.counter,"operation_id":None,
                "claim_hash":"0"*64,"status":"revoked","epoch":s["authority_epoch"]}
    def observe(self,s,operation):
        return self.history.get(operation)

def fixture():
    signer=Ed25519PrivateKey.generate()
    operator=Ed25519PrivateKey.generate()
    db=SeparateCAS()
    owner=owner_module.SendOwner(scope=scope(),operator_public_key=operator.public_key(),
                                 owner_signing_key=signer,protected_backend=db)
    return owner,operator,db

def approval(owner,operator,claim):
    p={"schema":owner_module.APPROVAL_SCHEMA,"scope":owner.scope,"action":"send-claim",
       "claim_hash":hashlib.sha256(owner_module.canonical(claim)).hexdigest(),
       "expires_at":800,"approval_id":"7"*32}
    return p,operator.sign(owner_module.canonical(p)).hex()

def test_exact_gateway_stage_selection_and_independent_owner_claim_deny_replay():
    claim=handoff.original_operation_claim(binding(),REQUEST_ID,stage(),
                                           protected_generation_sha256=GENERATION)
    assert claim["source_revision"]=="d"*40
    assert claim["source_generation"]==GENERATION
    owner,operator,db=fixture()
    claim=owner_module.validate_claim(claim)
    a,s=approval(owner,operator,claim)
    r=owner.claim_once(claim=claim,approval=a,approval_signature=s,now=400)
    assert r["body"]["witness"]["sequence"]==1
    # Complete local host-deploy journal/send-intent rollback is irrelevant
    # to the independent protected owner operation identity.
    with pytest.raises(owner_module.SendOwnerDenied):
        owner.claim_once(claim=claim,approval=a,approval_signature=s,now=400)
    assert db.counter==1

@pytest.mark.parametrize("mutate",[
    lambda b:b["source"].update(revision="0"*40),
    lambda b:b.update(monthly_pin_identity="sha256:"+"0"*64),
    lambda b:b.update(task_catalogue_identity="sha256:"+"0"*64),
    lambda b:b.update(target={"instance_id":"i-other","region":"us-east-1"}),
])
def test_changed_local_binding_cannot_reuse_original_signed_approval(mutate):
    original=handoff.original_operation_claim(binding(),REQUEST_ID,stage(),
                                              protected_generation_sha256=GENERATION)
    owner,operator,db=fixture()
    a,s=approval(owner,operator,original)
    modified=binding();mutate(modified)
    changed=handoff.original_operation_claim(modified,REQUEST_ID,stage(),
                                             protected_generation_sha256=GENERATION)
    with pytest.raises(owner_module.SendOwnerDenied):
        owner.claim_once(claim=changed,approval=a,approval_signature=s,now=400)
    assert db.counter==0

def test_changed_generation_or_missing_independent_provenance_denied():
    original=handoff.original_operation_claim(binding(),REQUEST_ID,stage(),
                                              protected_generation_sha256=GENERATION)
    owner,operator,db=fixture();a,s=approval(owner,operator,original)
    changed=handoff.original_operation_claim(binding(),REQUEST_ID,stage(),
                                              protected_generation_sha256="0"*64)
    with pytest.raises(owner_module.SendOwnerDenied):
        owner.claim_once(claim=changed,approval=a,approval_signature=s,now=400)
    for wrong in (None,"","sha256:"+"0"*64):
        with pytest.raises(handoff.ProtectedSendOwnerHold):
            handoff.original_operation_claim(binding(),REQUEST_ID,stage(),
                                              protected_generation_sha256=wrong)

def test_foreign_program_and_forged_operation_denied_before_owner():
    bad=stage();bad["request"]["operation"]="build.submit"
    bad["request_sha256"]=hashlib.sha256(intent._canonical(bad["request"])).hexdigest()
    with pytest.raises(handoff.ProtectedSendOwnerHold):
        handoff.original_operation_claim(binding(),REQUEST_ID,bad,
                                          protected_generation_sha256=GENERATION)
