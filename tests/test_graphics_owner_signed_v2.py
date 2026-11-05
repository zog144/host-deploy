"""Exact root-control PR39 signed-v2 source contract; no native SSM/AWS."""
import base64
import copy
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.host_deploy.gateway import graphics_owner_observation_v2 as v2
from zog.host_deploy.gateway import graphics_owner_ipc as ipc


def fixture(*, action="preflight-original", status="preflight-ready"):
    signer=Ed25519PrivateKey.generate()
    public=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    trust=v2.SelectedOwnerTrust(
        public_key=public,
        public_key_sha256="sha256:"+hashlib.sha256(public).hexdigest(),
        owner_request_sha256="sha256:"+"a"*64,
        scope_sha256="sha256:"+"b"*64,
        host_id="c"*64,installation_id="d"*64,state_volume_id="e"*64,
        authority_epoch=9)
    state={"preflight-ready":"success", "preflight-pending":"pending",
           "preflight-failed":"failed", "stage-pending":"pending",
           "stage-succeeded":"success", "stage-failed":"failed",
           "claimed-uncertain":"uncertain"}[status]
    history={"sequence":7,"history_sha256":"sha256:"+"f"*64,"revoked":False}
    body={"schema":v2.SCHEMA,"action":action,"nonce":"1"*48,
          "operation_id":"2"*32,"request_sha256":trust.owner_request_sha256,
          "original_request_sha256":"3"*64,"scope_sha256":trust.scope_sha256,
          "host_id":trust.host_id,"installation_id":trust.installation_id,
          "state_volume_id":trust.state_volume_id,"authority_epoch":9,
          "command_id":None if state=="uncertain" else "original-command",
          "ssm_state":state,"status":status,"revoked":False,
          "checkpoint_sequence":7,
          "checkpoint_head_sha256":history["history_sha256"]}
    return signer,trust,history,body


def encode(signer,body):
    signature=signer.sign(v2.DOMAIN+v2.canonical(body))
    return v2.canonical({**body,"signature_ed25519":
        base64.b64encode(signature).decode("ascii")})


def verify(raw,trust,history,body):
    return v2.verify(raw, action=body["action"],nonce=body["nonce"],
                     operation_id=body["operation_id"],
                     original_request_sha256=body["original_request_sha256"],
                     selected_trust=trust,current_history=history)


@pytest.mark.parametrize("action,status",[
    ("preflight-original","preflight-ready"),
    ("preflight-original","preflight-pending"),
    ("preflight-original","preflight-failed"),
    ("preflight-original","claimed-uncertain"),
    ("submit-original","stage-pending"),
    ("submit-original","stage-succeeded"),
    ("submit-original","stage-failed"),
    ("submit-original","claimed-uncertain"),
    ("observe-original","preflight-ready"),
    ("observe-original","stage-pending"),
])
def test_exact_signed_v2_status_and_current_history(action,status):
    signer,trust,history,body=fixture(action=action,status=status)
    result=verify(encode(signer,body),trust,history,body)
    assert result["status"]==status
    assert result["checkpoint_sequence"]==history["sequence"]


@pytest.mark.parametrize("field,value",[
    ("nonce","0"*48),("operation_id","0"*32),
    ("request_sha256","sha256:"+"0"*64),
    ("original_request_sha256","0"*64),
    ("scope_sha256","sha256:"+"0"*64),
    ("host_id","0"*64),("installation_id","0"*64),
    ("state_volume_id","0"*64),("authority_epoch",10),
    ("checkpoint_sequence",6),("checkpoint_head_sha256","sha256:"+"0"*64),
    ("revoked",True),("ssm_state","pending"),
])
def test_signed_but_wrong_original_or_current_claim_denied(field,value):
    signer,trust,history,body=fixture()
    body[field]=value
    with pytest.raises(v2.OwnerObservationDenied):
        verify(encode(signer,body),trust,history,body if field not in
               ("nonce","operation_id","original_request_sha256") else fixture()[3])


def test_wrong_key_stale_s3_head_and_highwater_denied():
    signer,trust,history,body=fixture()
    raw=encode(signer,body)
    for changed in ({"sequence":8,**{k:v for k,v in history.items() if k!="sequence"}},
                    {**history,"history_sha256":"sha256:"+"0"*64},
                    {**history,"revoked":True}):
        with pytest.raises(v2.OwnerObservationDenied):
            verify(raw,trust,changed,body)
    other=Ed25519PrivateKey.generate()
    with pytest.raises(v2.OwnerObservationDenied):
        verify(encode(other,body),trust,history,body)


def test_unsigned_v1_noncanonical_duplicate_field_and_wrong_status_denied():
    signer,trust,history,body=fixture()
    with pytest.raises(v2.OwnerObservationDenied):
        verify(v2.canonical({"schema":"zog-graphical-owner-ipc-v1",
                             "status":"preflight-ready"}),trust,history,body)
    raw=encode(signer,body)
    duplicated=raw[:-1]+b',"status":"preflight-ready"}'
    with pytest.raises(v2.OwnerObservationDenied):
        verify(duplicated,trust,history,body)
    body["status"]="stage-succeeded"
    with pytest.raises(v2.OwnerObservationDenied):
        verify(encode(signer,body),trust,history,body)


def test_root_control_exact_head_observation_contract():
    source=Path(__file__).resolve().parents[1]/(
        "companion-root-control/src/zog/root_control/graphical_task_c_runtime.py")
    text=source.read_text()
    assert 'RESULT_SCHEMA = "zog-graphical-task-c-owner-observation-v2"' in text
    assert 'RESULT_DOMAIN = b"zog-graphical-task-c-owner-observation-v2\\0"' in text
    for key in v2.FIELDS:
        assert '"'+key+'"' in text or key=="signature_ed25519"
    owner=Path(__file__).resolve().parents[1]/(
        "companion-root-control/src/zog/root_control/graphical_task_c_owner.py")
    assert '"observe-original"' in owner.read_text()


def test_gateway_missing_native_trust_and_history_denied(monkeypatch):
    original={"request_id":"a"*32,"original_request_sha256":"b"*64,
              "origin_repository":"zog144/host-deploy","origin_issue_number":17,
              "origin_trigger_actor":"zog144","operation_id":"c"*32,
              "stage":"submit","ordinal":0,"binding_sha256":"d"*64,
              "remote_request_sha256":"e"*64}
    with pytest.raises(ipc.OwnerUnavailable):
        ipc._trusted_selection_for_original(original,action="submit-original")
    with pytest.raises(ipc.OwnerUnavailable):
        ipc._current_external_history(None)
    # Even an injected syntactically valid positive reply cannot become a
    # send result without native selected trust and external history.
    signer,trust,history,body=fixture(action="submit-original",
                                     status="stage-pending")
    monkeypatch.setattr(ipc,"_check_path",lambda: None)
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,x):pass
        def connect(self,x):pass
        def getsockopt(self,*args):
            import struct
            return struct.pack("3i",1234,0,0)
        def sendall(self,bytes_):self.req=__import__("json").loads(bytes_)
        def recv(self,n):
            body["nonce"]=self.req["nonce"]
            return encode(signer,body)+b"\\n"
    monkeypatch.setattr(ipc.socket,"socket",lambda *a:Socket())
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**original)


def test_real_pinned_root_executor_observations_verify_across_both_claims(tmp_path):
    """Exercise root-control PR39's real source fixture, not a copied payload."""
    import sys
    root=Path(__file__).resolve().parents[1]/"companion-root-control"
    sys.path.insert(0,str(root/"src"))
    sys.path.insert(0,str(root/"tests"))
    from test_graphical_task_c_runtime import setup,observe
    executor,frames,signer,sender,inspector,ledger=setup(tmp_path)
    public=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)

    def checked(frame,response):
        selected=executor.registry.entries[frame["operation_id"]]
        request=selected["owner_request"]
        contract=__import__(
            "zog.root_control.graphical_operation_owner_source",
            fromlist=["digest"])
        scope=executor.owner.installed["identity"]
        trust=v2.SelectedOwnerTrust(
            public_key=public,
            public_key_sha256="sha256:"+hashlib.sha256(public).hexdigest(),
            owner_request_sha256=contract.digest(request),
            scope_sha256=scope, host_id=request["host_id"],
            installation_id=request["installation_id"],
            state_volume_id=request["state_volume_id"],
            authority_epoch=request["authority_epoch"])
        current=ledger.checkpoint.current_witness(scope)
        assert v2.verify(v2.canonical(response),action=frame["action"],
                      nonce=frame["nonce"],
                      operation_id=frame["operation_id"],
                      original_request_sha256=frame["original_request_sha256"],
                      selected_trust=trust,current_history=current)["status"]==response["status"]

    pre=frames["preflight-original"]
    stage=frames["submit-original"]
    first=executor.handle(pre,now=400)
    checked(pre,first)
    assert first["status"]=="preflight-pending"
    assert len(sender.sent)==1
    inspector.states[first["command_id"]]="success"
    observed=observe(pre)
    ready=executor.handle(observed,now=400)
    checked(observed,ready)
    assert ready["status"]=="preflight-ready"
    second=executor.handle(stage,now=400)
    checked(stage,second)
    assert second["status"]=="stage-pending"
    assert len(sender.sent)==2
    # The earlier signed preflight is now STALE relative to S3 stage claim.
    selected=executor.registry.entries[pre["operation_id"]]
    req=selected["owner_request"]
    from zog.root_control import graphical_operation_owner_source as contract
    trust=v2.SelectedOwnerTrust(
        public_key=public,
        public_key_sha256="sha256:"+hashlib.sha256(public).hexdigest(),
        owner_request_sha256=contract.digest(req),
        scope_sha256=executor.owner.installed["identity"],
        host_id=req["host_id"], installation_id=req["installation_id"],
        state_volume_id=req["state_volume_id"],
        authority_epoch=req["authority_epoch"])
    with pytest.raises(v2.OwnerObservationDenied):
        v2.verify(v2.canonical(ready),action=observed["action"],
                  nonce=observed["nonce"],operation_id=observed["operation_id"],
                  original_request_sha256=observed["original_request_sha256"],
                  selected_trust=trust,
                  current_history=ledger.checkpoint.current_witness(
                      executor.owner.installed["identity"]))
    inspector.states[second["command_id"]]="failed"
    final_frame=observe(stage,nonce="d"*48)
    failed=executor.handle(final_frame,now=400)
    checked(final_frame,failed)
    assert failed["status"]=="stage-failed"


def test_actual_root_source_over_gateway_stream_with_pending_observe(tmp_path,monkeypatch):
    import sys
    import json
    import struct
    root=Path(__file__).resolve().parents[1]/"companion-root-control"
    sys.path.insert(0,str(root/"src"))
    sys.path.insert(0,str(root/"tests"))
    from test_graphical_task_c_runtime import setup
    from zog.root_control import graphical_operation_owner_source as contract
    executor,frames,signer,sender,inspector,ledger=setup(tmp_path)
    public=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    scope=executor.owner.installed["identity"]
    from zog.host_deploy.gateway.graphics_owner_trust_history import AttestedSelection
    def trust_for(original,*,action):
        req=executor.registry.entries[original["operation_id"]]["owner_request"]
        trust=v2.SelectedOwnerTrust(
            public_key=public,
            public_key_sha256="sha256:"+hashlib.sha256(public).hexdigest(),
            owner_request_sha256=contract.digest(req),
            scope_sha256=scope, host_id=req["host_id"],
            installation_id=req["installation_id"],
            state_volume_id=req["state_volume_id"],
            authority_epoch=req["authority_epoch"])
        return AttestedSelection(trust,ledger.checkpoint.current_witness(scope))
    monkeypatch.setattr(ipc,"_trusted_selection_for_original",trust_for)
    monkeypatch.setattr(ipc,"_current_external_history",
                        lambda selection:selection.current_history)
    monkeypatch.setattr(ipc,"_check_path",lambda:None)
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,x):pass
        def connect(self,x):pass
        def getsockopt(self,*a):return struct.pack("3i",1234,0,0)
        def sendall(self,raw):self.request=json.loads(raw)
        def recv(self,n):
            response=executor.handle(self.request,now=400)
            if self.request["action"]=="preflight-original":
                inspector.states[response["command_id"]]="success"
            return v2.canonical(response)+bytes([10])
    monkeypatch.setattr(ipc.socket,"socket",lambda *args:Socket())
    pre=frames["preflight-original"]
    ready=ipc.preflight_original(**{k:pre[k] for k in (
        "request_id","original_request_sha256","origin_repository",
        "origin_issue_number","origin_trigger_actor","operation_id",
        "stage","ordinal","binding_sha256","remote_request_sha256")})
    assert ready["authenticated"] and ready["ready"]
    assert len(sender.sent)==1
    stage=frames["submit-original"]
    original={k:stage[k] for k in (
        "request_id","original_request_sha256","origin_repository",
        "origin_issue_number","origin_trigger_actor","operation_id",
        "stage","ordinal","binding_sha256","remote_request_sha256")}
    command=ipc.submit_original(**original)
    assert command=="command-2"
    assert len(sender.sent)==2
    inspected=ipc.observe_original(**original)
    assert inspected["status"]=="stage-pending"
    assert len(sender.sent)==2
