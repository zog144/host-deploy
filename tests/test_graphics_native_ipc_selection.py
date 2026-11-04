"""Original GitHub request and both protected IPC identities; source only."""
import hashlib
import inspect
import pytest

from zog.host_deploy.gateway import generic_pipeline as pipeline
from zog.host_deploy.gateway import graphics_owner_ipc as ipc


def _original():
    return dict(request_id="a"*32, operation_id="b"*32, stage="submit",
                ordinal=0, binding_sha256="c"*64,
                remote_request_sha256="d"*64)


def test_frozen_original_identity_for_both_owner_routes(monkeypatch):
    original = _original()
    monkeypatch.setattr(
        __import__("zog.host_deploy.gateway.graphics_operation_send_intent",
                   fromlist=["_expected"]), "_expected",
        lambda binding, request_id, step: {
            "operation_id": original["operation_id"],
            "stage": original["stage"], "ordinal": original["ordinal"],
            "binding_sha256": original["binding_sha256"],
            "remote_request_sha256": original["remote_request_sha256"],
        } if request_id == original["request_id"] else pytest.fail("new request selected"))
    binding={"request_id":original["request_id"]}
    step={"name":"submit"}
    calls=[]
    def preflight(**kwargs):
        calls.append(("preflight",kwargs))
        return {"contract":"zog-protected-graphical-preflight-observation-v1",
                "ready":True,"mutation":False,"authenticated":True}
    def submit(**kwargs):
        calls.append(("stage",kwargs))
        return "original-command"
    monkeypatch.setattr(ipc,"preflight_original",preflight)
    monkeypatch.setattr(ipc,"submit_original",submit)
    before=pipeline._selected_protected_owner_preflight(None,binding,step,{})
    sender=pipeline._selected_protected_owner_sender(None,binding,step)
    before()
    assert sender("local witness only",seconds=300)=="original-command"
    assert len(calls)==2
    pre_id=hashlib.sha256(("zog-graphical-original-preflight-v1:"+
                          original["request_id"]+":"+original["operation_id"]).encode(
                              "ascii")).hexdigest()[:32]
    assert calls[0]==("preflight",{**original,"operation_id":pre_id})
    assert calls[1]==("stage",original)
    assert pre_id!=original["operation_id"]
    assert "script" not in calls[1][1] and "seconds" not in calls[1][1]


def test_both_original_routes_fail_closed_without_native_ipc(monkeypatch):
    original=_original()
    monkeypatch.setattr(pipeline,"_protected_original_identifiers",lambda *a:original)
    def deny(**_):
        raise ipc.OwnerUnavailable("missing root-owned graphical owner")
    monkeypatch.setattr(ipc,"preflight_original",deny)
    monkeypatch.setattr(ipc,"submit_original",deny)
    with pytest.raises(ipc.OwnerUnavailable):
        pipeline._selected_protected_owner_preflight(None,{},None,None)()
    with pytest.raises(ipc.OwnerUnavailable):
        pipeline._selected_protected_owner_sender(None,{},None)("not executed",seconds=300)


def test_graphical_gateway_has_no_direct_ssm_call_or_legacy_preflight():
    source=inspect.getsource(pipeline.advance)
    assert "producer_runtime_preflight(host, stage_binding)" not in source
    assert "host.submit_command(" not in source
    assert "host.command(" not in source
    assert "_selected_protected_owner_preflight(" in source
    assert "_selected_protected_owner_sender(" in source
    assert source.index("_selected_protected_owner_sender(")<source.index(
        "protected_preflight()")
