"""Original GitHub request and both protected IPC identities; source only."""
import hashlib
import inspect
import pytest

from zog.host_deploy.gateway import generic_pipeline as pipeline
from zog.host_deploy.gateway import graphics_owner_ipc as ipc


def _original():
    return dict(request_id="a"*32, original_request_sha256="e"*64,
                origin_repository="zog144/host-deploy",origin_issue_number=17,
                origin_trigger_actor="zog144",
                operation_id="b"*32, stage="submit",
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
    from zog.host_deploy.gateway import protocol
    monkeypatch.setattr(protocol,"request_digest",lambda req:original["original_request_sha256"])
    monkeypatch.setattr(
        pipeline,"_load_provenance_state_under_owner_lock",lambda root, id:{
        "request_sha256":original["original_request_sha256"],
        "request":{"request_id":id,"operation":"build.submit",
                   "origin":{"repository":original["origin_repository"],
                             "issue_number":original["origin_issue_number"],
                             "trigger_actor":original["origin_trigger_actor"]}}})
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


def test_unsigned_native_preflight_receipt_is_never_authenticated(monkeypatch):
    from zog.host_deploy.gateway import graphics_owner_ipc
    monkeypatch.setattr(graphics_owner_ipc, "_exchange", lambda **kw: {
        "status": "preflight-ready", "command_id": "faked-original"})
    with pytest.raises(graphics_owner_ipc.OwnerUnavailable):
        graphics_owner_ipc.preflight_original(**_original())


def test_native_ipc_denies_missing_original_issue_number_before_connect(monkeypatch):
    monkeypatch.setattr(ipc,"_check_path",lambda:pytest.fail("socket reached"))
    fields=_original()
    fields["origin_issue_number"]=0
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**fields)


def test_fixed_root_socket_accepts_installer_0660_but_no_writable_ancestors(monkeypatch):
    import stat
    from types import SimpleNamespace
    def fake(path):
        mode=(stat.S_IFSOCK|0o660) if path == ipc.SOCKET_PATH else (
            stat.S_IFDIR|0o755)
        return SimpleNamespace(st_mode=mode,st_uid=0)
    monkeypatch.setattr(ipc.os,"lstat",fake)
    ipc._check_path()  # authorized root-owned, group-scoped 0660 socket


@pytest.mark.parametrize("path,mode,owner_uid",[
    ("/run",0o775,0),
    (ipc.SOCKET_DIR,0o777,0),
    (ipc.SOCKET_PATH,0o666,0),
    (ipc.SOCKET_PATH,0o600,0),
    (ipc.SOCKET_PATH,0o660,1000),
])
def test_writable_ancestors_and_wrong_or_shared_socket_modes_denied(
        monkeypatch,path,mode,owner_uid):
    import stat
    from types import SimpleNamespace
    def fake(which):
        socket_mode=stat.S_IFSOCK if which == ipc.SOCKET_PATH else stat.S_IFDIR
        return SimpleNamespace(
            st_mode=socket_mode | (mode if which == path else
                    (0o660 if which == ipc.SOCKET_PATH else 0o755)),
            st_uid=(owner_uid if which == path else 0))
    monkeypatch.setattr(ipc.os,"lstat",fake)
    with pytest.raises(ipc.OwnerUnavailable):
        ipc._check_path()


def test_owner_identity_read_does_not_acquire_nonreentrant_request_lock_twice():
    # Source invariant: generic_pipeline.advance calls these helpers while it
    # holds ledger.request_lock for the original gateway request. A second
    # load_request -> request_lock would block forever on the same flock.
    code=inspect.getsource(pipeline._load_provenance_state_under_owner_lock)
    assert "load_request(" not in code.split('    from .ledger')[1]
    assert "_load_state(directory)" in code
    selected=inspect.getsource(pipeline._protected_original_identifiers)
    assert "_load_provenance_state_under_owner_lock(" in selected
