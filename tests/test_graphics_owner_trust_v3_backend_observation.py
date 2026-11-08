"""V3 broker cannot sign on static mapping/boolean; checks native backend per IPC."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import graphics_owner_trust_daemon as daemon
from zog.host_deploy.gateway import graphics_owner_trust_history as protocol
from test_graphics_owner_trust_daemon import selected, Peer, frame


def proof():
    return {
        "backend":"root-directory",
        "registry_sha256":"sha256:"+"2"*64,
        "installation_scope_sha256":"sha256:"+"3"*64,
        "native_observer_sha256":"sha256:"+"4"*64,
        "observation_sha256":"sha256:"+"5"*64,
    }


def fixture(monkeypatch,backend_guard):
    original=selected()
    checkpoint=SimpleNamespace(
        scope="sha256:"+"3"*64, registry_sha="sha256:"+"2"*64)
    auth=replace(original,
        original_checkpoint={
            "schema":"zog-task-c-installation-storage-authority-v1"},
        checkpoint=checkpoint, backend_recheck=backend_guard)
    monkeypatch.setattr(daemon,"_native_peer_witness",lambda pid,policy:None)
    calls=[]
    def attest(frame,**kwargs):
        calls.append(frame)
        return {"schema":protocol.SCHEMA,"nonce":frame["nonce"],
                "action":frame["action"],"original":frame["original"],
                "status":"synthetic-only"}
    monkeypatch.setattr(daemon.attest,"attest_original",attest)
    peer=Peer(protocol.canonical(frame())+b"\n")
    return auth,peer,calls


def test_v3_broker_rechecks_backend_on_each_request_before_signed_reply(monkeypatch):
    called=[]
    def check():
        called.append("native")
        return proof()
    authority,peer,calls=fixture(monkeypatch,check)
    assert daemon.serve_connection(peer,authority,now=123)["status"]=="synthetic-only"
    assert len(called)==1 and len(calls)==1 and len(peer.sent)==1
    # This test uses a synthetic callable; actual installed runtime selects
    # a protected root-control readback, not this test seam.
    assert not hasattr(authority.checkpoint,"send_command")


@pytest.mark.parametrize("bad",(
    None, False, {"native_accepted":True},
    {**proof(),"installation_scope_sha256":"sha256:"+"e"*64},
    {**proof(),"registry_sha256":"sha256:"+"f"*64},
    {**proof(),"broker_admission":True},
))
def test_v3_broker_never_trusts_signed_mapping_or_boolean(monkeypatch,bad):
    guard=None if bad is None else lambda:bad
    authority,peer,calls=fixture(monkeypatch,guard)
    with pytest.raises(protocol.TrustUnavailable):
        daemon.serve_connection(peer,authority,now=123)
    assert calls==[] and peer.sent==[]


def test_native_observer_denial_prevents_v3_history_signature(monkeypatch):
    def deny():
        raise protocol.TrustUnavailable("native selected /state changed")
    authority,peer,calls=fixture(monkeypatch,deny)
    with pytest.raises(protocol.TrustUnavailable):
        daemon.serve_connection(peer,authority,now=123)
    assert calls==[] and peer.sent==[]
