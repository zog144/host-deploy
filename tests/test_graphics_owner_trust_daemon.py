"""Disabled but runnable Task C trust/history broker source harness.

No AWS/SSM/network access, root install or native gateway admission occurs.
"""
import json
import socket
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from zog.host_deploy.gateway import graphics_owner_trust_daemon as daemon
from zog.host_deploy.gateway import graphics_owner_trust_history as protocol


def selected():
    return daemon.InstalledReadOnlyAuthority(
        registry=object(), issuer_evidence={}, issuer_public_key=b"a"*32,
        observation_public_key=b"b"*32, checkpoint=object(), signed_pin={},
        broker_signer=object(), installed_source_sha256="c"*64,
        original_checkpoint={"schema":daemon.LEGACY_ORIGINAL_SCHEMA},gateway_uid=15310,gateway_gid=15311,
        gateway_executable_sha256="sha256:"+"d"*64,
        gateway_cgroup="/system.slice/zog-graphical-gateway.service")


def frame():
    original={"request_id":"1"*32,"original_request_sha256":"2"*64,
              "origin_repository":"zog144/host-deploy",
              "origin_issue_number":17,"origin_trigger_actor":"zog144",
              "operation_id":"3"*32,"stage":"submit","ordinal":0,
              "binding_sha256":"4"*64,"remote_request_sha256":"5"*64}
    return {"schema":protocol.SCHEMA,"nonce":"6"*48,
            "action":"observe-original", "original":original,
            "pin_sha256":"sha256:"+"7"*64}


class Peer:
    def __init__(self, request, *, uid=15310, gid=15311):
        self.request=request
        self.uid=uid
        self.gid=gid
        self.position=0
        self.sent=[]
    def getsockopt(self,*args):
        return struct.pack("3i",2211,self.uid,self.gid)
    def recv(self,limit):
        raw=self.request[self.position:self.position+limit]
        self.position+=len(raw)
        return raw
    def sendall(self,raw):
        self.sent.append(raw)


def test_single_canonical_frame_and_signed_reply_no_command(monkeypatch):
    witnesses=[]
    monkeypatch.setattr(daemon,"_native_peer_witness",
                        lambda pid,policy:witnesses.append((pid,policy)))
    def produce(request,**kwargs):
        assert request==frame()
        assert kwargs["now"]==123
        assert kwargs["registry"] is authority.registry
        assert kwargs["checkpoint"] is authority.checkpoint
        assert kwargs["independently_retained_original_checkpoint"] is authority.original_checkpoint
        assert "ssm_client" not in kwargs and "role_arn" not in kwargs
        return {"schema":protocol.SCHEMA, "nonce":request["nonce"],
                "action":request["action"],"original":request["original"],
                "status":"synthetic-only"}
    monkeypatch.setattr(daemon.attest,"attest_original",produce)
    authority=selected()
    peer=Peer(protocol.canonical(frame())+b"\n")
    result=daemon.serve_connection(peer,authority,now=123)
    assert witnesses==[(2211,authority)]
    assert len(peer.sent)==1
    assert peer.sent[0]==protocol.canonical(result)+b"\n"


@pytest.mark.parametrize("mutation",[
    lambda raw:raw[:-1], lambda raw:raw+b"extra",
    lambda raw:raw.replace(b'"nonce":',b'"nonce":"0","nonce":'),
    lambda raw:b"x"*(daemon.FRAME_MAX+1),
])
def test_invalid_multiple_or_oversize_frame_denied(monkeypatch,mutation):
    monkeypatch.setattr(daemon,"_native_peer_witness",lambda *args:None)
    monkeypatch.setattr(daemon.attest,"attest_original",
                        lambda *a,**k:pytest.fail("broker authority reached"))
    with pytest.raises(protocol.TrustUnavailable):
        daemon.serve_connection(Peer(mutation(protocol.canonical(frame())+b"\n")),
                                selected(),now=123)


@pytest.mark.parametrize("uid,gid",[
    (0,15311),(15310,0),(15312,15311),(15310,15312)])
def test_only_exact_gateway_peer_proceeds(monkeypatch,uid,gid):
    monkeypatch.setattr(daemon,"_native_peer_witness",
                        lambda *a:pytest.fail("peer witness reached"))
    with pytest.raises(protocol.TrustUnavailable):
        daemon.serve_connection(Peer(protocol.canonical(frame())+b"\n",
                                    uid=uid,gid=gid),selected(),now=123)


def test_unselected_authority_and_unapproved_main_denied(monkeypatch):
    with pytest.raises(protocol.TrustUnavailable):
        daemon.serve_connection(Peer(b""),object(),now=123)
    assert daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
    monkeypatch.setattr(daemon.os,"geteuid",lambda:0)
    monkeypatch.setattr(daemon.sys,"argv",["broker"])
    monkeypatch.setattr(daemon,"installed_runtime",
                        lambda:pytest.fail("native constructor attempted"))
    monkeypatch.setattr(daemon,"_activated_socket",
                        lambda:pytest.fail("socket activated"))
    with pytest.raises(protocol.TrustUnavailable):
        daemon.main()


def test_disabled_unit_source_and_no_bypass():
    base=Path(__file__).resolve().parents[1]/"deploy/graphical-trust-broker"
    sock=(base/"zog-graphical-trust.socket").read_text()
    service=(base/"zog-graphical-trust.service").read_text()
    assert "ListenStream=/run/zog/graphical-owner-trust.sock" in sock
    assert "SocketMode=0660" in sock
    assert "FileDescriptorName=trust-history" in sock
    assert "ExecStart=/usr/bin/python3 -I -m zog.host_deploy.gateway.graphics_owner_trust_daemon" in service
    assert "ProtectSystem=strict" in service
    assert "CapabilityBoundingSet=" in service
    assert "ReadOnlyPaths=/var/lib/zog-graphical-owner-ledger" in service
    for body in (sock,service):
        assert "[Install]" not in body
        assert "aws-session.json" not in body
        assert "checkpoint-session.json" not in body
        assert "ssm:SendCommand" not in body
        assert "ExecStartPost=" not in body
    module=(Path(__file__).resolve().parents[1]/
            "src/zog/host_deploy/gateway/graphics_owner_trust_daemon.py").read_text()
    assert "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED = False" in module
    assert "socket.bind(" not in module and "boto3" not in module
    assert "assume_role(" not in module and "send_command(" not in module
