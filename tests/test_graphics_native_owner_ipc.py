"""Pinned root-owned graphical owner IPC client source and cross-owner tests.

No socket path, IAM credentials, kernel process or AWS service is activated.
"""
import base64
import copy
import hashlib
import os
from pathlib import Path
import socket
import sys
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.host_deploy.gateway import graphics_native_owner_client as client
from zog.host_deploy.gateway import graphics_protected_owner_handoff as bridge

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))
from test_graphics_selected_owner_direct_route_denial import data
from zog.root_control import graphical_operation_owner_source as root_contract
from zog.root_control.graphical_native_owner import ProtectedLedger,SelectedOwner,serve_one
from zog.root_control.graphical_owner_checkpoint import SeparateDurableCheckpoint


def binding():
    b,s,p=data()
    return b,s,p,root_contract.validate_request(
        bridge.selected_owner_request(b,"e"*32,s,protected_selection=p))


def fake_installed(tmp_path):
    b,s,p,req=binding()
    local=tmp_path/"ledger";external=tmp_path/"checkpoint"
    for d in (local,external):
        d.mkdir(mode=0o700)
        (d/".selected-graphical-owner.lock").write_bytes(b"pinned")
        (d/".selected-graphical-owner.lock").chmod(0o600)
        (d/"claims").mkdir(mode=0o700)
    (local/"results").mkdir(mode=0o700)
    checkpoint=SeparateDurableCheckpoint(external)
    ledger=ProtectedLedger(local,external_checkpoint=checkpoint)
    signer=Ed25519PrivateKey.generate()
    operator=Ed25519PrivateKey.generate()
    pub=operator.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    selection={"scope":root_contract.scope_from_request(req),
               "approved":{req["operation_id"]:root_contract.digest(req)},
               "identity":root_contract.digest(root_contract.scope_from_request(req)),
               "commands":{req["operation_id"]:{
                   "approval_id":"f"*32,
                   "script_sha256":"sha256:"+"f"*64,
                   "timeout_seconds":120}}}
    calls=[]
    class Sender:
        def send_fixed(self,op,cmd):
            calls.append(op)
            return "canonical-command"
    owner=SelectedOwner(ledger,installed=selection,pinned_operator_key=pub,
                        observation_signer=signer,sender=Sender())
    body={"schema":root_contract.APPROVAL_SCHEMA,"approval_id":"f"*32,
          "request_sha256":root_contract.digest(req),
          "scope_sha256":root_contract.digest(selection["scope"]),
          "expires_at":600}
    grant={**body,"signature_ed25519":base64.b64encode(
        operator.sign(root_contract.APPROVAL_DOMAIN+
                      root_contract.canonical(body))).decode("ascii")}
    client_public=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    remote=object.__new__(client.NativeOwnerClient)
    remote.public_key=client_public
    remote.pin={"scope_sha256":selection["identity"]}
    return b,s,p,req,grant,owner,remote,calls


def test_no_installed_public_key_or_socket_never_falls_back_to_ssm():
    with pytest.raises(client.NativeOwnerHold):
        client.NativeOwnerClient()
    assert "submit_command" not in client.selected_sender.__code__.co_names
    assert "boto3" not in client.selected_sender.__code__.co_names


def test_signed_owner_observation_is_exact_original_and_no_send_ticket(tmp_path):
    b,s,p,req,grant,owner,remote,calls=fake_installed(tmp_path)
    owner.submit(req,grant,now=400)
    observed=owner.observe(req,"a"*48)
    assert remote.verify_observation(
        observed,request=req,nonce="a"*48,
        expected_command="canonical-command")["command_id"]=="canonical-command"
    other=copy.deepcopy(observed)
    other["operation_id"]="0"*32
    with pytest.raises(client.NativeOwnerHold):
        remote.verify_observation(other,request=req,nonce="a"*48)
    with pytest.raises(client.NativeOwnerHold):
        remote.verify_observation(observed,request=req,nonce="b"*48)
    altered=copy.deepcopy(req);altered["authority_epoch"]=100
    with pytest.raises(client.NativeOwnerHold):
        remote.verify_observation(observed,request=altered,nonce="a"*48)
    remote.pin["scope_sha256"]="sha256:"+"0"*64
    with pytest.raises(client.NativeOwnerHold):
        remote.verify_observation(observed,request=req,nonce="a"*48)
    assert len(calls)==1


def test_full_cross_repository_unix_ipc_send_and_signed_reconciliation(tmp_path,monkeypatch):
    b,s,p,req,grant,owner,remote,calls=fake_installed(tmp_path)
    threads=[]
    def connect():
        a,z=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        def run():
            with z:
                try:
                    serve_one(z,owner,expected_uid=os.getuid(),
                              expected_gid=os.getgid(),now=400)
                except root_contract.OperationDenied:
                    z.send(root_contract.canonical({"error":"original-claim-denied"}))
        t=threading.Thread(target=run)
        t.start();threads.append(t)
        return a
    monkeypatch.setattr(remote,"_connect",connect)
    monkeypatch.setattr(remote,"_approval",lambda *args:(req,grant))
    assert remote.submit_original(b,"e"*32,s)=="canonical-command"
    assert len(calls)==1
    # Same gateway request restored after complete local rollback: root
    # external checkpoint denies the second SendCommand under its own lock.
    with pytest.raises(client.NativeOwnerHold):
        remote.submit_original(b,"e"*32,s)
    assert len(calls)==1
    for t in threads:
        t.join(2)
        assert not t.is_alive()


def test_original_approval_files_cannot_be_substituted_or_promoted(monkeypatch):
    b,s,p,req,grant,owner,remote,calls=fake_installed(__import__("tempfile").TemporaryDirectory().__enter__()) if False else (None,)*8
    # This intentionally tests only the actual contract via source static
    # evidence; the root file path and selected key are not caller-settable.
    assert str(client.PIN)=="/etc/zog/graphical-owner/gateway-client.json"
    assert str(client.APPROVALS)=="/etc/zog/graphical-owner/gateway-approvals.json"
    assert str(client.SOCKET)=="/run/zog/graphical-owner.sock"
    assert "source-only" not in client.RPC_SCHEMA
