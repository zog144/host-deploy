"""Source-only IPC denial tests. No native owner, socket or SSM execution."""
import json
import socket
import pytest
from zog.host_deploy.gateway import graphics_owner_ipc as ipc

REQ = dict(request_id="a"*32, operation_id="b"*32, stage="submit",
           ordinal=0, binding_sha256="c"*64, remote_request_sha256="d"*64)

def test_missing_native_root_owned_socket_denies():
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**REQ)

@pytest.mark.parametrize("field,invalid", [
    ("request_id", "../escape"), ("operation_id", "x"*32),
    ("stage", "arbitrary"), ("ordinal", True), ("ordinal", 64),
    ("binding_sha256", "sha256:"+"c"*64),
    ("remote_request_sha256", "0"*63),
])
def test_untrusted_or_noncanonical_identity_denied_before_socket(field, invalid, monkeypatch):
    monkeypatch.setattr(ipc, "_check_path", lambda: pytest.fail("socket reached"))
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**{**REQ, field: invalid})

class FakeSocket:
    def __init__(self, response, peer):
        self.response=response
        self.peer=peer
        self.sent=b""
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, value): assert value == 5
    def connect(self, value): assert value == ipc.SOCKET_PATH
    def getsockopt(self, *args):
        import struct
        return struct.pack("3i", 1234, self.peer, 0)
    def sendall(self, data):
        self.sent=data
        self.response=self.response(json.loads(data))
    def recv(self, n): 
        value=self.response
        self.response=b""
        return value

def test_root_peer_exact_nonce_bound_original_command(monkeypatch):
    monkeypatch.setattr(ipc, "_check_path", lambda: None)
    def reply(req):
        assert set(req) == {"schema", "action", "nonce", "request_id",
                            "operation_id", "stage", "ordinal",
                            "binding_sha256", "remote_request_sha256"}
        assert "script" not in req and "credentials" not in req
        result={"schema":ipc.SCHEMA, "nonce":req["nonce"], "operation_id":req["operation_id"],
                "status":"sent-original", "command_id":"original-command-id"}
        return ipc._canonical(result)+b"\n"
    sock=FakeSocket(reply, 0)
    monkeypatch.setattr(socket, "socket", lambda *args: sock)
    assert ipc.submit_original(**REQ) == "original-command-id"

def test_untrusted_peer_denied_before_request(monkeypatch):
    monkeypatch.setattr(ipc, "_check_path", lambda: None)
    sock=FakeSocket(lambda x: b"", 1001)
    monkeypatch.setattr(socket, "socket", lambda *args: sock)
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**REQ)
    assert not sock.sent

@pytest.mark.parametrize("malicious", [
    lambda r: {**r, "nonce":"0"*48},
    lambda r: {**r, "operation_id":"0"*32},
    lambda r: {**r, "status":"claimed"},
    lambda r: {**r, "command_id":""},
    lambda r: {**r, "shell":"echo injected"},
])
def test_ambiguous_or_substituted_owner_reply_denied(monkeypatch, malicious):
    monkeypatch.setattr(ipc, "_check_path", lambda: None)
    def reply(req):
        r={"schema":ipc.SCHEMA,"nonce":req["nonce"],"operation_id":req["operation_id"],
           "status":"sent-original","command_id":"original-id"}
        return ipc._canonical(malicious(r))+b"\n"
    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket(reply,0))
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**REQ)

def test_duplicate_response_keys_denied(monkeypatch):
    monkeypatch.setattr(ipc, "_check_path", lambda: None)
    def reply(req):
        raw=ipc._canonical({"schema":ipc.SCHEMA,"nonce":req["nonce"],
            "operation_id":req["operation_id"],"status":"sent-original",
            "command_id":"one"})
        return raw[:-1]+b',"command_id":"two"}\n'
    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket(reply,0))
    with pytest.raises(ipc.OwnerUnavailable):
        ipc.submit_original(**REQ)
