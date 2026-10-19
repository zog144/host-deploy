import hashlib
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import threading
from http.server import ThreadingHTTPServer
import urllib.error
import urllib.request

import pytest

from zog.host_deploy.gateway.compiler_rpc import (
    CONTRACT, CompilerRPC, RPCError, _handler, decode_request,
    validate_config,
)
from zog.host_deploy.gateway.ledger import (
    load_dispatch, load_request, mark_dispatch_submitted,
    mark_dispatch_submitting, prepare_dispatch,
)
from zog.host_deploy.gateway.protocol import new_state, transition
from zog.host_deploy.workspace import save

WORKSPACE = "0123456789abcdeffedcba9876543210"
EPOCH = "1029384756aabbccddeeff0011223344"
INSTANCE = "i-0123456789abcdef0"
ACCOUNT = "123456789012"
REGION = "us-east-1"
REQUEST = "f" * 32
CERTIFICATE = b"test-client-cert-bytes"


def configuration(tmp_path, *, scopes=None, cert=CERTIFICATE):
    root = tmp_path / "gateway"
    workspace = root / "workspaces" / WORKSPACE
    owner = root / "ownership"
    workspace.mkdir(parents=True)
    owner.mkdir()
    operation = "a" * 32
    save(workspace / "workspace.json", {
        "schema": 1, "workspace_id": WORKSPACE, "name": "compiler",
        "profile": "development", "region": REGION,
    })
    save(workspace / "gateway-owner.json", {
        "schema": 1, "workspace_id": WORKSPACE, "owner": "host-deploy-gateway",
    })
    save(workspace / "host.json", {
        "region": REGION, "account_id": ACCOUNT, "instance_id": INSTANCE,
        "workspace_id": WORKSPACE, "ownership_epoch": EPOCH,
        "adoption_operation_id": operation,
    })
    save(workspace / "adoption.json", {
        "schema": 1, "workspace_id": WORKSPACE, "region": REGION,
        "account_id": ACCOUNT, "instance_id": INSTANCE,
        "ownership_epoch": EPOCH, "operation_id": operation,
        "inventory_sha256": "b" * 64,
    })
    save(owner / (WORKSPACE + ".json"), {
        "schema": 2, "workspace_id": WORKSPACE,
        "owner": "host-deploy-gateway", "phase": "owned",
        "ownership_epoch": EPOCH,
        "adoption_operation_id": operation, "inventory_sha256": "b" * 64,
    })
    return {
        "schema": 1,
        "state_directory": str(root),
        "workspace_id": WORKSPACE,
        "ownership_epoch": EPOCH,
        "instance_id": INSTANCE,
        "account_id": ACCOUNT,
        "region": REGION,
        "listen": {"host": "127.0.0.1", "port": 9443},
        "tls": {
            "certificate": "/etc/host-deploy/compiler-rpc/server.pem",
            "private_key": "/etc/host-deploy/compiler-rpc/server.key",
            "client_ca": "/etc/host-deploy/compiler-rpc/client-ca.pem",
        },
        "clients": [{
            "certificate_sha256": hashlib.sha256(cert).hexdigest(),
            "scopes": scopes or ["compiler.status", "dispatch.status"],
        }],
    }


def message(operation, parameters):
    return json.dumps({
        "schema": CONTRACT, "operation": operation, "parameters": parameters
    }).encode()


def assert_failure(code, callback):
    with pytest.raises(RPCError) as raised:
        callback()
    assert raised.value.code == code


def test_authenticated_observation_and_owner_metadata(tmp_path):
    config = configuration(tmp_path)
    rpc = CompilerRPC(config)
    response = rpc.handle(message("compiler.status", {}), CERTIFICATE)
    assert response["result"] == {
        "workspace_id": WORKSPACE,
        "ownership": "owned",
        "compiler": "registered",
        "visibility": "owner-ledger",
    }
    assert rpc.authenticate(CERTIFICATE) == {
        "compiler.status", "dispatch.status"
    }
    assert_failure(
        "not-authorized",
        lambda: rpc.handle(message("compiler.status", {}), b"wrong client"),
    )


@pytest.mark.parametrize(("edit", "reason"), [
    (("ownership", "ownership_epoch", "0" * 32), "ownership-epoch-mismatch"),
    (("host", "ownership_epoch", "0" * 32), "ownership-epoch-mismatch"),
    (("adoption", "ownership_epoch", "0" * 32), "ownership-epoch-mismatch"),
    (("host", "instance_id", "i-aaaaaaaaaaaaaaaaa"), "not-owned"),
    (("ownership", "phase", "released"), "not-owned"),
])
def test_owner_mismatch_fails_closed(tmp_path, edit, reason):
    config = configuration(tmp_path)
    name, key, value = edit
    directory = Path(config["state_directory"])
    files = {
        "host": directory / "workspaces" / WORKSPACE / "host.json",
        "adoption": directory / "workspaces" / WORKSPACE / "adoption.json",
        "ownership": directory / "ownership" / (WORKSPACE + ".json"),
    }
    path = files[name]
    changed = json.loads(path.read_text())
    changed[key] = value
    save(path, changed)
    assert_failure(
        reason, lambda: CompilerRPC(config).handle(
            message("compiler.status", {}), CERTIFICATE
        ),
    )


def test_missing_owner_or_evidence_fails_closed(tmp_path):
    config = configuration(tmp_path)
    path = Path(config["state_directory"]) / "ownership" / (WORKSPACE + ".json")
    path.unlink()
    assert_failure(
        "unavailable", lambda: CompilerRPC(config).handle(
            message("compiler.status", {}), CERTIFICATE
        )
    )


def test_readonly_scope_never_invokes_compiler_mutations(tmp_path):
    config = configuration(tmp_path)
    called = []
    rpc = CompilerRPC(
        config,
        prepare=lambda *a: called.append("prepare"),
        submit=lambda *a: called.append("submit"),
        observe=lambda *a: called.append("observe"),
    )
    for method in ("dispatch.prepare", "dispatch.submit", "dispatch.observe"):
        assert_failure(
            "not-authorized",
            lambda method=method: rpc.handle(
                message(method, {"request_id": REQUEST}), CERTIFICATE
            ),
        )
    assert called == []


@pytest.mark.parametrize("payload", [
    {"schema": CONTRACT, "operation": "shell", "parameters": {"command": "id"}},
    {"schema": CONTRACT, "operation": "compiler.status",
     "parameters": {"path": "/etc/shadow"}},
    {"schema": CONTRACT, "operation": "dispatch.submit",
     "parameters": {"request_id": REQUEST, "ssm_document": "AWS-RunShellScript"}},
    {"schema": CONTRACT, "operation": "dispatch.prepare",
     "parameters": {"request_id": "not-an-id"}},
    {"schema": CONTRACT, "operation": "compiler.status", "parameters": {},
     "extra": "test"},
])
def test_arbitrary_commands_paths_and_fields_are_rejected(payload):
    assert_failure(
        "invalid-operation",
        lambda: decode_request(json.dumps(payload).encode()),
    )


def test_duplicate_json_fields_and_oversize_rejected():
    assert_failure(
        "invalid-operation",
        lambda: decode_request(
            b'{"schema":"host-deploy-compiler-rpc-v1","operation":"compiler.status",'
            b'"operation":"dispatch.submit","parameters":{}}'
        ),
    )
    assert_failure("invalid-operation", lambda: decode_request(b"x" * 5000))


def _admit(root):
    request = {
        "schema": 1, "request_id": REQUEST, "workspace_id": WORKSPACE,
        "operation": "build.status",
        "origin": {
            "repository": "zog144/host-deploy", "issue_number": 42,
            "trigger_actor": "zog144",
        },
        "parameters": {"lane": "gateway-pass4-readonly", "pipeline_id": "c" * 32},
    }
    state = new_state(request)
    for stage, status in (
        ("acceptance", "accepted"), ("admission", "pending"),
        ("admission", "admitted"),
    ):
        state = transition(state, stage, status, "2026-10-11T12:00:00Z")
    save(root / "requests" / REQUEST / "state.json", state)
    return state


def test_prepared_request_durable_retry_and_sanitized_recovery(tmp_path):
    config = configuration(
        tmp_path,
        scopes=["compiler.status", "dispatch.status",
                "dispatch.prepare", "dispatch.submit", "dispatch.observe"],
    )
    root = Path(config["state_directory"])
    _admit(root)
    calls = []

    def prepare(root, request_id):
        binding = {
            "request_id": request_id, "workspace_id": WORKSPACE,
            "aws_password": "secret-that-must-not-leak",
        }
        return prepare_dispatch(root, request_id, binding)

    def submit(root, request_id):
        previous = load_dispatch(root, request_id)
        if previous["phase"] == "submitted":
            return load_request(root, request_id), previous
        mark_dispatch_submitting(root, request_id)
        calls.append("one-admitted-compiler-action")
        return mark_dispatch_submitted(root, request_id, "command-id-opaque")

    rpc = CompilerRPC(config, prepare=prepare, submit=submit)
    prepared = rpc.handle(
        message("dispatch.prepare", {"request_id": REQUEST}), CERTIFICATE
    )
    again = rpc.handle(
        message("dispatch.prepare", {"request_id": REQUEST}), CERTIFICATE
    )
    assert prepared["result"]["dispatch"] == again["result"]["dispatch"]
    first = rpc.handle(
        message("dispatch.submit", {"request_id": REQUEST}), CERTIFICATE
    )
    restarted = CompilerRPC(config, prepare=prepare, submit=submit)
    duplicate = restarted.handle(
        message("dispatch.submit", {"request_id": REQUEST}), CERTIFICATE
    )
    assert first == duplicate
    assert calls == ["one-admitted-compiler-action"]
    observation = restarted.handle(
        message("dispatch.status", {"request_id": REQUEST}), CERTIFICATE
    )
    assert observation["result"]["request"]["completion"] == "pending"
    assert "secret-that-must-not-leak" not in json.dumps(observation)
    assert "secret-that-must-not-leak" not in json.dumps(first)
    assert "command-id-opaque" not in json.dumps(first)


def test_mutation_rejects_unadmitted_request(tmp_path):
    config = configuration(
        tmp_path, scopes=["dispatch.prepare", "dispatch.submit"]
    )
    root = Path(config["state_directory"])
    state = _admit(root)
    state["states"]["admission"] = "pending"
    # The malformed transition history must not be silently trusted.
    save(root / "requests" / REQUEST / "state.json", state)
    assert_failure(
        "unavailable", lambda: CompilerRPC(config).handle(
            message("dispatch.prepare", {"request_id": REQUEST}), CERTIFICATE
        ),
    )


def test_missing_request_not_created_by_observation(tmp_path):
    config = configuration(tmp_path)
    root = Path(config["state_directory"])
    path = root / "requests" / REQUEST
    assert_failure(
        "unavailable", lambda: CompilerRPC(config).handle(
            message("dispatch.status", {"request_id": REQUEST}), CERTIFICATE
        ),
    )
    assert not path.exists()


def test_configuration_fails_closed_on_unknown_scopes(tmp_path):
    config = configuration(tmp_path)
    config["clients"][0]["scopes"] = ["arbitrary.ssm"]
    with pytest.raises(ValueError, match="client scope"):
        validate_config(config)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL binary needed")
def test_live_https_client_certificate_authentication(tmp_path):
    """Exercises real TLS client verification and bounded HTTPS RPC end to end."""
    from zog.host_deploy.gateway.compiler_rpc import _Server, serve

    ca = tmp_path / "ca.pem"
    ca_key = tmp_path / "ca.key"
    server_key = tmp_path / "server.key"
    server_csr = tmp_path / "server.csr"
    server_cert = tmp_path / "server.pem"
    client_key = tmp_path / "client.key"
    client_csr = tmp_path / "client.csr"
    client_cert = tmp_path / "client.pem"

    def openssl(*args):
        subprocess.run(
            ["openssl", *args], check=True, capture_output=True, timeout=15
        )

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca),
            "-days", "1", "-subj", "/CN=Test-CA")
    for name, key, csr, cert in (
        ("localhost", server_key, server_csr, server_cert),
        ("station-observer", client_key, client_csr, client_cert),
    ):
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                "-out", str(csr), "-subj", "/CN=" + name)
        args = ("x509", "-req", "-in", str(csr), "-CA", str(ca),
                "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert),
                "-days", "1")
        openssl(*args)

    pem = client_cert.read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    config = configuration(tmp_path, cert=der)
    config["tls"] = {
        "certificate": str(server_cert),
        "private_key": str(server_key),
        "client_ca": str(ca),
    }

    allocated = {}
    import threading

    def factory(address, handler):
        server = _Server(("127.0.0.1", 0), handler)
        allocated["server"] = server
        return server

    rpc = CompilerRPC(config)
    thread = threading.Thread(
        target=serve,
        args=(config,),
        kwargs={"rpc": rpc, "server_factory": factory},
        daemon=True,
    )
    thread.start()
    import time
    for _ in range(100):
        if "server" in allocated and isinstance(
            allocated["server"].socket, ssl.SSLSocket
        ):
            break
        time.sleep(0.02)
    else:
        raise AssertionError("TLS listener not initialized")
    server = allocated["server"]
    url = "https://localhost:" + str(server.server_port) + "/v1/compiler/rpc"
    context = ssl.create_default_context(cafile=str(ca))
    context.load_cert_chain(str(client_cert), str(client_key))
    try:
        req = urllib.request.Request(
            url, data=message("compiler.status", {}),
            headers={"Content-Type": "application/json"},
        )
        value = json.loads(
            urllib.request.urlopen(req, context=context, timeout=4).read()
        )
        assert value["status"] == "completed"
        assert value["result"]["workspace_id"] == WORKSPACE
        readonly = urllib.request.Request(
            url, data=message("dispatch.submit", {"request_id": REQUEST}),
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(readonly, context=context, timeout=4)
        assert error.value.code == 403

        unauthenticated = ssl.create_default_context(cafile=str(ca))
        with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError)):
            urllib.request.urlopen(req, context=unauthenticated, timeout=4)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=4)
