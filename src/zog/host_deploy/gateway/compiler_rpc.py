"""Authenticated, owner-bound RPC facade for the adopted compiler gateway.

No RPC method accepts an AWS target, command, path, source revision or shell text.
The existing gateway ledger remains the only compiler mutation authority.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import re
import ssl
import threading

from .image_build_dispatch import prepare_image_build_dispatch
from .image_build_execution import observe_submitted, submit_prepared
from .ledger import LedgerConflict, load_dispatch, load_request, owned_workspace

CONTRACT = "host-deploy-compiler-rpc-v1"
OPERATIONS = frozenset((
    "compiler.status", "dispatch.status", "dispatch.prepare",
    "dispatch.submit", "dispatch.observe",
))
READ_ONLY = frozenset(("compiler.status", "dispatch.status"))
MAXIMUM_REQUEST_BYTES = 4096
MAXIMUM_RESPONSE_BYTES = 8192
_ID = re.compile(r"[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class RPCError(Exception):
    """Safe failure category, never a raw backend traceback."""

    def __init__(self, code, http_status=409):
        super().__init__(code)
        self.code = code
        self.http_status = http_status


def _regular_json(path, label):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise RPCError("unavailable", 503)
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        raise RPCError("unavailable", 503) from None
    if not isinstance(value, dict):
        raise RPCError("unavailable", 503)
    return value


def _owned(config):
    """Check the adopted workspace, epoch and target from retained owner evidence."""
    root = Path(config["state_directory"])
    workspace_id = config["workspace_id"]
    if not root.is_dir() or root.is_symlink():
        raise RPCError("unavailable", 503)
    try:
        workspace = owned_workspace(root, workspace_id)
    except (ValueError, RuntimeError, OSError):
        raise RPCError("not-owned") from None
    if workspace is None or workspace.is_symlink():
        raise RPCError("not-owned")
    owner = _regular_json(root / "ownership" / (workspace_id + ".json"), "ownership")
    marker = _regular_json(workspace / "gateway-owner.json", "workspace owner")
    host = _regular_json(workspace / "host.json", "compiler host")
    adoption = _regular_json(workspace / "adoption.json", "adoption")
    expected = {
        "workspace_id": workspace_id,
        "instance_id": config["instance_id"],
        "account_id": config["account_id"],
        "region": config["region"],
    }
    if (owner.get("schema") != 2 or owner.get("phase") != "owned"
            or owner.get("owner") != "host-deploy-gateway"
            or owner.get("workspace_id") != workspace_id
            or marker != {"schema": 1, "workspace_id": workspace_id,
                          "owner": "host-deploy-gateway"}):
        raise RPCError("not-owned")
    epoch = config["ownership_epoch"]
    if (owner.get("ownership_epoch") != epoch
            or host.get("ownership_epoch") != epoch
            or adoption.get("ownership_epoch") != epoch):
        raise RPCError("ownership-epoch-mismatch")
    if (any(host.get(key) != value or adoption.get(key) != value
            for key, value in expected.items())
            or owner.get("adoption_operation_id") != adoption.get("operation_id")
            or host.get("adoption_operation_id") != adoption.get("operation_id")
            or owner.get("inventory_sha256") != adoption.get("inventory_sha256")):
        raise RPCError("not-owned")
    return workspace


def validate_config(value):
    required = {
        "schema", "state_directory", "workspace_id", "ownership_epoch",
        "instance_id", "account_id", "region", "listen",
        "tls", "clients",
    }
    if not isinstance(value, dict) or set(value) != required or value["schema"] != 1:
        raise ValueError("invalid compiler RPC configuration schema")
    if (any(not isinstance(value.get(k), str) or not _ID.fullmatch(value[k])
            for k in ("workspace_id", "ownership_epoch"))
            or not isinstance(value["instance_id"], str)
            or not re.fullmatch(r"i-[0-9a-f]{8,32}", value["instance_id"])
            or not isinstance(value["account_id"], str)
            or not re.fullmatch(r"[0-9]{12}", value["account_id"])
            or not isinstance(value["region"], str)
            or not re.fullmatch(r"[a-z]{2}-[a-z-]+-\d", value["region"])):
        raise ValueError("invalid compiler RPC owned host identity")
    if (not isinstance(value["state_directory"], str)
            or not Path(value["state_directory"]).is_absolute()):
        raise ValueError("compiler RPC state_directory must be absolute")
    listen = value["listen"]
    if (not isinstance(listen, dict) or set(listen) != {"host", "port"}
            or not isinstance(listen["host"], str)
            or not listen["host"] or len(listen["host"]) > 255
            or type(listen["port"]) is not int
            or not 1 <= listen["port"] <= 65535):
        raise ValueError("invalid compiler RPC listen configuration")
    tls = value["tls"]
    if not isinstance(tls, dict) or set(tls) != {"certificate", "private_key", "client_ca"}:
        raise ValueError("compiler RPC requires mutual TLS")
    if any(not isinstance(item, str) or not Path(item).is_absolute()
           for item in tls.values()):
        raise ValueError("compiler RPC TLS files must be absolute")
    clients = value["clients"]
    if not isinstance(clients, list) or not clients or len(clients) > 32:
        raise ValueError("compiler RPC requires explicit authorized clients")
    seen = set()
    for item in clients:
        if not isinstance(item, dict) or set(item) != {"certificate_sha256", "scopes"}:
            raise ValueError("invalid compiler RPC client")
        digest = item["certificate_sha256"]
        scopes = item["scopes"]
        if (not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                or digest in seen
                or not isinstance(scopes, list) or not scopes
                or len(scopes) != len(set(scopes))
                or any(scope not in OPERATIONS for scope in scopes)):
            raise ValueError("invalid compiler RPC client scope")
        seen.add(digest)
    return json.loads(json.dumps(value))


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise RPCError("invalid-operation", 400)
        result[name] = value
    return result


def decode_request(payload):
    if not isinstance(payload, bytes) or len(payload) > MAXIMUM_REQUEST_BYTES:
        raise RPCError("invalid-operation", 400)
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (UnicodeError, ValueError, TypeError):
        raise RPCError("invalid-operation", 400) from None
    if (not isinstance(value, dict)
            or set(value) != {"schema", "operation", "parameters"}
            or value["schema"] != CONTRACT
            or value["operation"] not in OPERATIONS
            or not isinstance(value["parameters"], dict)):
        raise RPCError("invalid-operation", 400)
    operation = value["operation"]
    parameters = value["parameters"]
    if operation == "compiler.status":
        expected = set()
    elif operation in {"dispatch.status", "dispatch.prepare",
                       "dispatch.submit", "dispatch.observe"}:
        expected = {"request_id"}
    else:
        raise RPCError("invalid-operation", 400)
    if set(parameters) != expected:
        raise RPCError("invalid-operation", 400)
    if expected and (not isinstance(parameters["request_id"], str)
                     or not _ID.fullmatch(parameters["request_id"])):
        raise RPCError("invalid-operation", 400)
    return operation, parameters


def _safe_request(state):
    return {
        "request_id": state["request_id"],
        "operation": state["request"]["operation"],
        "admission": state["states"]["admission"],
        "dispatch": state["states"]["dispatch"],
        "completion": state["states"]["completion"],
    }


def _safe_dispatch(record):
    if record is None:
        return {"phase": "not-prepared"}
    return {
        "phase": record["phase"],
        "binding_sha256": record["binding_sha256"],
        "submitted": record["phase"] == "submitted",
    }


def _safe_failure(error):
    """Do not let boto3, state paths, SSM stderr or authorization leak to clients."""
    if isinstance(error, RPCError):
        return error
    if isinstance(error, (LedgerConflict, FileNotFoundError, OSError)):
        return RPCError("unavailable", 503)
    if isinstance(error, (TimeoutError,)):
        return RPCError("uncertain")
    if isinstance(error, RuntimeError):
        message = str(error).lower()
        if any(key in message for key in ("uncertain", "cannot replay", "submitting")):
            return RPCError("uncertain")
        return RPCError("unavailable", 503)
    return RPCError("unavailable", 503)


class CompilerRPC:
    def __init__(self, config, *, prepare=None, submit=None, observe=None):
        self.config = validate_config(config)
        self.prepare = prepare or prepare_image_build_dispatch
        self.submit = submit or submit_prepared
        self.observe = observe or observe_submitted

    def authenticate(self, der_certificate):
        if not isinstance(der_certificate, bytes) or not der_certificate:
            raise RPCError("not-authorized", 403)
        digest = hashlib.sha256(der_certificate).hexdigest()
        for client in self.config["clients"]:
            if hmac.compare_digest(digest, client["certificate_sha256"]):
                return frozenset(client["scopes"])
        raise RPCError("not-authorized", 403)

    def call(self, operation, parameters, *, scopes):
        if operation not in OPERATIONS:
            raise RPCError("invalid-operation", 400)
        if operation not in scopes:
            raise RPCError("not-authorized", 403)
        root = Path(self.config["state_directory"])
        _owned(self.config)
        try:
            if operation == "compiler.status":
                return {
                    "workspace_id": self.config["workspace_id"],
                    "ownership": "owned",
                    "compiler": "registered",
                    "visibility": "owner-ledger",
                }
            request_id = parameters["request_id"]
            path = root / "requests" / request_id / "state.json"
            if path.is_symlink() or not path.is_file():
                raise RPCError("unavailable", 404)
            state = load_request(root, request_id)
            if state["request"]["workspace_id"] != self.config["workspace_id"]:
                raise RPCError("not-owned")
            if operation == "dispatch.status":
                return {
                    "request": _safe_request(state),
                    "dispatch": _safe_dispatch(load_dispatch(root, request_id)),
                }
            if state["states"]["admission"] != "admitted":
                raise RPCError("not-authorized", 403)
            if operation == "dispatch.prepare":
                state, record = self.prepare(root, request_id)
            elif operation == "dispatch.submit":
                current = load_dispatch(root, request_id)
                if current is None:
                    raise RPCError("unavailable", 409)
                state, record = self.submit(root, request_id)
            elif operation == "dispatch.observe":
                current = load_dispatch(root, request_id)
                if current is None or current.get("phase") != "submitted":
                    raise RPCError("uncertain")
                state, record = self.observe(root, request_id)
            else:
                raise RPCError("invalid-operation", 400)
            return {"request": _safe_request(state), "dispatch": _safe_dispatch(record)}
        except Exception as error:
            raise _safe_failure(error) from None

    def handle(self, payload, der_certificate):
        """Bounded authenticated entrypoint also used by the network handler."""
        scopes = self.authenticate(der_certificate)
        operation, parameters = decode_request(payload)
        result = self.call(operation, parameters, scopes=scopes)
        return {"schema": CONTRACT, "status": "completed", "result": result}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _handler(rpc):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            # Never log client-supplied request bodies, authorization material or errors.
            pass

        def _respond(self, status, body):
            raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
            if len(raw) > MAXIMUM_RESPONSE_BYTES:
                status = 503
                raw = b'{"schema":"host-deploy-compiler-rpc-v1","status":"unavailable"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            if self.path != "/v1/compiler/rpc":
                self._respond(404, {"schema": CONTRACT, "status": "invalid-operation"})
                return
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= size <= MAXIMUM_REQUEST_BYTES:
                    raise RPCError("invalid-operation", 400)
                certificate = self.connection.getpeercert(binary_form=True)
                # Authentication occurs before parsing untrusted request bytes.
                rpc.authenticate(certificate)
                result = rpc.handle(self.rfile.read(size), certificate)
                self._respond(200, result)
            except Exception as error:
                failure = _safe_failure(error)
                self._respond(
                    failure.http_status,
                    {"schema": CONTRACT, "status": failure.code},
                )

        def do_GET(self):
            self._respond(405, {"schema": CONTRACT, "status": "invalid-operation"})

    return Handler


def serve(config, *, rpc=None, server_factory=_Server):
    config = validate_config(config)
    rpc = rpc or CompilerRPC(config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(config["tls"]["certificate"], config["tls"]["private_key"])
    context.load_verify_locations(cafile=config["tls"]["client_ca"])
    server = server_factory(
        (config["listen"]["host"], config["listen"]["port"]), _handler(rpc)
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.25)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    options = parser.parse_args(argv)
    path = Path(options.config)
    if path.is_symlink() or not path.is_file():
        parser.error("RPC configuration must be a real file")
    config = validate_config(json.loads(path.read_text()))
    serve(config)


if __name__ == "__main__":
    main()
