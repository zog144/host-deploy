"""Exact-source certificate controller compatibility acceptance (no live socket).

Run only after the certificate workflow checked out box-control at the source
revision hard-pinned in certificate_issuer_lifecycle. This imports the REAL
upstream client rather than substituting a fake controller implementation.
"""
from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import types

import pytest

from zog.host_deploy.certificate_issuer_lifecycle import (
    ISSUER_LIFECYCLE_BOX_CONTROL_REVISION,
    ISSUER_LIFECYCLE_CLIENT_MODULE,
    SelectedIssuerController,
)
from zog.host_deploy.certificate_renewal import RenewalBlocked


REQUEST_ID = "r1-1-" + "a" * 32 + "-" + "b" * 64
DIFFERENT = "r1-1-" + "c" * 32 + "-" + "d" * 64


def _pinned_client():
    checkout = Path(os.environ["ZOG_BOX_CONTROL_CHECKOUT"]).resolve(strict=True)
    resolved = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "--verify", "HEAD"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()
    assert resolved == ISSUER_LIFECYCLE_BOX_CONTROL_REVISION, (
        "unreviewed box-control source revision"
    )
    # Load the actual checked-out producer client and transport source, while
    # excluding unrelated box-control package initialization (the complete
    # box-control package requires the image-build runtime). The isolated
    # broker contract stub carries no production grant or transport.
    expected = (checkout / ISSUER_LIFECYCLE_CLIENT_MODULE).resolve(strict=True)
    src_dir = expected.parent
    prefix = "_host_deploy_pinned_issuer"
    pkg = types.ModuleType(prefix)
    pkg.__path__ = [str(src_dir)]
    sys.modules[prefix] = pkg
    role = types.ModuleType(prefix + ".role_broker")
    class RoleBrokerError(ValueError):
        def __init__(self, message, *, code="blocked"):
            super().__init__(message)
            self.code = code
    role.RoleBrokerError = RoleBrokerError
    role.SCHEMA = "zog-application-role-broker-v1"
    role._REQUEST = re.compile(r"[A-Za-z0-9-]{1,200}\\Z")
    role._RUNTIME = re.compile(r"[A-Za-z0-9-]{1,40}\\Z")
    role._APPLICATION = re.compile(r"[A-Za-z0-9-]{1,64}\\Z")
    role._decode = lambda raw, *args, **kwargs: raw
    role._json_bytes = lambda raw, *args: b""
    role._peer_uid = lambda connection: 23001
    sys.modules[role.__name__] = role

    def load_real_module(module_name, path):
        spec = importlib.util.spec_from_file_location(prefix + "." + module_name,
                                                       path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    load_real_module("role_broker_client", src_dir / "role_broker_client.py")
    imported = load_real_module("issuer_lifecycle_client", expected)
    assert Path(imported.__file__).resolve(strict=True) == expected
    client = imported.IssuerLifecycleClient(
        "/run/zog/certify-lifecycle.sock", controller_uid=23001
    )
    assert client.expected_server_uid == 23001
    return imported, client


def _envelope():
    now = datetime.now(timezone.utc)
    return {
        "schema": "zog-trusted-issuer-inspection-v1",
        "request_id": REQUEST_ID, "runtime_id": "RUNTIME01",
        "program": "inspect", "boot_id": "a" * 32,
        "invocation_id": "b" * 32,
        "storage_id": "c" * 32, "grant_id": "d" * 32,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "host_policy_digest": "sha256:" + "e" * 64,
        "status": "verified", "tls_ready": False,
        "inspection": {
            "schema": "zog-certify-inspection-result-v1",
            "certificate_id": "station-web", "hostnames": ["candidate.example.org"],
            "policy_sha256": "f" * 64, "health": "valid",
            "certificate_fingerprint_sha256": "1" * 64,
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=20)).isoformat(),
            "days_remaining": 20, "operation": "renew", "outcome": "renewed",
            "operation_updated_at": (now - timedelta(minutes=1)).isoformat(),
            "observed_at": now.isoformat(), "issuer_verified": True,
            "tls_ready": False,
        },
    }


def test_selected_inspect_round_trip_uses_real_pinned_client():
    _, client = _pinned_client()
    calls = []

    def local_broker(operation, **args):
        calls.append((operation, args))
        if operation == "start":
            return {"program": "inspect", "runtime_id": "RUNTIME01"}
        if operation == "result":
            return {
                "request_id": REQUEST_ID, "program": "inspect",
                "runtime_id": "RUNTIME01", "status": "satisfied",
            }
        if operation == "inspect-result":
            return _envelope()
        raise AssertionError("unsupported controller operation: " + operation)

    client._call = local_broker
    adapter = SelectedIssuerController(
        "/run/zog/certify-lifecycle.sock", controller_uid=23001,
        client_factory=lambda path, *, controller_uid: client,
    )
    launched = adapter.request_application_launch(
        "certify-manage", program_name="inspect", request_id=REQUEST_ID,
    )
    assert launched.runtime_id == "RUNTIME01"
    result = adapter.application_request_result(REQUEST_ID)
    assert result.request_id == REQUEST_ID and result.program_name == "inspect"
    assert result.status == "satisfied"
    inspection = adapter.inspect_issuer_result(REQUEST_ID)
    assert inspection["request_id"] == REQUEST_ID
    assert inspection["inspection"]["certificate_fingerprint_sha256"] == "1" * 64
    assert calls == [
        ("start", {"request_id": REQUEST_ID, "program": "inspect"}),
        ("result", {"request_id": REQUEST_ID}),
        ("inspect-result", {"request_id": REQUEST_ID}),
    ]
    with pytest.raises(RenewalBlocked, match="selection-rejected"):
        adapter.request_application_launch(
            "certify-manage", program_name="shell", request_id=REQUEST_ID,
        )


@pytest.mark.parametrize("invalid", [
    {"request_id": DIFFERENT},
    {"program": "shell"},
    {"program": 123},
    {"program": ["inspect"]},
    {"program": False},
])
def test_original_request_or_program_mismatch_rejected_in_real_client(invalid):
    module, client = _pinned_client()
    client._call = lambda operation, **args: {
        "request_id": REQUEST_ID, "status": "satisfied",
        "program": "inspect", "runtime_id": "RUNTIME01", **invalid,
    }
    with pytest.raises(module.RoleBrokerError):
        client.application_request_result(REQUEST_ID)


def test_real_inspection_reader_requires_pinned_controller_uid():
    module, _ = _pinned_client()
    client = module.IssuerLifecycleClient("/run/zog/certify-lifecycle.sock")
    client._call = lambda *args, **kwargs: pytest.fail(
        "inspection must not access broker without authenticated controller UID"
    )
    with pytest.raises(module.RoleBrokerError, match="UID"):
        client.inspect_issuer_result(REQUEST_ID)
