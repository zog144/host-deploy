import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest

from zog.host_deploy.compiler_rpc_identity import (
    IdentityBlocked, OBSERVER_SCOPES, _certificates,
    plan_enrollment,
)

OPENSSL = shutil.which("openssl")


def _run(*args):
    subprocess.run(["openssl", *args], capture_output=True,
                   text=True, timeout=20, check=True)


def _ca(path, name):
    key, cert = path / (name + ".key"), path / (name + ".pem")
    _run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
         "-subj", "/CN=" + name, "-keyout", str(key), "-out", str(cert))
    return key, cert


@pytest.mark.skipif(OPENSSL is None, reason="OpenSSL is required for real X.509 testing")
def test_additive_rpc_identity_rotation_preserves_existing_trust_and_scope(tmp_path):
    old_key, old_ca = _ca(tmp_path, "old-ca")
    new_key, new_ca = _ca(tmp_path, "new-ca")
    client_key = tmp_path / "station-client.key"
    csr = tmp_path / "station-client.csr"
    cert = tmp_path / "station-client.pem"
    _run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=station-observer",
         "-keyout", str(client_key), "-out", str(csr))
    _run("x509", "-req", "-in", str(csr), "-CA", str(new_ca),
         "-CAkey", str(new_key), "-CAcreateserial", "-out", str(cert), "-days", "30")
    bundle = tmp_path / "additive-ca.pem"
    bundle.write_text(old_ca.read_text() + new_ca.read_text())
    config = {
        "schema": 1, "state_directory": "/var/lib/host-deploy-gateway",
        "workspace_id": "a"*32, "ownership_epoch": "b"*32,
        "instance_id": "i-0123456789abcdef0", "account_id": "123456789012",
        "region": "us-east-1", "listen": {"host": "127.0.0.1", "port": 9443},
        "tls": {
            "certificate": "/etc/host-deploy/server.pem",
            "private_key": "/etc/host-deploy/server.key",
            "client_ca": str(old_ca),
        },
        "clients": [{"certificate_sha256": "f"*64,
                     "scopes": ["compiler.status", "dispatch.status"]}],
    }
    report = plan_enrollment(
        config, new_client_certificate=cert, current_client_ca=old_ca,
        additive_client_ca=bundle,
    )
    expected = hashlib.sha256(_certificates(cert.read_text())[0]).hexdigest()
    assert report["status"] == "proposed-not-applied"
    assert report["new_station_certificate_sha256"] == expected
    assert report["existing_client_fingerprints"] == ["f"*64]
    assert report["prospective_server_configuration"]["clients"] == [
        *config["clients"],
        {"certificate_sha256": expected, "scopes": list(OBSERVER_SCOPES)},
    ]
    assert report["prospective_server_configuration"]["tls"]["client_ca"] == str(bundle)
    assert "PRIVATE KEY" not in str(report)
    assert str(client_key) not in str(report)
    with pytest.raises(IdentityBlocked, match="remove previously trusted"):
        plan_enrollment(config, new_client_certificate=cert,
                        current_client_ca=old_ca, additive_client_ca=new_ca)
    with pytest.raises(IdentityBlocked, match="distinct"):
        plan_enrollment(
            {**config, "clients": [{"certificate_sha256": expected,
                                    "scopes": list(OBSERVER_SCOPES)}]},
            new_client_certificate=cert, current_client_ca=old_ca,
            additive_client_ca=bundle,
        )
    with pytest.raises(IdentityBlocked, match="trust path differs"):
        plan_enrollment(config, new_client_certificate=cert,
                        current_client_ca=new_ca, additive_client_ca=bundle)
    cert.unlink()
    with pytest.raises(IdentityBlocked, match="unavailable"):
        plan_enrollment(config, new_client_certificate=cert,
                        current_client_ca=old_ca, additive_client_ca=bundle)


def test_invalid_pem_and_paths_rejected(tmp_path):
    file = tmp_path / "bad.pem"
    file.write_text("not a certificate: synthetic malformed input")
    with pytest.raises(IdentityBlocked, match="malformed"):
        _certificates(file.read_text())
    file.unlink()
    with pytest.raises(IdentityBlocked, match="unavailable"):
        from zog.host_deploy.compiler_rpc_identity import _public_file
        _public_file(file)
