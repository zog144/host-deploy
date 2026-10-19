"""Plan additive compiler RPC observer certificate rotation without handling keys.

This module never issues a certificate, copies a private key, changes the
server configuration, or deletes earlier client/CA trust during enrollment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess

from .gateway.compiler_rpc import validate_config

SCHEMA = "zog-compiler-rpc-identity-transition-v1"
OBSERVER_SCOPES = ("compiler.status", "dispatch.status")
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\s*[\w+/=\s]+-----END CERTIFICATE-----")


class IdentityBlocked(ValueError):
    pass


def _certificates(data):
    if not isinstance(data, str) or len(data) > 256 * 1024:
        raise IdentityBlocked("certificate material is invalid")
    chunks = _PEM.findall(data)
    if not chunks or "".join(data.split()) != "".join("".join(chunks).split()):
        raise IdentityBlocked("certificate bundle is malformed")
    try:
        return [ssl.PEM_cert_to_DER_cert(chunk) for chunk in chunks]
    except (ValueError, ssl.SSLError):
        raise IdentityBlocked("certificate bundle is malformed") from None


def _public_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        raise IdentityBlocked("public certificate file unavailable")
    try:
        return path.read_text()
    except (OSError, UnicodeError):
        raise IdentityBlocked("public certificate file unavailable") from None


def _fingerprint(der):
    return hashlib.sha256(der).hexdigest()


def _validate_with_openssl(client_cert, ca_bundle, *, run=subprocess.run):
    # Fixed argument vector; no shell and no response containing private data.
    for cmd in (
        ["openssl", "verify", "-purpose", "sslclient",
         "-CAfile", str(ca_bundle), str(client_cert)],
        ["openssl", "x509", "-checkend", "86400",
         "-noout", "-in", str(client_cert)],
    ):
        try:
            result = run(cmd, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            raise IdentityBlocked("certificate verification unavailable") from None
        if result.returncode != 0:
            raise IdentityBlocked("client certificate chain or expiry is not acceptable")


def plan_enrollment(
    configuration, *, new_client_certificate, current_client_ca,
    additive_client_ca, run=subprocess.run,
):
    """Return a nonsecret prospective config and exact additive rollout gates."""
    config = validate_config(configuration)
    if config["tls"]["client_ca"] != str(current_client_ca):
        raise IdentityBlocked("current trust path differs from running owner configuration")
    current_ca = _certificates(_public_file(current_client_ca))
    new_ca = _certificates(_public_file(additive_client_ca))
    old_trust = {_fingerprint(der) for der in current_ca}
    new_trust = {_fingerprint(der) for der in new_ca}
    if not old_trust.issubset(new_trust):
        raise IdentityBlocked("rotation would remove previously trusted client CA")
    certs = _certificates(_public_file(new_client_certificate))
    if len(certs) != 1:
        raise IdentityBlocked("observer identity must contain exactly one client certificate")
    _validate_with_openssl(new_client_certificate, additive_client_ca, run=run)
    fingerprint = _fingerprint(certs[0])
    existing = {item["certificate_sha256"] for item in config["clients"]}
    if fingerprint in existing:
        raise IdentityBlocked("new station identity must be distinct from existing identities")
    if len(existing) >= 32:
        raise IdentityBlocked("client allowlist at capacity")
    prospective = json.loads(json.dumps(config))
    prospective["tls"]["client_ca"] = str(additive_client_ca)
    prospective["clients"].append({
        "certificate_sha256": fingerprint,
        "scopes": list(OBSERVER_SCOPES),
    })
    validate_config(prospective)
    return {
        "schema": SCHEMA,
        "status": "proposed-not-applied",
        "new_station_certificate_sha256": fingerprint,
        "existing_client_fingerprints": sorted(existing),
        "preserved_client_ca_sha256": sorted(old_trust),
        "added_client_ca_sha256": sorted(new_trust - old_trust),
        "prospective_server_configuration": prospective,
        "private_key_bytes": "never-collected",
        "gates": [
            "approve-new-CA-and-expiration",
            "preserve-old-server-CA-and-client-fingerprints",
            "install-new-client-key-in-station-owned-protected-storage",
            "verify-certificate-mode-and-station-execution-identity",
            "reload-RPC-with-additive-trust",
            "verify-new-observer-readonly-and-old-approved-client",
            "record-expiry-and-revocation-review",
            "remove-retired-trust-only-in-separate-reviewed-change",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-config", required=True)
    parser.add_argument("--new-client-certificate", required=True)
    parser.add_argument("--current-client-ca", required=True)
    parser.add_argument("--additive-client-ca", required=True)
    args = parser.parse_args(argv)
    try:
        path = Path(args.server_config)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            raise IdentityBlocked("RPC configuration unavailable")
        value = json.loads(path.read_text())
        report = plan_enrollment(
            value, new_client_certificate=args.new_client_certificate,
            current_client_ca=args.current_client_ca,
            additive_client_ca=args.additive_client_ca,
        )
        print(json.dumps(report, sort_keys=True))
        return 0
    except (IdentityBlocked, ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"schema": SCHEMA, "status": "blocked",
                          "reason": "invalid-identity-or-trust-evidence"},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
