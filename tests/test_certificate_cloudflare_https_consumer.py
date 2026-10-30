"""Source-only HTTPS Cloudflare consumer. No DNS, ACME, real token, network."""
import copy
import os
import time

import pytest

from zog.host_deploy.certificate_cloudflare_https_consumer import (
    CloudflareDeliveryBlocked, prepare, check_receipt, deliver_selected,
    _hash, PURPOSE, SCHEMA, REPLY_SCHEMA,
)
from test_certificate_cross_host_admission import sample, NOW


def inputs():
    case = sample()
    issuer = case["ledger"]["issuer"]
    installed = {k: issuer[k] for k in (
        "grant_id", "storage_id", "uid", "gid", "software_view",
        "certificate_data_path", "controller_record_sha256")}
    for key in ("host_id", "installation_id", "state_volume_id", "registry_id"):
        installed[key] = case["binding"][key]
    client = case["client"]
    return {k: case[k] for k in (
        "owner", "binding", "ledger", "delivery", "authorization",
        "projection", "client", "owner_bytes", "signer_pin_bytes")}, installed


def make_request():
    case, installed = inputs()
    return prepare(**case, now=NOW, request_id="a"*32,
                   installed_issuer=installed)


def reply(req):
    return {
        "schema": REPLY_SCHEMA, "status": "authorized-delivery",
        "purpose": PURPOSE, "request_id": req["request_id"],
        "request_sha256": _hash(req), "expires_at": req["expires_at"],
        **{k: req[k] for k in (
            "host_id", "installation_id", "state_volume_id",
            "registry_id", "assignment_id", "assignment_revision",
            "credential_id", "credential_revision",
            "issuer_grant_id", "issuer_storage_id", "issuer_uid")},
    }


def test_selected_issuer_credential_request_is_nonsecret_and_exact():
    req = make_request()
    assert req["schema"] == SCHEMA
    assert req["purpose"] == "issuer-cloudflare-dns01"
    assert req["transport_origin"] == "https://station.example.org"
    assert req["fqdn"] == "issuer.example.org"
    assert req["dns_zone"] == "example.org"
    assert req["credential_revision"] == 5
    assert req["issuer_uid"] == 28001
    assert req["nginx_delivery_policy_sha256"] == _hash(inputs()[0]["delivery"])
    assert "ssh" not in str(req).lower()
    assert "token" not in str(req).lower()
    assert not any("password" in key for key in req)
    assert check_receipt(req, reply(req), now=NOW)["credential_installed"] is False


@pytest.mark.parametrize("which,key,value", [
    ("case.owner", "dns_zone", "elsewhere.org"),
    ("case.owner", "hostnames", ["elsewhere.example.org"]),
    ("case.owner", "credential_revision", 6),
    ("case.authorization", "state", "revoked"),
    ("case.authorization", "assignment_revision", 999),
    ("case.client", "https_origin", "http://station.example.org"),
    ("case.client", "https_origin", "https://station.example.org:8443"),
    ("case.client", "purpose", "station-admin-password"),
    ("case.client", "tls_authority_pin_sha256", "bad"),
    ("installed", "uid", 0),
    ("installed", "storage_id", "f"*32),
])
def test_authority_or_installed_issuer_drift_never_requests_secret(
        which, key, value):
    case, installed = inputs()
    if which == "installed":
        installed[key] = value
    else:
        case[which.split(".")[1]][key] = value
    with pytest.raises(CloudflareDeliveryBlocked) as exc:
        prepare(**case, now=NOW, request_id="a"*32, installed_issuer=installed)
    assert str(exc.value) == "cloudflare-https-delivery-not-authorized"


@pytest.mark.parametrize("key,value", [
    ("request_id", "b"*32),
    ("credential_revision", 6),
    ("issuer_grant_id", "f"*32),
    ("request_sha256", "0"*64),
    ("purpose", "admin-password"),
    ("status", "pending"),
    ("expires_at", NOW),
])
def test_authenticated_metadata_replay_or_substitution_rejected(key, value):
    req = make_request()
    resp = reply(req)
    resp[key] = value
    with pytest.raises(CloudflareDeliveryBlocked):
        check_receipt(req, resp, now=NOW)


def test_bad_nonce_expiring_assignment_unknown_fields_rejected():
    case, installed = inputs()
    for nonce in ("", "A"*32, "a"*31):
        with pytest.raises(CloudflareDeliveryBlocked):
            prepare(**case, now=NOW, request_id=nonce,
                    installed_issuer=installed)
    case["owner"]["expires_at"] = NOW + 10
    with pytest.raises(CloudflareDeliveryBlocked):
        prepare(**case, now=NOW, request_id="a"*32,
                installed_issuer=installed)


def test_no_network_on_failed_preflight(monkeypatch):
    case, installed = inputs()
    case["owner"]["status"] = "revoked"
    class NoNetwork:
        def request_fd(self, *args):
            pytest.fail("failed authority must not contact station")
    class NoJournal:
        def claim_once(self, request):
            pytest.fail("failed authority must not create request")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(CloudflareDeliveryBlocked):
        deliver_selected(snapshots=case, request_id="a"*32,
                         installed_issuer=installed, channel=NoNetwork(),
                         journal=NoJournal(), install_from_fd=lambda *a,**kw: None,
                         reread=lambda: case, reread_issuer=lambda: installed, now=NOW)


def test_retired_draft_wire_cannot_claim_request_or_communicate(monkeypatch):
    case, installed = inputs()
    events = []
    class Journal:
        def claim_once(self, request):
            events.append("claim")
    class Transport:
        def request_fd(self, origin, pin, request):
            events.append("network")
            raise AssertionError("legacy transport must be disabled")
    def installer(*args, **kwargs):
        events.append("installer")
        raise AssertionError("legacy installer must be disabled")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(CloudflareDeliveryBlocked):
        deliver_selected(
            snapshots=case, request_id="a"*32, installed_issuer=installed,
            channel=Transport(), journal=Journal(), install_from_fd=installer,
            reread=lambda: copy.deepcopy(case),
            reread_issuer=lambda: copy.deepcopy(installed), now=NOW)
    assert events == []
