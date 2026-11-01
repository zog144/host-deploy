"""Mandatory current graphical antirollback checkpoint, cross-owner source tests.

Synthetic independent issuer, NEVER a native installer, remote authority or key.
The real consumer uses fixed protected identity, independent signature and
fresh live challenges twice around signed Host export selection.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.host_deploy.gateway import graphics_external_checkpoint as external
from zog.host_deploy.gateway import graphics_chain_export as gateway
from zog.host_deploy.gateway import graphics_generation_chain as chain
from test_gateway_graphics_chain_export import setup

HOST_INSTALL_SOURCE = "adb0a15e3defd4e34b622a3867fe19d6afadeba7"


class IndependentIssuer:
    def __init__(self, current):
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.host_id = current["host_id"]
        self.installation_id = current["installation_id"]
        self.epoch = current["epoch"]
        self.sequence = 3
        self.pin_sha256 = hashlib.sha256(
            external._canonical(current)).hexdigest()
        self.approval_sha256 = "e"*64
        self.available = True
        self.first_response = None
        self.replay = False
        self.foreign_host = False
        self.signer = self.key
        self.reads = 0

    def remote(self, nonce, pin):
        if not self.available:
            raise external.CheckpointBlocked("service unavailable")
        self.reads += 1
        if self.replay and self.first_response is not None:
            return self.first_response
        value = {
            "schema": external.CHECKPOINT_SCHEMA,
            "host_id": self.host_id if not self.foreign_host else "foreign-host",
            "installation_id": self.installation_id,
            "epoch": self.epoch,
            "pin_sha256": self.pin_sha256,
            "approval_sha256": self.approval_sha256,
            "sequence": self.sequence,
            "nonce": nonce,
        }
        signature = self.signer.sign(external.DOMAIN + external._canonical(value))
        proof = external._canonical({
            **value, "signature_ed25519": base64.b64encode(signature).decode("ascii")
        })
        if self.first_response is None:
            self.first_response = proof
        return proof

    def installed(self):
        return {
            "schema": external.PIN_SCHEMA,
            "host_id": self.host_id,
            "installation_id": self.installation_id,
            "external_public_key": base64.b64encode(self.pub).decode("ascii"),
            "external_key_sha256": hashlib.sha256(self.pub).hexdigest(),
            "relay_uid": 23001,
        }, self.pub


def test_exact_host_install_checkpoint_signature_contract(monkeypatch):
    source = os.getenv("ZOG_HOST_INSTALL_CHECKPOINT_SOURCE")
    if not source: pytest.skip("pin exact host-install checkout for cross-repo proof")
    root = Path(source).resolve()
    assert subprocess.check_output(["git", "-C", str(root),
                                    "rev-parse", "HEAD"], text=True).strip() == HOST_INSTALL_SOURCE
    from zog.host_install import graphical_rotation_checkpoint as original
    from zog.host_install import graphical_current_authority as local
    current, _, _, _, _ = setup()
    issuer = IndependentIssuer(current)
    nonce = "a"*48
    raw = issuer.remote(nonce, issuer.installed()[0])
    installed, public_key = issuer.installed()
    assert external.checked_snapshot(
        raw, nonce=nonce, pin=installed, key=public_key, current=current)["epoch"] == current["epoch"]
    assert original.checked_snapshot(
        raw, nonce=nonce, host_id=current["host_id"],
        installation_id=current["installation_id"],
        independently_pinned_external_key=public_key,
        independently_expected_external_sha256=local._sha(public_key),
    )["pin_sha256"] == hashlib.sha256(external._canonical(current)).hexdigest()


def test_current_gateway_accepts_only_online_independent_highwater(
        monkeypatch, tmp_path):
    pin, payload, signed, catalogue, now = setup()
    issuer = IndependentIssuer(pin)
    monkeypatch.setattr(external, "_installed_pin", issuer.installed)
    monkeypatch.setattr(external, "_exchange", issuer.remote)
    monkeypatch.setattr(gateway, "_read_public_pin",
                        lambda path: pin if path == gateway.CURRENT_AUTHORITY_PATH
                        else pytest.fail("caller selected obsolete pin"))
    calls = []
    monkeypatch.setattr(gateway, "_query_live_owner",
                        lambda *a, **kw: calls.append("remote-host") or b"synthetic-live-ack")
    monkeypatch.setattr(gateway, "verify_live_ack",
                        lambda *a, **kw: calls.append("verified-live"))
    exports = tmp_path/"export"
    exports.mkdir()
    (exports/(chain.TASKS[0]+".json")).write_bytes(signed(payload))
    selected, digest = gateway.load_selected_step(
        exports, gateway.CURRENT_AUTHORITY_PATH,
        chain.TASKS[0], pin["chain_policy_sha256"])
    assert selected == catalogue and digest == payload["catalogue_sha256"]
    assert calls == ["remote-host", "verified-live"] and issuer.reads == 2

    # Local pin, local journal, export bytes, and Host signing remain coherent
    # after rollback, but the independent issuer has permanently advanced.
    issuer.epoch += 1
    issuer.pin_sha256 = "f"*64
    calls.clear()
    with pytest.raises(external.CheckpointBlocked):
        gateway.load_selected_step(
            exports, gateway.CURRENT_AUTHORITY_PATH,
            chain.TASKS[0], pin["chain_policy_sha256"])
    assert calls == []


@pytest.mark.parametrize("failure", (
    "offline", "replay", "wrong-signature", "foreign-host", "old-epoch",
))
def test_stale_or_unavailable_external_is_never_a_local_fallback(monkeypatch, failure):
    current, _, _, _, _ = setup()
    issuer = IndependentIssuer(current)
    monkeypatch.setattr(external, "_installed_pin", issuer.installed)
    monkeypatch.setattr(external, "_exchange", issuer.remote)
    if failure == "offline":
        issuer.available = False
    elif failure == "replay":
        issuer.replay = True
    elif failure == "wrong-signature":
        issuer.signer = Ed25519PrivateKey.generate()
    elif failure == "foreign-host":
        issuer.foreign_host = True
    else:
        issuer.epoch += 1
    if failure == "replay":
        assert external.require_current(current)["epoch"] == current["epoch"]
        with pytest.raises(external.CheckpointBlocked):
            external.require_current(current)
    else:
        with pytest.raises(external.CheckpointBlocked):
            external.require_current(current)


def test_external_service_identity_is_not_the_compiler_host_signer(monkeypatch):
    current, _, _, _, _ = setup()
    host_key = base64.b64decode(current["public_key"])
    issuer = IndependentIssuer(current)
    monkeypatch.setattr(external, "_installed_pin",
                        lambda: (issuer.installed()[0], host_key))
    monkeypatch.setattr(external, "_exchange",
                        lambda *a: pytest.fail("must fail before relay request"))
    with pytest.raises(external.CheckpointBlocked):
        external.require_current(current)


def test_gateway_rejects_checkpoint_callback_substitution_and_no_install(
        monkeypatch, tmp_path):
    current, _, _, _, _ = setup()
    exports = tmp_path/"cache"
    exports.mkdir()
    with pytest.raises(TypeError):
        gateway.load_selected_step(
            exports, gateway.CURRENT_AUTHORITY_PATH,
            chain.TASKS[0], current["chain_policy_sha256"],
            read_independent_checkpoint=lambda nonce: b"forged")
    monkeypatch.setattr(gateway, "_read_public_pin", lambda path: current)
    monkeypatch.setattr(external, "_installed_pin",
                        lambda: (_ for _ in ()).throw(
                            external.CheckpointBlocked("pin not installed")))
    with pytest.raises(external.CheckpointBlocked):
        gateway.load_selected_step(
            exports, gateway.CURRENT_AUTHORITY_PATH,
            chain.TASKS[0], current["chain_policy_sha256"])
