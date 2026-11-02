"""Gateway history must be independently signed, not just copied root-owned."""
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_deploy.gateway import graphics_gateway_history as history
from test_gateway_graphics_generation_attester import (
    policy, binding, REQUEST, PIPELINE, HOST, LANE)
from zog.host_deploy.gateway import graphics_generation_chain as chain
from zog.host_deploy.gateway import graphics_catalogue_owner as first


def fixture():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p = policy()
    pin = {
        "schema": history.PIN,
        "host_id": HOST, "installation_id": p["installation_id"],
        "lane": LANE, "boot_id": "b"*32, "epoch": 3,
        "source_revision": first.SOURCE,
        "monthly_pin_identity": p["monthly_pin_identity"],
        "chain_policy_sha256": chain._hash(p),
        "public_key": base64.b64encode(public).decode("ascii"),
        "revoked": False,
    }
    request = {
        "request": {
            "request_id": REQUEST, "operation": "build.submit",
            "parameters": {"task": chain.TASKS[0], "lane": LANE},
            "source": {"repository": first.REPOSITORY, "commit": first.SOURCE},
        },
        "states": {"admission": "admitted"},
    }
    dispatch = {"phase": "prepared", "binding": binding()}
    progress = {"phase": "completed", "pipeline_id": PIPELINE,
                "stages": [{"phase": "completed"}]}
    grant = {
        "schema": history.SCHEMA,
        "request_id": REQUEST,
        "request_sha256": history._hash(request),
        "dispatch_sha256": history._hash(dispatch),
        "progress_sha256": history._hash(progress),
        "pipeline_id": PIPELINE, "task": chain.TASKS[0],
        "host_id": HOST, "installation_id": p["installation_id"],
        "lane": LANE, "boot_id": pin["boot_id"], "epoch": pin["epoch"],
        "source_revision": first.SOURCE,
        "monthly_pin_identity": p["monthly_pin_identity"],
        "chain_policy_sha256": pin["chain_policy_sha256"], "sequence": 1,
    }
    def signed(value=grant, signer=private):
        return {"payload": value,
                "signature": base64.b64encode(signer.sign(
                    history._canonical(value))).decode("ascii")}
    return p, pin, request, dispatch, progress, grant, signed


def test_original_gateway_request_and_dispatch_signed():
    p, pin, request, dispatch, progress, grant, signed = fixture()
    assert history._verify(signed(), pin, p, REQUEST, request, dispatch,
                           progress) == grant
    with pytest.raises(history.HistoryAuthorityBlocked):
        history._verify(signed(), pin, p, REQUEST,
                        {**request, "states": {"admission": "revoked"}},
                        dispatch, progress)
    with pytest.raises(history.HistoryAuthorityBlocked):
        history._verify(signed(), pin, p, REQUEST, request,
                        {**dispatch, "phase": "replaced"}, progress)
    with pytest.raises(history.HistoryAuthorityBlocked):
        history._verify(signed(), pin, p, REQUEST, request, dispatch,
                        {**progress, "phase": "uncertain"})


def test_wrong_issuer_foreign_boot_and_history_replay_denied():
    p, pin, request, dispatch, progress, grant, signed = fixture()
    wrong = Ed25519PrivateKey.generate()
    for envelope, selected_pin in (
        (signed(signer=wrong), pin),
        (signed({**grant, "request_id": "0"*32}), pin),
        (signed({**grant, "epoch": 4}), pin),
        (signed({**grant, "boot_id": "0"*32}), pin),
        (signed({**grant, "sequence": 0}), pin),
        (signed(), {**pin, "epoch": 4}),
        (signed(), {**pin, "boot_id": "0"*32}),
    ):
        with pytest.raises(history.HistoryAuthorityBlocked):
            history._verify(envelope, selected_pin, p, REQUEST,
                            request, dispatch, progress)


def test_absent_host_history_key_is_not_native_authority(monkeypatch):
    from zog.host_deploy.gateway import graphics_gateway_history
    monkeypatch.setattr(graphics_gateway_history.chain, "_read_locked",
                        lambda path: (_ for _ in ()).throw(
                            chain.ChainBlocked("missing protected pin")))
    with pytest.raises(chain.ChainBlocked):
        graphics_gateway_history._pin(policy())
