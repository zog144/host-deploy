"""Signed cross-Host graphical export checks; no running Host or private STATE."""
import base64
from datetime import datetime, timedelta, timezone
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_deploy.gateway import graphics_chain_export as export
from zog.host_deploy.gateway import graphics_generation_chain as chain
from test_gateway_graphics_generation_chain import scenario


def setup():
    policy, cat, receipt = scenario()
    private = Ed25519PrivateKey.generate()
    pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pin = {
        "schema": export.PIN, "host_id": policy["host_id"],
        "installation_id": policy["installation_id"],
        "lane": policy["lane"], "lane_owner": policy["lane_owner"],
        "boot_id": "b" * 32, "epoch": 7,
        "chain_policy_sha256": chain._hash(policy),
        "original_catalogue_sha256": chain._hash(cat),
        "first_base_generation_id": policy["first_base_generation_id"],
        "first_receipt_sha256": chain._hash(receipt),
        "relay_uid": 23001,
        "public_key": base64.b64encode(pub).decode("ascii"),
        "source_revision": cat["tasks"][chain.TASKS[0]]["source_revision"],
        "monthly_pin_identity": cat["tasks"][chain.TASKS[0]]["monthly_pin_identity"],
    }
    now = datetime.now(timezone.utc)
    payload = {
        "schema": export.CONTRACT, "task": chain.TASKS[0],
        "host_id": pin["host_id"], "installation_id": pin["installation_id"],
        "lane": pin["lane"], "lane_owner": pin["lane_owner"],
        "boot_id": pin["boot_id"], "epoch": pin["epoch"],
        "chain_policy_sha256": pin["chain_policy_sha256"],
        "catalogue": cat, "catalogue_sha256": chain._hash(cat),
        "receipt": receipt, "receipt_sha256": chain._hash(receipt),
        "published_at": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    def signed(value, signing_key=private):
        return export._canonical({
            "payload": value,
            "signature": base64.b64encode(
                signing_key.sign(export._canonical(value))).decode("ascii"),
        })
    return pin, payload, signed, cat, now


def test_valid_nonroot_gateway_uses_only_signed_host_catalogue():
    pin, payload, signed, cat, now = setup()
    answer, digest = export.verify(signed(payload), pin, task=chain.TASKS[0], now=now)
    assert answer == cat and digest == payload["catalogue_sha256"]


@pytest.mark.parametrize("field,value", [
    ("host_id", "foreign"),
    ("installation_id", "foreign-installation"),
    ("lane", "foreign-lane"),
    ("boot_id", "0"*32),
    ("epoch", 8),
    ("chain_policy_sha256", "sha256:"+"0"*64),
    ("catalogue_sha256", "sha256:"+"0"*64),
    ("receipt_sha256", "not-a-receipt"),
    ("task", "graphics-x11-core-image-v1"),
    ("published_at", "2020-01-01T00:00:00+00:00"),
    ("expires_at", "2090-01-01T00:00:00+00:00"),
])
def test_signed_but_foreign_or_stale_record_denied(field, value):
    pin, payload, signed, cat, now = setup()
    with pytest.raises(export.GraphicalExportBlocked):
        export.verify(signed({**payload, field: value}), pin,
                      task=chain.TASKS[0], now=now)


def test_wrong_signer_and_unsigned_transport_rejected():
    pin, payload, signed, cat, now = setup()
    wrong = Ed25519PrivateKey.generate()
    for data in (signed(payload, wrong), export._canonical({"payload": payload}),
                 signed({**payload, "catalogue": {**cat, "schema": 0}})):
        with pytest.raises(export.GraphicalExportBlocked):
            export.verify(data, pin, task=chain.TASKS[0], now=now)


def test_pin_revocation_reboot_and_owner_epoch_deny_old_export():
    pin, payload, signed, cat, now = setup()
    for change in ({"epoch": pin["epoch"] + 1},
                   {"boot_id": "0" * 32},
                   {"chain_policy_sha256": "sha256:"+"0"*64},
                   {"source_revision": "f"*40},
                   {"first_base_generation_id": "0"*64}):
        with pytest.raises(export.GraphicalExportBlocked):
            export.verify(signed(payload), {**pin, **change},
                          task=chain.TASKS[0], now=now)


def test_duplicate_json_and_wrong_task_never_promote():
    pin, payload, signed, cat, now = setup()
    raw = signed(payload)
    duplicate = b'{"payload":{}, "payload":{}, "signature":"x"}'
    for data in (duplicate, raw + b"garbage", raw * 500):
        with pytest.raises(export.GraphicalExportBlocked):
            export.verify(data, pin, task=chain.TASKS[0], now=now)
    with pytest.raises(export.GraphicalExportBlocked):
        export.verify(raw, pin, task=chain.TASKS[1], now=now)


def test_gateway_unit_is_unprivileged_and_keeps_private_state_out():
    from pathlib import Path
    source = Path(__file__).resolve().parents[1] / "src/zog/host_deploy/gateway"
    unit = (source / "host-deploy-gateway.service").read_text()
    assert "DynamicUser=yes" in unit
    assert "ProtectSystem=strict" in unit
    import inspect
    from zog.host_deploy.gateway import consumer
    body = inspect.getsource(consumer.GatewayConsumer._advance_one_reviewed)
    assert "load_selected_step" in body
    assert "load_installed_step" not in body


def test_signed_cross_host_xcb_x11_exports_bind_original_toolchain_and_accepted_layers():
    """The nonroot view must retain the original toolchain, not recast images."""
    from test_gateway_graphics_generation_chain import evidence, FONTS, XCB
    policy, fonts, receipt = scenario()
    pin, payload, signed, _, now = setup()
    xcb = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[0],
        previous_catalogue=fonts, previous_receipt=receipt,
        accepted_generation=evidence(policy, chain.TASKS[0], fonts, FONTS),
    )
    x11 = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[1],
        previous_catalogue=xcb["catalogue"], previous_receipt=xcb["receipt"],
        accepted_generation=evidence(
            policy, chain.TASKS[1], xcb["catalogue"], XCB, request_id="6"*32),
    )
    for task, candidate, layer in (
        (chain.TASKS[1], xcb, FONTS),
        (chain.TASKS[2], x11, XCB),
    ):
        envelope = dict(
            payload, task=task, catalogue=candidate["catalogue"],
            catalogue_sha256=candidate["catalogue_sha256"],
            receipt=candidate["receipt"],
            receipt_sha256=chain._hash(candidate["receipt"]),
        )
        verified, digest = export.verify(signed(envelope), pin, task=task, now=now)
        assert digest == candidate["catalogue_sha256"]
        args = verified["tasks"][task]["arguments"]
        assert args["selection"] == policy["first_base_generation_id"]
        assert args["graphical_predecessor"] == layer
        # Even an authentic signature from this signer cannot change the
        # independently installed original-toolchain public pin.
        forged_cat = json.loads(json.dumps(candidate["catalogue"]))
        forged_cat["tasks"][task]["arguments"]["selection"] = "f"*64
        forged = dict(
            envelope, catalogue=forged_cat,
            catalogue_sha256=chain._hash(forged_cat),
        )
        with pytest.raises(export.GraphicalExportBlocked):
            export.verify(signed(forged), pin, task=task, now=now)



def test_signed_export_refuses_receipt_substitution_and_public_arbitrary_signer():
    pin, payload, sign, cat, now = setup()
    with pytest.raises(export.GraphicalExportBlocked):
        export.verify(sign({**payload, "receipt_sha256": "sha256:"+"0"*64}),
                      pin, task=chain.TASKS[0], now=now)
    changed = json.loads(json.dumps(payload["receipt"]))
    changed["accepted_base_generation_id"] = "f"*64
    with pytest.raises(export.GraphicalExportBlocked):
        export.verify(sign({**payload, "receipt": changed,
                            "receipt_sha256": chain._hash(changed)}),
                      pin, task=chain.TASKS[0], now=now)
    with pytest.raises(export.GraphicalExportBlocked):
        export.sign_host_export(payload, b"\0"*32)


def test_online_host_nonce_blocks_cached_reboot_and_revocation():
    pin, payload, signed, cat, now = setup()
    nonce = "a"*64
    digest = "sha256:"+"b"*64
    observed = now - timedelta(seconds=1)
    proof = {
        "schema": "host-deploy-graphical-live-epoch-v1",
        "nonce": nonce, "export_sha256": digest, "task": chain.TASKS[0],
        "host_id": pin["host_id"], "installation_id": pin["installation_id"],
        "lane": pin["lane"], "lane_owner": pin["lane_owner"],
        "boot_id": pin["boot_id"], "epoch": pin["epoch"],
        "chain_policy_sha256": pin["chain_policy_sha256"],
        "sequence": 1, "observed_at": observed.isoformat(),
        "expires_at": (now+timedelta(seconds=2)).isoformat(),
    }
    assert export.verify_live_ack(
        signed(proof), pin, nonce=nonce, export_digest=digest,
        task=chain.TASKS[0], now=now)["sequence"] == 1
    for mismatch in (
        ({"nonce": "0"*64}, pin, nonce),
        ({"boot_id": "0"*32}, pin, nonce),
        ({"epoch": 8}, pin, nonce),
        ({"export_sha256": "sha256:"+"0"*64}, pin, nonce),
        ({"expires_at": (now+timedelta(seconds=30)).isoformat()}, pin, nonce),
        ({"sequence": 0}, pin, nonce),
        ({}, {**pin, "epoch": 8}, nonce),
        ({}, pin, "f"*64),
    ):
        change, selected_pin, selected_nonce = mismatch
        with pytest.raises(export.GraphicalExportBlocked):
            export.verify_live_ack(signed({**proof, **change}), selected_pin,
                nonce=selected_nonce, export_digest=digest,
                task=chain.TASKS[0], now=now)


def test_receiver_fails_closed_without_fresh_live_host(monkeypatch, tmp_path):
    pin, payload, signed, cat, now = setup()
    from zog.host_deploy.gateway import graphics_chain_export as selected
    exports = tmp_path / "exports"
    exports.mkdir()
    (exports / (chain.TASKS[0]+".json")).write_bytes(signed(payload))
    monkeypatch.setattr(selected, "_read_public_pin", lambda path: pin)
    monkeypatch.setattr(selected, "_query_live_owner", lambda *a, **k:
        (_ for _ in ()).throw(export.GraphicalExportBlocked("relay offline")))
    with pytest.raises(export.GraphicalExportBlocked, match="relay offline"):
        selected.load_selected_step(exports, "/etc/zog/owner-pin", chain.TASKS[0],
                                    pin["chain_policy_sha256"])
