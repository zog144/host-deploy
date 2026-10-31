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
    policy, cat, _ = scenario()
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
        "public_key": base64.b64encode(pub).decode("ascii"),
    }
    now = datetime.now(timezone.utc)
    payload = {
        "schema": export.CONTRACT, "task": chain.TASKS[0],
        "host_id": pin["host_id"], "installation_id": pin["installation_id"],
        "lane": pin["lane"], "lane_owner": pin["lane_owner"],
        "boot_id": pin["boot_id"], "epoch": pin["epoch"],
        "chain_policy_sha256": pin["chain_policy_sha256"],
        "catalogue": cat, "catalogue_sha256": chain._hash(cat),
        "receipt_sha256": "sha256:" + "a" * 64,
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
                   {"chain_policy_sha256": "sha256:"+"0"*64}):
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
