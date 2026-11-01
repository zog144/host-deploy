"""Root-only native-source fixtures, no real Host or accepted compilation."""
import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_deploy.gateway import graphics_chain_export as exports
from zog.host_deploy.gateway import graphics_gateway_history as history
from zog.host_deploy.gateway import graphics_generation_chain as chain
from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_canary_owner as canary
from zog.host_deploy.gateway import graphics_catalogue_owner as first
from test_gateway_graphics_generation_chain_native import protected_chain
from test_gateway_graphics_gateway_history import fixture as signed_history


@pytest.mark.skipif(os.geteuid() != 0, reason="ephemeral root test")
def test_root_export_reads_real_receipt_and_missing_epoch_holds(protected_chain, monkeypatch):
    policy, cat, receipt, files, store = protected_chain
    monkeypatch.setattr(chain, "_verified_native_owner", lambda p: p == policy)
    monkeypatch.setattr(owner, "_boot", lambda: "b"*32)
    now = datetime.now(timezone.utc)
    start = (now-timedelta(seconds=1)).isoformat()
    end = (now+timedelta(minutes=2)).isoformat()
    with pytest.raises(chain.ChainBlocked):
        exports.issue_native_step_export(task=chain.TASKS[0],
                                         published_at=start, expires_at=end)
    private = Ed25519PrivateKey.generate()
    key = private.private_bytes(serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    epoch = {"schema":"host-deploy-graphical-export-epoch-v1",
        "host_id":policy["host_id"],"installation_id":policy["installation_id"],
        "lane":policy["lane"],"lane_owner":policy["lane_owner"],
        "boot_id":"b"*32,"epoch":2,
        "chain_policy_sha256":chain._hash(policy),
        "source_revision":first.SOURCE,
        "monthly_pin_identity":policy["monthly_pin_identity"],
        "public_key_sha256":"sha256:"+hashlib.sha256(pub).hexdigest()}
    secret = {"schema":"host-deploy-graphical-export-private-key-v1",
        "private_key":base64.b64encode(key).decode("ascii")}
    for name, value in (("graphical-export-epoch-v1.json",epoch),
                        ("graphical-export-signing-key-v1.json",secret)):
        path = store/name
        path.write_bytes(chain._canonical(value))
        path.chmod(0o600)
    raw = exports.issue_native_step_export(
        task=chain.TASKS[0],published_at=start,expires_at=end)
    from test_gateway_graphics_chain_export import setup
    pin,_,_,_,_=setup()
    pin.update({"boot_id":"b"*32,"epoch":2,
                "public_key":base64.b64encode(pub).decode("ascii")})
    selected,digest=exports.verify(raw,pin,task=chain.TASKS[0],now=now)
    assert selected==cat and digest==chain._hash(cat)
    first.RECEIPT.write_bytes(b"tampered")
    with pytest.raises((ValueError,chain.ChainBlocked)):
        exports.issue_native_step_export(
            task=chain.TASKS[0],published_at=start,expires_at=end)


@pytest.mark.skipif(os.geteuid() != 0, reason="ephemeral root test")
def test_protected_stage_grant_never_repairs_partial_install(monkeypatch):
    root=Path(tempfile.mkdtemp(prefix="zog-history-stage-",dir="/root"))
    root.chmod(0o700)
    state=root/"history"
    state.mkdir(mode=0o700)
    (state/"grants").mkdir(mode=0o700)
    (state/"stage-once").mkdir(mode=0o700)
    policy,pin,request,dispatch,progress,grant,signed=signed_history()
    monkeypatch.setattr(history,"_pin",lambda p:pin)
    @contextmanager
    def locked(_owner):
        yield
    monkeypatch.setattr(canary,"locked",locked)
    try:
        digest=history.install_history_grant(
            state,policy,signed(),grant["request_id"],
            request,dispatch,progress)
        assert digest==history._hash(signed())
        stage=state/"stage-once"/(grant["lane"]+"--"+grant["task"]+".json")
        receipt=state/"grants"/(grant["request_id"]+".json")
        assert stage.exists() and receipt.exists()
        with pytest.raises(history.HistoryAuthorityBlocked):
            history.install_history_grant(
                state,policy,signed(),grant["request_id"],
                request,dispatch,progress)
        receipt.unlink()
        with pytest.raises(history.HistoryAuthorityBlocked):
            history.install_history_grant(
                state,policy,signed(),grant["request_id"],
                request,dispatch,progress)
        assert stage.exists() and not receipt.exists()
    finally:
        shutil.rmtree(root)
