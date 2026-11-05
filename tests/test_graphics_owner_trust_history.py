"""Source-only pinned trust broker and read-only current S3 witness tests."""
import base64
import hashlib
import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from zog.host_deploy.gateway import graphics_owner_trust_history as broker
from zog.host_deploy.gateway import graphics_owner_observation_v2 as v2
from zog.host_deploy.gateway import graphics_owner_ipc as ipc

def fixture():
    signer=Ed25519PrivateKey.generate()
    observer=Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)
    public=signer.public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)
    pin={"schema":"zog-graphical-task-c-gateway-trust-pin-v1",
         "broker_public_key":public.hex(),
         "owner_observation_public_key":observer.hex(),
         "original_checkpoint_sha256":"sha256:"+"d"*64,
         "installed_owner_source":"5ad7d5ed72d1b72edc767a658de28506791a74d4",
         "installed_broker_source":"a"*64,
         "installation_id":"b"*64,"state_volume_id":"c"*64,
         "scope_sha256":"sha256:"+"e"*64}
    pin_sha="sha256:"+hashlib.sha256(broker.canonical(pin)).hexdigest()
    original={"request_id":"1"*32,"original_request_sha256":"2"*64,
              "origin_repository":"zog144/host-deploy",
              "origin_issue_number":17,"origin_trigger_actor":"zog144",
              "operation_id":"3"*32,"stage":"submit","ordinal":0,
              "binding_sha256":"4"*64,"remote_request_sha256":"5"*64}
    trust={"public_key":observer.hex(),
           "public_key_sha256":"sha256:"+hashlib.sha256(observer).hexdigest(),
           "owner_request_sha256":"sha256:"+"6"*64,
           "scope_sha256":pin["scope_sha256"],"host_id":"7"*64,
           "installation_id":pin["installation_id"],
           "state_volume_id":pin["state_volume_id"],
           "authority_epoch":5}
    history={"sequence":2,"history_sha256":"sha256:"+"8"*64,"revoked":False}
    body={"schema":broker.SCHEMA,"nonce":"9"*48,
          "action":"observe-original","original":original,
          "selected_trust":trust,"current_history":history,"pin_sha256":pin_sha}
    return signer,pin,pin_sha,body

def signed(key,body):
    data=broker.canonical(body)
    sig=key.sign(broker.DOMAIN+data)
    return broker.canonical({**body,"signature_ed25519":
                             base64.b64encode(sig).decode("ascii")})

def verify(key,pin,pin_sha,body):
    return broker.verify_broker_reply(
        signed(key,body),nonce="9"*48,action="observe-original",
        original=body["original"],pin=pin,pin_sha256=pin_sha)

def test_valid_pinned_signed_history_and_trust():
    key,pin,sha,body=fixture()
    selected=verify(key,pin,sha,body)
    assert selected.trust.state_volume_id==pin["state_volume_id"]
    assert selected.current_history["sequence"]==2

@pytest.mark.parametrize("change",[
    lambda b:b.update(nonce="0"*48),
    lambda b:b.update(action="submit-original"),
    lambda b:b["original"].update(operation_id="0"*32),
    lambda b:b["selected_trust"].update(scope_sha256="sha256:"+"0"*64),
    lambda b:b["selected_trust"].update(public_key="0"*64),
    lambda b:b["selected_trust"].update(installation_id="0"*64),
    lambda b:b["selected_trust"].update(authority_epoch=0),
    lambda b:b["current_history"].update(revoked=True),
    lambda b:b["current_history"].update(sequence=0),
    lambda b:b["current_history"].update(history_sha256="invalid"),
    lambda b:b.update(pin_sha256="sha256:"+"0"*64),
])
def test_changed_signed_trust_identity_or_nonce_denied(change):
    key,pin,sha,body=fixture()
    original=json.loads(json.dumps(body["original"]))
    change(body)
    with pytest.raises(broker.TrustUnavailable):
        broker.verify_broker_reply(
            signed(key,body),nonce="9"*48,action="observe-original",
            original=original,pin=pin,pin_sha256=sha)

def test_wrong_broker_signer_and_duplicate_fields_denied():
    key,pin,sha,body=fixture()
    other=Ed25519PrivateKey.generate()
    with pytest.raises(broker.TrustUnavailable):
        broker.verify_broker_reply(
            signed(other,body),nonce="9"*48,action="observe-original",
            original=body["original"],pin=pin,pin_sha256=sha)
    raw=signed(key,body)
    with pytest.raises(broker.TrustUnavailable):
        broker.verify_broker_reply(
            raw[:-1]+b',"action":"observe-original"}',
            nonce="9"*48,action="observe-original",
            original=body["original"],pin=pin,pin_sha256=sha)

def test_no_native_pinned_issuer_or_checkpoint_defaults_to_hold():
    key,pin,sha,body=fixture()
    assert broker.APPROVED_PIN_SHA256 is None
    with pytest.raises(broker.TrustUnavailable):
        broker.selected_pin()
    with pytest.raises(broker.TrustUnavailable):
        broker.select_original(body["original"],action="observe-original")
    with pytest.raises(ipc.OwnerUnavailable):
        ipc._current_external_history(None)

def test_trust_provider_returns_only_signed_selection_not_credentials(monkeypatch):
    key,pin,sha,body=fixture()
    selected=verify(key,pin,sha,body)
    monkeypatch.setattr(broker,"select_original",lambda original,action:selected)
    looked=ipc._trusted_selection_for_original(
        body["original"],action="observe-original")
    assert looked==selected
    assert ipc._current_external_history(looked)==selected.current_history
    assert "credential" not in str(selected).lower()
    assert "role_arn" not in str(selected).lower()

def test_source_has_no_sending_or_checkpoint_write_or_role_discovery():
    source=(Path(__file__).resolve().parents[1]/
        "src/zog/host_deploy/gateway/graphics_owner_trust_history.py").read_text()
    producer=(Path(__file__).resolve().parents[1]/
        "src/zog/host_deploy/gateway/graphics_owner_trust_service.py").read_text()
    for forbidden in ("send_command(", "put_object(", "delete_object(",
                      "assume_role(", "boto3.Session(", "os.environ.get("):
        assert forbidden not in source+producer
    assert "checkpoint.current_witness(scope)" in producer
    assert "origin.verify_installed_evidence(" in producer
    assert "registry.select(parsed)" in producer
