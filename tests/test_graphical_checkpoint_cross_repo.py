"""Exact cross-repository issuer -> host-install -> gateway source protocol.

All files and key material are synthetic. Never touches installed /etc, STATE,
an actual Host or a real external service.
"""
import base64
import os
from pathlib import Path
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.root_control.graphical_monotonic_issuer import Issuer
from zog.host_install import graphical_current_authority as local
from zog.host_install import graphical_rotation_checkpoint as rotation
from zog.host_deploy.gateway import graphics_external_checkpoint as gateway
from zog.host_deploy.gateway import graphics_chain_export as export


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def pin(key, epoch):
    return {"schema":local.PIN_SCHEMA,"host_id":"host-approved",
        "installation_id":"installation-approved","lane":"compiler",
        "lane_owner":"image-build","boot_id":"a"*32,
        "chain_policy_sha256":"sha256:"+"a"*64,
        "original_catalogue_sha256":"sha256:"+"b"*64,
        "public_key":base64.b64encode(pub(key)).decode(),"epoch":epoch,
        "source_revision":"c"*40,"monthly_pin_identity":"d"*64,
        "first_base_generation_id":"e"*64,
        "first_receipt_sha256":"sha256:"+"f"*64,"relay_uid":23001}

def approval(operator,p,previous):
    values={"schema":local.APPROVAL_SCHEMA,
        "host_id":p["host_id"],"installation_id":p["installation_id"],
        "previous_pin_sha256":None if previous is None else local._sha(local.canonical(previous)),
        "new_pin_sha256":local._sha(local.canonical(p)),
        "new_epoch":p["epoch"],"approval_id":"independent-approval",
        "authorization_revision":p["epoch"]}
    proof=operator.sign(b"zog-graphical-current-authority-rotation-v1\x00"+
                       local.canonical(values))
    return local.canonical({**values,"operator_signature":
                            base64.b64encode(proof).decode()})

@pytest.fixture
def model(tmp_path,monkeypatch):
    root=tmp_path/"external-storage"
    pubdir=tmp_path/"local-public"
    privdir=tmp_path/"local-private"
    for d,mode in ((root,0o700),(pubdir,0o755),(privdir,0o700)):
        d.mkdir(mode=mode)
        os.chmod(d,mode)
    fds=[os.open(d,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
         for d in (root,pubdir,privdir)]
    issuer=Issuer(fds[0],signer=Ed25519PrivateKey.generate())
    operator=Ed25519PrivateKey.generate()
    owners=[Ed25519PrivateKey.generate() for _ in range(2)]
    anchor={"schema":gateway.PIN_SCHEMA,"host_id":"host-approved",
            "installation_id":"installation-approved",
            "external_public_key":base64.b64encode(issuer.public_key).decode(),
            "external_key_sha256":issuer.public_sha256,"relay_uid":23009}
    monkeypatch.setattr(gateway,"_installed_pin",
                        lambda:(anchor,issuer.public_key))
    def transport(nonce,anchor):
        return issuer.read_signed(host_id=anchor["host_id"],
                                  installation_id=anchor["installation_id"],
                                  nonce=nonce)
    monkeypatch.setattr(gateway,"_exchange",transport)
    def rotate(epoch,checkpoint=None):
        current=pin(owners[epoch-1],epoch)
        old=pin(owners[epoch-2],epoch-1) if epoch>1 else None
        record=approval(operator,current,old)
        def cas(**kwargs):
            issuer.compare_and_advance(operation_id="operator-"+str(epoch),**kwargs)
        return rotation.rotate_checked_source(
            public_fd=fds[1],private_fd=fds[2],
            approved_pin_bytes=local.canonical(current),approval_bytes=record,
            independently_pinned_operator_public_key=pub(operator),
            independently_expected_operator_sha256=local._sha(pub(operator)),
            independently_pinned_external_public_key=issuer.public_key,
            independently_expected_external_sha256=issuer.public_sha256,
            read_independent_checkpoint=lambda nonce:issuer.read_signed(
                host_id="host-approved",installation_id="installation-approved",
                nonce=nonce),
            compare_and_advance_independent_checkpoint=cas,
            uid=os.getuid(),checkpoint=checkpoint)
    yield rotate,pin,owners,issuer,pubdir,privdir,fds
    for fd in fds:os.close(fd)


def test_exact_root_issuer_host_installer_and_gateway(model):
    rotate,build,owners,issuer,pubdir,privdir,_=model
    rotate(1)
    assert gateway.require_current(build(owners[0],1))["epoch"]==1
    old_pub=(pubdir/local.PUBLIC_NAME).read_bytes()
    old_private=(privdir/local.PRIVATE_JOURNAL).read_bytes()
    rotate(2)
    assert gateway.require_current(build(owners[1],2))["epoch"]==2
    # Coherent rollback of local public/private files is NOT authority.
    (pubdir/local.PUBLIC_NAME).write_bytes(old_pub)
    (pubdir/local.PUBLIC_NAME).chmod(0o444)
    (privdir/local.PRIVATE_JOURNAL).write_bytes(old_private)
    (privdir/local.PRIVATE_JOURNAL).chmod(0o600)
    with pytest.raises(gateway.CheckpointBlocked):
        gateway.require_current(build(owners[0],1))


def test_gateway_requires_external_before_cache_or_live_host(model,tmp_path,monkeypatch):
    rotate,build,owners,issuer,public,private,_=model
    rotate(1)
    old=build(owners[0],1)
    rotate(2)
    called=[]
    monkeypatch.setattr(export,"_read_public_pin",lambda path: old)
    monkeypatch.setattr(export,"_query_live_owner",lambda *a,**k:called.append(1))
    with pytest.raises(gateway.CheckpointBlocked):
        export.load_selected_step(tmp_path/"missing-export",
                                  export.CURRENT_AUTHORITY_PATH,
                                  export.TASKS[0],old["chain_policy_sha256"])
    assert called==[]


def test_stale_nonce_substituted_key_and_external_outage(model,monkeypatch):
    rotate,build,owners,issuer,*_=model
    rotate(1)
    active=build(owners[0],1)
    original=gateway._exchange
    cached=issuer.read_signed(host_id=active["host_id"],
        installation_id=active["installation_id"],nonce="f"*48)
    monkeypatch.setattr(gateway,"_exchange",lambda nonce,pin:cached)
    with pytest.raises(gateway.CheckpointBlocked):
        gateway.require_current(active)
    monkeypatch.setattr(gateway,"_exchange",lambda nonce,pin:
                        (_ for _ in ()).throw(OSError("disconnected")))
    with pytest.raises(OSError):
        gateway.require_current(active)
    monkeypatch.setattr(gateway,"_exchange",original)
    fake=Ed25519PrivateKey.generate()
    monkeypatch.setattr(gateway,"_installed_pin",lambda:(
        {"schema":gateway.PIN_SCHEMA,"host_id":active["host_id"],
         "installation_id":active["installation_id"],
         "external_public_key":base64.b64encode(pub(fake)).decode(),
         "external_key_sha256":hashlib.sha256(pub(fake)).hexdigest(),
         "relay_uid":23009},pub(fake)))
    with pytest.raises(gateway.CheckpointBlocked):
        gateway.require_current(active)
    with pytest.raises(TypeError):
        gateway.require_current(active,read_callback=lambda *_:True)
