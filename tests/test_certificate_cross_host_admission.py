"""No token or root mutation: exact HTTPS issuer owner provenance tests."""
import copy
import hashlib
import json
import time
import uuid

import pytest
from zog.host_deploy.certificate_cross_host_admission import (
    CredentialAdmissionBlocked, validate, _hash,
)

NOW = 1790000000


def uuidn(n):
    return str(uuid.UUID("00000000-0000-4000-8000-" + format(n, "012x")))


def sample():
    credential_uuid = uuidn(10)
    owner = dict(
        schema="zog-host-deploy-certificate-owner-authority-v1",
        origin="managed", verified_by="signed-host-discover",
        host_id=uuidn(1), installation_id=uuidn(2),
        operation_id=uuidn(3), revision=4, status="approved",
        approved_at=NOW-100, expires_at=NOW+3600, revoked_at=None,
        certificate_id="station-web", service_id="candidate-nginx",
        hostnames=["issuer.example.org"], policy_sha256="a"*64,
        challenge="dns-01", dns_mode="local-cloudflare",
        dns_zone="example.org", credential_id="cloudflare-"+credential_uuid.replace("-", ""),
        credential_revision=5,
    )
    binding = dict(owner)
    for key in ("schema", "origin", "verified_by", "operation_id", "revision",
                "status", "approved_at", "expires_at", "revoked_at"):
        binding.pop(key)
    binding.update(schema="zog-host-deploy-managed-certificate-consumer-binding-v1",
                   state_volume_id=uuidn(4), registry_id="station-registry",
                   authority_key_id="b"*64, consumer="host-nginx-https",
                   contact_email="ops@example.org",
                   acme_directory="https://acme-staging.example.org/directory")
    delivery = dict(service_id="candidate-nginx", certificate_id="station-web",
                    hostnames=["issuer.example.org"], policy_sha256="a"*64,
                    issuer_uid=28001, peer_uid=28001,
                    issuer_state="/verified/state/certificate-data")
    issuer = dict(storage_id="c"*32, grant_id="d"*32,
                  uid=28001, gid=28002, software_view="sha256:"+"e"*64,
                  certificate_data_path="/verified/state/certificate-data",
                  controller_record_sha256="f"*64)
    ledger = dict(schema="zog-host-install-certificate-owner-ledger-v1",
                  installation_id=uuidn(2), state_volume_id=uuidn(4),
                  registry_id="station-registry", authority_key_id="b"*64,
                  service_id="candidate-nginx", certificate_id="station-web",
                  binding_sha256=_hash(binding), delivery_policy_sha256=_hash(delivery),
                  issuer=issuer, local_intent_sha256="e"*64,
                  revision=4, operation_id=uuidn(3),
                  assignment_sha256="d"*64, owner_authority_sha256=_hash(owner),
                  status="approved", operations=[])
    authorization=dict(schema="zog-issuer-cloudflare-credential-v1", state="approved",
                       project="/verified/project", certificate_id="station-web",
                       assignment_id=uuidn(12), assignment_revision=4,
                       credential_id=credential_uuid, credential_revision=5,
                       zone_id="zone1", zone_name="example.org", grant_id="d"*32,
                       storage_id="c"*32, policy_sha256="a"*64, receipt_sha256="f"*64,
                       expires_at=NOW+1800)
    projection=dict(schema="zog-station-issuer-reader-authorization-v1",
                    authorization=authorization, origin="managed",
                    installation_id=uuidn(2),host_id=uuidn(1),
                    account_id="a"*32,owner_user_id=42)
    owner_bytes=json.dumps(owner,sort_keys=True).encode()
    pin_bytes=b"trusted installed signer pin"
    client=dict(schema="zog-issuer-https-credential-client-v1",
                project="/verified/project", authorization_id=_hash(authorization),
                host_id=uuidn(1), installation_id=uuidn(2), state_volume_id=uuidn(4),
                host_fingerprint="d"*64, registry_id="station-registry",
                assignment_id=uuidn(12), assignment_revision=4,
                receipt_sha256="f"*64,
                https_origin="https://station.example.org",
                tls_authority_pin_sha256="a"*64,
                purpose="issuer-cloudflare-dns01",
                consumer_uid=28001, grant_id="d"*32,
                storage_id="c"*32, credential_revision=5,
                owner_authority_sha256=hashlib.sha256(owner_bytes).hexdigest(),
                station_signer_pin_sha256=hashlib.sha256(pin_bytes).hexdigest())
    return dict(owner=owner,binding=binding,ledger=ledger,delivery=delivery,
                authorization=authorization,projection=projection,client=client,
                owner_bytes=owner_bytes,signer_pin_bytes=pin_bytes,now=NOW)


def test_positive_exact_issuer_admission_is_nonsecret_and_not_transfer():
    kwargs=sample()
    result=validate(**kwargs)
    assert result["status"]=="source-bound-nonsecret-admission"
    assert result["credential_transferred"] is False
    assert result["installed_bytes_verified"] is False
    assert result["authorization_id"]==kwargs["client"]["authorization_id"]
    assert "token" not in str(result)
    assert result["transport"]=="authenticated-https-443"


@pytest.mark.parametrize("field, key, changed",[
    ("owner","status","revoked"),
    ("owner","credential_revision",6),
    ("owner","dns_zone","another.example.org"),
    ("owner","host_id",uuidn(99)),
    ("binding","installation_id",uuidn(99)),
    ("binding","policy_sha256","0"*64),
    ("binding","credential_id","cloudflare-"+"f"*32),
    ("ledger","revision",5),
    ("ledger","delivery_policy_sha256","0"*64),
    ("ledger","owner_authority_sha256","0"*64),
    ("delivery","issuer_uid",9999),
    ("authorization","credential_revision",9),
    ("authorization","zone_name","other.example.org"),
    ("authorization","storage_id","0"*32),
    ("authorization","policy_sha256","0"*64),
    ("projection","origin","local"),
    ("client","host_id",uuidn(99)),
    ("client","assignment_id",uuidn(99)),
    ("client","registry_id","other-registry"),
    ("client","state_volume_id",uuidn(99)),
    ("client","station_signer_pin_sha256","0"*64),
    ("client","https_origin","http://station.example.org"),
    ("client","https_origin","https://user@station.example.org"),
    ("client","tls_authority_pin_sha256","0"),
    ("client","purpose","admin-password"),
    ("client","consumer_uid",0),
    ("client","grant_id","0"*32),
    ("client","credential_revision",6),
])
def test_independent_owner_policy_revision_and_station_drift_denied(field,key,changed):
    kwargs=sample()
    kwargs[field][key]=changed
    with pytest.raises(CredentialAdmissionBlocked):
        validate(**kwargs)


def test_root_credential_revision_is_bound_to_signed_local_intent():
    kwargs=sample()
    kwargs["owner"]["credential_id"]="cloudflare-"+"b"*32
    with pytest.raises(CredentialAdmissionBlocked):
        validate(**kwargs)


def test_expiry_and_signer_owner_file_rotation_fail_closed():
    kwargs=sample()
    kwargs["now"]=NOW+4000
    with pytest.raises(CredentialAdmissionBlocked):
        validate(**kwargs)
    kwargs=sample()
    kwargs["owner_bytes"]=b"rotated or replaced receipt"
    with pytest.raises(CredentialAdmissionBlocked):
        validate(**kwargs)
    kwargs=sample()
    kwargs["signer_pin_bytes"]=b"rotated signer"
    with pytest.raises(CredentialAdmissionBlocked):
        validate(**kwargs)
