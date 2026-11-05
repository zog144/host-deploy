"""Exact disabled broker package/unit selection, no filesystem installation."""
from pathlib import Path
import pytest
from zog.host_deploy.gateway import graphics_owner_trust_install as install
from zog.host_deploy.gateway import graphics_owner_trust_history as trust

ROOT=Path(__file__).resolve().parents[1]


def candidate():
    sources={}
    for name in install.SOURCES:
        path=ROOT/"src"/Path(*name.split(".")).with_suffix(".py")
        sources[name]=path.read_bytes()
    service=(ROOT/"deploy/graphical-trust-broker/zog-graphical-trust.service").read_bytes()
    sock=(ROOT/"deploy/graphical-trust-broker/zog-graphical-trust.socket").read_bytes()
    record={
        "schema":"zog-task-c-original-checkpoint-installation-v1",
        "host_id":"1"*64,"installation_id":"2"*64,
        "state_volume_id":"3"*64,
        "checkpoint_account_id":"123456789012",
        "checkpoint_region":"us-east-1",
        "checkpoint_bucket":"original-bucket",
        "checkpoint_prefix":"original-accepted/task-c/",
        "checkpoint_scope_sha256":"sha256:"+"4"*64,
        "checkpoint_genesis_sha256":"sha256:"+"5"*64,
        "checkpoint_role_arn":"arn:aws:iam::123456789012:role/OriginalCheckpointWriter",
        "root_source_revision":install.OWNER}
    manifest={
        "schema":install.SCHEMA,"root_source_revision":install.OWNER,
        "gateway_source_revision":"a"*40,
        "host_id":record["host_id"],"installation_id":record["installation_id"],
        "state_volume_id":record["state_volume_id"],
        "scope_sha256":record["checkpoint_scope_sha256"],
        "gateway_executable_sha256":"sha256:"+"6"*64,
        "gateway_uid":15310,"gateway_gid":15311,
        "gateway_cgroup":"/system.slice/zog-graphical-gateway.service",
        "original_checkpoint_sha256":install.sha(trust.canonical(record)),
        "owner_observation_public_sha256":"sha256:"+"7"*64,
        "broker_signer_public_sha256":"sha256:"+"8"*64,
        "installed_gateway_source_sha256":"sha256:"+"9"*64,
        "readonly_checkpoint_role_arn":"arn:aws:iam::123456789012:role/OriginalReadOnlyReader",
        "owner_ssm_role_arn":"arn:aws:iam::123456789012:role/OriginalSsmSender",
        "owner_checkpoint_write_role_arn":record["checkpoint_role_arn"],
        "source_modules_sha256":install.sha(b"".join(
            name.encode("ascii")+b"\0"+sources[name]+b"\0"
            for name in sorted(sources))),
        "service_sha256":install.sha(service),
        "socket_sha256":install.sha(sock),
        "runtime_python":"/opt/selected-venv/bin/python",
        "status":"NOT_ACTIVATED","socket_enabled":False,
        "service_enabled":False,"broker_admitted":False,
        "original_authority_admitted":False,
    }
    return manifest,sources,service,sock,record


def check(manifest,sources,service,sock,record):
    return install.validate_disabled_selection(
        manifest,actual_modules=sources,service=service,
        socket_unit=sock,original_checkpoint_record=record)


def test_complete_source_contract_is_inactive_without_native_authority():
    inputs=candidate()
    result=check(*inputs)
    assert result["status"]=="SOURCE_SELECTION_DISABLED"
    assert set(result.values())=={
        "SOURCE_SELECTION_DISABLED",False}
    assert result["native_broker_installed"] is False


@pytest.mark.parametrize("field,value",[
    ("host_id","0"*64),
    ("installation_id","0"*64),
    ("state_volume_id","0"*64),
    ("scope_sha256","sha256:"+"0"*64),
    ("root_source_revision","0"*40),
    ("readonly_checkpoint_role_arn",
        "arn:aws:iam::123456789012:role/OriginalCheckpointWriter"),
    ("owner_ssm_role_arn",
        "arn:aws:iam::123456789012:role/OriginalReadOnlyReader"),
    ("gateway_uid",0),("gateway_gid",0),
    ("gateway_executable_sha256","invalid"),
    ("service_sha256","sha256:"+"0"*64),
    ("socket_enabled",True),
    ("broker_admitted",True),("original_authority_admitted",True),
    ("status","ACTIVATED"),
])
def test_source_substitutions_and_early_activation_hold(field,value):
    manifest,sources,service,sock,record=candidate()
    manifest[field]=value
    with pytest.raises(install.BrokerInstallHold):
        check(manifest,sources,service,sock,record)


@pytest.mark.parametrize("field,value",[
    ("checkpoint_account_id","999999999999"),
    ("checkpoint_region","eu-west-1"),
    ("checkpoint_bucket","another-bucket"),
    ("checkpoint_prefix","new-scope/"),
    ("checkpoint_genesis_sha256","sha256:"+"0"*64),
    ("checkpoint_role_arn",
      "arn:aws:iam::123456789012:role/AlteredCheckpoint"),
])
def test_original_s3_authority_must_not_be_replaced(field,value):
    manifest,sources,service,sock,record=candidate()
    record[field]=value
    with pytest.raises(install.BrokerInstallHold):
        check(manifest,sources,service,sock,record)


def test_changed_code_or_credential_unit_bytes_deny():
    manifest,sources,service,sock,record=candidate()
    sources[next(iter(sources))]+=b"\n"
    with pytest.raises(install.BrokerInstallHold):
        check(manifest,sources,service,sock,record)
    manifest,sources,service,sock,record=candidate()
    with pytest.raises(install.BrokerInstallHold):
        check(manifest,sources,service+b"\nWantedBy=multi-user.target",sock,record)
    manifest,sources,service,sock,record=candidate()
    with pytest.raises(install.BrokerInstallHold):
        check(manifest,sources,service,sock+b"\nListenSequentialPacket=/tmp/weak",record)
