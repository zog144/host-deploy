"""Exact-byte v3 broker disabled install; no real source/role admission."""
import importlib.util
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from zog.host_deploy.gateway import graphics_owner_trust_install as install
from zog.root_control import graphical_task_c_trust_authority as root
from zog.root_control import graphical_operation_owner_source as op
from test_graphics_owner_trust_v3_installation import selected


BASE=Path(__file__).resolve().parents[1]


def selection():
    row=selected()
    root_files={
        name:Path(importlib.util.find_spec(name).origin).read_bytes()
        for name in root.ROOT_V3_SOURCES}
    modules={
        name:Path(importlib.util.find_spec(name).origin).read_bytes()
        for name in install.SOURCES}
    host_modules={
        name:Path(importlib.util.find_spec(name).origin).read_bytes()
        for name in install.HOST_INSTALL_V2_SOURCES}
    owner_sha=install.sha(b"".join(
        name.encode()+b"\0"+root_files[name]+b"\0"
        for name in sorted(root_files)))
    broker_sha=install.sha(b"".join(
        name.encode()+b"\0"+modules[name]+b"\0"
        for name in sorted(modules)))
    host_sha=install.sha(b"".join(
        name.encode()+b"\0"+host_modules[name]+b"\0"
        for name in sorted(host_modules)))
    unit=(BASE/"deploy/graphical-trust-broker/zog-graphical-trust.service").read_bytes()
    sock=(BASE/"deploy/graphical-trust-broker/zog-graphical-trust.socket").read_bytes()
    record=row["storage_record"]
    manifest={
        "schema":install.V3_SCHEMA,
        "root_source_sha256":owner_sha,
        "native_host_install_source_sha256":host_sha,
        "gateway_source_revision":"f"*40,
        "host_id":row["root_row"]["host_id"],
        "installation_id":row["root_row"]["installation_id"],
        "state_volume_id":row["root_row"]["state_volume_id"],
        "scope_sha256":row["pin"]["scope_sha256"],
        "installation_scope_sha256":record["installation_scope_sha256"],
        "registry_sha256":record["registry_sha256"],
        "storage_commit_sha256":op.digest(row["storage_commit"]),
        "gateway_executable_sha256":row["broker_config"][
            "gateway_executable_sha256"],
        "gateway_uid":row["broker_config"]["gateway_uid"],
        "gateway_gid":row["broker_config"]["gateway_gid"],
        "gateway_cgroup":row["broker_config"]["gateway_cgroup"],
        "original_checkpoint_sha256":op.digest(record),
        "owner_observation_public_sha256":root.digest_bytes(
            row["observation_public"]),
        "broker_signer_public_sha256":root.digest_bytes(
            row["broker_signer"].public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "installed_gateway_source_sha256":broker_sha,
        "readonly_checkpoint_role_arn":record["checkpoint_reader_role_arn"],
        "owner_ssm_role_arn":row["root_row"]["ssm"]["role_arn"],
        "owner_checkpoint_write_role_arn":record["checkpoint_writer_role_arn"],
        "source_modules_sha256":broker_sha,
        "service_sha256":install.sha(unit),
        "socket_sha256":install.sha(sock),
        "runtime_python":"/usr/bin/python3",
        "status":"NOT_ACTIVATED",
        "socket_enabled":False,"service_enabled":False,
        "broker_admitted":False,"original_authority_admitted":False,
    }
    assert set(manifest)==install.V3_FIELDS
    return manifest, modules, root_files, unit, sock,record,row["storage_commit"],host_modules


def inspect(values):
    manifest,modules,roots,unit,sock,record,commit,host_modules=values
    return install.validate_disabled_v3_selection(
        manifest,actual_modules=modules,installed_root_modules=roots,
        installed_host_install_modules=host_modules,
        service=unit,socket_unit=sock,
        installation_storage_record=record,storage_commit=commit)


def test_v3_installation_source_selects_correct_modules_and_both_mounts():
    row=selection()
    result=inspect(row)
    assert result["status"]=="V3_SOURCE_SELECTION_DISABLED"
    assert result["socket_enabled"] is False
    assert result["broker_admitted"] is False
    assert result["ssm_authorized"] is False
    assert result["read_only_role_verified_native"] is False
    assert result["exact_root_module_sha256"]==row[0]["root_source_sha256"]
    assert result["exact_host_install_v2_source_sha256"]==row[0][
        "native_host_install_source_sha256"]
    assert result["exact_broker_module_sha256"]==row[0]["source_modules_sha256"]


@pytest.mark.parametrize("tamper",(
    "root_bytes","broker_bytes","host_install_bytes","role_swap","scope_swap",
    "commit_swap","genesis_swap","owner_mount_missing",
    "requires_in_service","socket_enable","privileged_ssm",
    "claimed_activation","missing_readonly_role",
))
def test_exact_v3_disabled_install_blocks_mutated_source_or_authority(tamper):
    state=list(selection())
    manifest,modules,roots,service,socket,record,commit,host_modules=state
    if tamper=="root_bytes":
        name=next(iter(roots))
        roots[name]+=b"malicious"
    elif tamper=="broker_bytes":
        name=next(iter(modules))
        modules[name]+=b"malicious"
    elif tamper=="host_install_bytes":
        name=next(iter(host_modules))
        host_modules[name]+=b"malicious"
    elif tamper=="role_swap":
        manifest["readonly_checkpoint_role_arn"]=manifest[
            "owner_checkpoint_write_role_arn"]
    elif tamper=="scope_swap":
        manifest["installation_scope_sha256"]="sha256:"+"f"*64
    elif tamper=="commit_swap":
        commit["accepted_at"]=999
    elif tamper=="genesis_swap":
        record["checkpoint_genesis_sha256"]="sha256:"+"f"*64
    elif tamper=="owner_mount_missing":
        state[3]=service.replace(
            b"RequiresMountsFor=/var/lib/zog-graphical-owner-authority\n",b"")
        manifest["service_sha256"]=install.sha(state[3])
    elif tamper=="requires_in_service":
        state[3]=service.replace(
            b"RequiresMountsFor=/var/lib/zog-graphical-owner-ledger\n",b"")
        state[3]+=b"\nRequiresMountsFor=/var/lib/zog-graphical-owner-ledger"
        manifest["service_sha256"]=install.sha(state[3])
    elif tamper=="socket_enable":
        state[4]=socket+b"\n[Install]\nWantedBy=sockets.target\n"
        manifest["socket_sha256"]=install.sha(state[4])
    elif tamper=="privileged_ssm":
        state[3]=service+b"\nLoadCredential=aws-session.json:/etc/aws-secret"
        manifest["service_sha256"]=install.sha(state[3])
    elif tamper=="claimed_activation":
        manifest["broker_admitted"]=True
    elif tamper=="missing_readonly_role":
        manifest["readonly_checkpoint_role_arn"]="arn:aws:iam::123456789012:role/NewReader"
    with pytest.raises(install.BrokerInstallHold):
        inspect(state)
