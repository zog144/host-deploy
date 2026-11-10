"""Root-backed broker v4 disabled source selection; no live IAM/SSM."""
import copy
from pathlib import Path

import pytest

from zog.host_deploy.gateway import graphics_owner_trust_install as install
from zog.root_control import graphical_operation_owner_source as op
from zog.root_control import graphical_task_c_root_backed_storage as root
from test_graphics_owner_trust_v3_install import selection

BASE=Path(__file__).resolve().parents[1]
BROKER=BASE/"deploy/graphical-trust-broker/root-backed/zog-graphical-trust.service"
import zog.host_install
VERIFY=Path(zog.host_install.__file__).resolve().parent/"systemd/root-backed/zog-graphical-owner-storage-verified.service"


def selected():
    manifest,modules,roots,_,sock,authority,commit,host=selection()
    manifest=copy.deepcopy(manifest)
    authority=copy.deepcopy(authority)
    commit=copy.deepcopy(commit)
    unit=BROKER.read_bytes()
    verifier=VERIFY.read_bytes()
    authority.update(schema=root.AUTHORITY_SCHEMA,mode=root.MODE,
        ledger_directory=root.LEDGER,authority_directory=root.AUTHORITY,
        root_filesystem_uuid="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
    commit.update(schema=root.COMMIT_SCHEMA,mode=root.MODE)
    plan={"schema":"zog-task-c-root-backed-storage-plan-v2",
          "mode":root.MODE,"root_filesystem_uuid":authority["root_filesystem_uuid"],
          "directories":[root.LEDGER,root.AUTHORITY]}
    manifest.update({
        "schema":install.V4_SCHEMA,
        "root_storage_mode":root.MODE,
        "root_directory_plan_sha256":op.digest(plan),
        "verified_unit_sha256":install.sha(verifier),
        "service_sha256":install.sha(unit),
        "original_checkpoint_sha256":op.digest(authority),
        "storage_commit_sha256":op.digest(commit),
    })
    return manifest,modules,roots,unit,sock,authority,commit,host,plan,verifier


def verify(row):
    manifest,modules,roots,unit,sock,authority,commit,host,plan,verifier=row
    return install.validate_disabled_v4_selection(
        manifest,actual_modules=modules,installed_root_modules=roots,
        installed_host_install_modules=host,service=unit,
        socket_unit=sock,installation_storage_record=authority,
        storage_commit=commit,root_directory_plan=plan,
        verified_unit=verifier)


def test_selected_root_backed_broker_rejects_mount_requirement_and_ssm():
    result=verify(selected())
    assert result["status"]=="V4_ROOT_BACKED_SOURCE_DISABLED"
    assert result["broker_admitted"] is False
    assert result["read_only_role_verified_native"] is False
    assert result["ssm_authorized"] is False


@pytest.mark.parametrize("attack",(
    "legacy_schema","legacy_commit","changed_directory","mount_reintroduced",
    "missing_order","weak_verifier","verified_unit_swapped","wrong_mode",
    "different_reader","missing_anchor","swapped_source","fake_install",
))
def test_v4_never_accepts_wrong_mode_or_native_boolean(attack):
    row=list(selected())
    manifest,modules,roots,unit,sock,authority,commit,host,plan,verifier=row
    if attack=="legacy_schema":
        manifest["schema"]=install.V3_SCHEMA
    elif attack=="legacy_commit":
        commit["schema"]="zog-task-c-installation-storage-commit-v1"
    elif attack=="changed_directory":
        authority["ledger_directory"]="/state/owner"
    elif attack=="mount_reintroduced":
        row[3]=unit.replace(b"[Unit]\n",b"[Unit]\nRequiresMountsFor="+root.LEDGER.encode()+b"\n")
        manifest["service_sha256"]=install.sha(row[3])
    elif attack=="missing_order":
        row[3]=unit.replace(b"After=zog-graphical-owner-storage-verified.service network-online.target\n",b"")
        manifest["service_sha256"]=install.sha(row[3])
    elif attack=="weak_verifier":
        row[9]=verifier.replace(b"CapabilityBoundingSet=\n",b"")
        manifest["verified_unit_sha256"]=install.sha(row[9])
    elif attack=="verified_unit_swapped":
        row[9]=b"not the selected verifier"
    elif attack=="wrong_mode":
        manifest["root_storage_mode"]="two-devices"
    elif attack=="different_reader":
        manifest["readonly_checkpoint_role_arn"]=manifest["owner_checkpoint_write_role_arn"]
    elif attack=="missing_anchor":
        row[8]["directories"]=[]
    elif attack=="swapped_source":
        name=next(iter(roots))
        roots[name]+=b"unknown module"
    elif attack=="fake_install":
        manifest["broker_admitted"]=True
    with pytest.raises(install.BrokerInstallHold):
        verify(row)


def test_old_v3_disallows_a_root_backed_authority_and_service():
    row=list(selected())
    row[0]["schema"]=install.V3_SCHEMA
    with pytest.raises(install.BrokerInstallHold):
        install.validate_disabled_v3_selection(
            row[0],actual_modules=row[1],installed_root_modules=row[2],
            installed_host_install_modules=row[7],service=row[3],
            socket_unit=row[4],installation_storage_record=row[5],
            storage_commit=row[6])
