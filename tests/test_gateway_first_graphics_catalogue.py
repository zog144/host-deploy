"""Observed-isolation PR20 signed compiler consumer source tests (synthetic keys only)."""
import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from zog.host_deploy import image_build_lanes
from zog.host_deploy.gateway import graphics_base_acceptance as base
from zog.host_deploy.gateway import graphics_catalogue_owner as graphics
from zog.host_deploy.gateway import task_catalogue

GEN="e"*64
HOST="host-source-fixture"
LANE="graphics-protected-fixture"

def base_evidence(a,lane,kind="toolchain"):
    """Generate deterministic disposable signed claim, NEVER real admission."""
    key=Ed25519PrivateKey.from_private_bytes(bytes([3])*32)
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
    historical=({"status":"complete","missing":[],"retained_evidence_sha256":None}
                if kind=="toolchain" else {
                    "status":"historical-gap-declared",
                    "missing":["original self-hosting Build Record history unavailable"],
                    "retained_evidence_sha256":"sha256:"+"b"*64})
    slots={
        role:{"path":path,"sha256":"sha256:"+str(i)*64}
        for i,(role,path) in enumerate((
            ("compiler","usr/bin/gcc"),("linker","usr/bin/ld"),
            ("assembler","usr/bin/as"),("libc_header","usr/include/stdio.h"),
            ("abi_header","usr/include/features.h"),("crt","usr/lib/crt1.o"),
            ("libc","usr/lib/libc.so")),start=1)}
    probe={"schema":"image-build-compiler-linker-probe-v1",
           "status":"passed","base_generation_id":a["accepted_base_generation_id"],
           "compiler_target":"x86_64-linux-gnu","elapsed_seconds":1,
           "isolation":{"schema":"image-build-compiler-isolation-v2",
                        "profile":"selected-root-kernel-mounts-v1",
                        "witness_sha256":"sha256:"+"9"*64}}
    claim={
        "schema":base.ACCEPTANCE_SCHEMA,
        "status":"independently-accepted-for-compiler-use",
        "generation_id":a["accepted_base_generation_id"],
        "generation_kind":kind,
        "generation_manifest_sha256":"sha256:"+"a"*64,
        "generation_inventory_sha256":"sha256:"+"b"*64,
        "generation_record_sha256":"sha256:"+"c"*64 if kind=="toolchain" else None,
        "host_id":a["host_id"],
        "installation_id":a["installation_id"],
        "state_volume_id":"fixture-STATE-identity",
        "project_id":lane["provenance_project_id"],
        "execution_environment_sha256":"sha256:"+"d"*64,
        "target_abi":"x86_64-linux-gnu",
        "installed_paths":slots,
        "historical_provenance":historical,
        "native_probe":probe,
        "required_probe_command_sha256":"sha256:"+"e"*64,
    }
    issuer={
        "schema":base.ISSUER_SCHEMA,
        "host_id":claim["host_id"],"installation_id":claim["installation_id"],
        "state_volume_id":claim["state_volume_id"],
        "project_id":claim["project_id"],
        "execution_environment_sha256":claim["execution_environment_sha256"],
        "key_id":"synthetic-only-not-native","ed25519_public_key":public,
        "receipt_directory":"/protected/native-fixture",
    }
    raw=base.canonical({
        "schema":base.ACCEPTANCE_SCHEMA,"key_id":issuer["key_id"],
        "claim":claim,
        "signature":base64.b64encode(
            key.sign(base.DOMAIN+base.canonical(claim))).decode("ascii")})
    binding={
        "schema":base.BINDING_SCHEMA,
        "generation_id":claim["generation_id"],
        "generation_kind":claim["generation_kind"],
        "generation_manifest_sha256":claim["generation_manifest_sha256"],
        "generation_inventory_sha256":claim["generation_inventory_sha256"],
        "generation_record_sha256":claim["generation_record_sha256"],
        "host_id":claim["host_id"],
        "installation_id":claim["installation_id"],
        "state_volume_id":claim["state_volume_id"],
        "project_id":claim["project_id"],
        "execution_environment_sha256":claim["execution_environment_sha256"],
        "target_abi":claim["target_abi"],
        "compiler_files_sha256":base.digest(base.canonical(slots)),
        "native_probe_sha256":base.digest(base.canonical(probe)),
        "historical_provenance":historical,
        "acceptance_receipt_sha256":base.digest(raw),
        "status":"independent-compiler-capability-observed-not-job-authorization",
    }
    return raw,issuer,binding

def example(kind="toolchain"):
    a={
        "schema":graphics.APPROVAL_SCHEMA,"host_id":HOST,
        "installation_id":"fixture-installation","lane":LANE,
        "lane_owner":HOST,"project_root":"/home/owner/"+LANE,
        "accepted_base_generation_id":GEN,
        "accepted_base_receipt_sha256":"sha256:"+"f"*64,
        "source_revision":graphics.SOURCE,
        "monthly_pin_identity":"sha256:"+graphics.PIN_SHA256,
        "task_allowlist":[graphics.TASK],
        "dedicated_storage_bytes":32*1024**3,"work_bytes":30*1024**3,
        "external_bytes":2*1024**3,"execution_limit_seconds":21600,
    }
    lane=image_build_lanes.specification(
        LANE,source_repository=graphics.REPOSITORY,
        source_revision=graphics.SOURCE,
        monthly_pin_repository_path=graphics.PIN_PATH,
        monthly_pin_identity="sha256:"+graphics.PIN_SHA256,
        provenance_host_id=HOST,provenance_project_id="test-project",
        project_root=a["project_root"],memory_maximum_bytes=2*1024**3,
        thread_count_maximum=16,cpu_weight=100,
        disk_reservation_bytes=32*1024**3,
        execution_user_id=24302,execution_group_id=24302,
        python_executable="/usr/bin/python3")
    signed,issuer,binding=base_evidence(a,lane,kind)
    a["accepted_base_receipt_sha256"]=base.digest(signed)
    selected={
        "schema":graphics.EVIDENCE_SCHEMA,"generation_id":GEN,
        "kind":kind,"acceptance_receipt_sha256":a["accepted_base_receipt_sha256"],
        "source_repository":graphics.REPOSITORY,
        "verified_source_revision":graphics.READER_SOURCE}
    reservation={"scope":graphics.aggregate.BUDGET_SCOPE,
                 "work_bytes":30*1024**3,"external_bytes":2*1024**3}
    return a,lane,selected,reservation

def candidate(a,l,selected,reservation,*,evidence=None,pin=None):
    if evidence is None:
        evidence=base_evidence(a,l,selected["kind"])
    raw,issuer,binding=evidence
    return graphics.prepare(
        approval=a,lane_record=l,accepted_base=selected,
        installed_pin_bytes=accepted_pin_bytes() if pin is None else pin,
        actual_reservation=reservation,compiler_base_receipt_bytes=raw,
        compiler_base_issuer_policy=issuer,compiler_base_binding=binding)

def accepted_pin_bytes():
    file=Path("dependencies/image-build/project/pins/2026-10-01/commit-pin.py")
    if not file.is_file():
        pytest.skip("original immutable October pin not checked out")
    return file.read_bytes()

def test_original_producer_and_new_reader_sources_remain_distinct():
    assert graphics.SOURCE=="1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert graphics.READER_SOURCE=="1616f192ef9d8964a8f37f32a86c69c0242a213c"
    assert graphics.PIN_SHA256=="d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert graphics.TASK=="graphics-fonts-image-v1"
    assert graphics.RECEIPT.parent==graphics.CATALOGUE.parent

def test_signed_toolchain_and_image_keep_original_identity():
    for kind in ("toolchain","image"):
        a,l,b,r=example(kind)
        data=candidate(a,l,b,r)
        assert data["compiler_authorized"] is False
        assert data["accepted_base_kind"]==kind
        assert data["accepted_base_receipt_sha256"]==a["accepted_base_receipt_sha256"]
        assert data["accepted_base_generation_record_sha256"]==(
            "sha256:"+"c"*64 if kind=="toolchain" else None)
        cat=task_catalogue.loads(data["bytes"])
        assert cat==data["catalogue"]
        task=cat["tasks"][graphics.TASK]
        assert task["retained_acceptance_sha256"]==data["retained_acceptance_sha256"]
        assert task["arguments"]=={
            "mode":"image","selection":a["accepted_base_generation_id"],
            "compiler_base":a["accepted_base_receipt_sha256"],
            "targets":["libpng-final","freetype-final","fontconfig-final"]}
        assert set(cat["tasks"])=={graphics.TASK}
        assert data["accepted_base_historical_provenance"]["status"]==(
            "complete" if kind=="toolchain" else "historical-gap-declared")

@pytest.mark.parametrize("mutation",[
    lambda a,l,b,r:a.update(accepted_base_generation_id="0"*64),
    lambda a,l,b,r:a.update(accepted_base_receipt_sha256="sha256:"+"0"*64),
    lambda a,l,b,r:a.update(source_revision="0"*40),
    lambda a,l,b,r:a.update(task_allowlist=[graphics.TASK,"graphics-xcb-core-image-v1"]),
    lambda a,l,b,r:a.update(execution_limit_seconds=21601),
    lambda a,l,b,r:a.update(work_bytes=29*1024**3),
    lambda a,l,b,r:a.update(lane_owner="other"),
    lambda a,l,b,r:l.update(source_revision="0"*40),
    lambda a,l,b,r:b.update(kind="image" if b["kind"]=="toolchain" else "toolchain"),
    lambda a,l,b,r:r.update(external_bytes=1),
])
def test_independent_approval_lane_budget_or_kind_changes_deny(mutation):
    a,l,b,r=example()
    mutation(a,l,b,r)
    with pytest.raises((graphics.GraphicalCatalogueBlocked,
                        base.BaseAcceptanceDenied,ValueError)):
        candidate(a,l,b,r)

@pytest.mark.parametrize("target",[
    "signature","key","receipt","manifest","probe","environment","kind",
    "history","state","abi","installed_paths","source_binding"])
def test_signed_identity_or_native_binding_substitution_denied(target):
    a,l,b,r=example("image")
    raw,issuer,binding=base_evidence(a,l,"image")
    claim=json.loads(raw)["claim"]
    if target=="signature":
        envelope=json.loads(raw);envelope["signature"]="A"*86+"=="
        raw=base.canonical(envelope)
    elif target=="key":
        issuer={**issuer,"ed25519_public_key":"f"*64}
    elif target=="receipt":
        a["accepted_base_receipt_sha256"]="sha256:"+"0"*64
    elif target=="manifest":
        binding={**binding,"generation_manifest_sha256":"sha256:"+"0"*64}
    elif target=="probe":
        binding={**binding,"native_probe_sha256":"sha256:"+"0"*64}
    elif target=="environment":
        issuer={**issuer,"execution_environment_sha256":"sha256:"+"0"*64}
    elif target=="kind":
        binding={**binding,"generation_kind":"toolchain"}
    elif target=="history":
        binding={**binding,"historical_provenance":{
            "status":"complete","missing":[],"retained_evidence_sha256":None}}
    elif target=="state":
        binding={**binding,"state_volume_id":"wrong-STATE"}
    elif target=="abi":
        binding={**binding,"target_abi":"aarch64-linux-gnu"}
    elif target=="installed_paths":
        binding={**binding,"compiler_files_sha256":"sha256:"+"0"*64}
    elif target=="source_binding":
        b["verified_source_revision"]="0"*40
    with pytest.raises((base.BaseAcceptanceDenied,graphics.GraphicalCatalogueBlocked)):
        candidate(a,l,b,r,evidence=(raw,issuer,binding))

def test_wrong_pin_bytes_and_native_nonroot_denied(monkeypatch):
    a,l,b,r=example()
    with pytest.raises(graphics.GraphicalCatalogueBlocked):
        candidate(a,l,b,r,pin=b"wrong")
    monkeypatch.setattr(graphics.os,"geteuid",lambda:1000)
    with pytest.raises(PermissionError):
        graphics.install_native(
            read_managed_lane=lambda _:None,
            read_accepted_base=lambda _:None,
            read_installed_pin=lambda *_:None,
            attest_installed_source=lambda _:None,
            attest_host_identity=lambda *_:None)

def test_missing_native_readers_and_host_denial_precede_any_write(monkeypatch):
    from zog.host_deploy.gateway import fresh_budget_guard,fresh_native_owner
    a,l,b,r=example()
    seen=[]
    monkeypatch.setattr(graphics.os,"geteuid",lambda:0)
    monkeypatch.setattr(graphics.quota,"inspect",
                        lambda:{"capacity_bytes":30*1024**3-4096})
    monkeypatch.setattr(graphics.aggregate,"inspect_external_pool_native",
                        lambda:{"limit_bytes":2*1024**3-4096,
                                "mount_verified":True,"allocation_verified":True,
                                "budget_scope":graphics.aggregate.BUDGET_SCOPE})
    monkeypatch.setattr(fresh_budget_guard,"_protected_root",lambda _:True)
    monkeypatch.setattr(fresh_native_owner,"_read_json",lambda _:a)
    def source(revision):
        seen.append(revision)
        return True
    with pytest.raises(graphics.GraphicalCatalogueBlocked):
        graphics.install_native(
            read_managed_lane=lambda _:pytest.fail("lane"),
            read_accepted_base=lambda _:pytest.fail("base"),
            read_installed_pin=lambda *_:pytest.fail("pin"),
            attest_installed_source=source,
            attest_host_identity=lambda *_:False)
    assert seen==[graphics.SOURCE,graphics.READER_SOURCE]

def test_no_implicit_compilation_or_authorization():
    import inspect
    source=inspect.getsource(graphics)
    for forbidden in ("toolchain.submit(", "build.submit(",
                      "StartTransientUnit","send_command("):
        assert forbidden not in source
    assert "os.O_EXCL" in source
    assert '"compiler_authorized": False' in source
    assert "attest_installed_source(READER_SOURCE)" in source


@pytest.mark.parametrize("target_abi", ["x86_64-linux-gnu", "x86_64-zog-linux-gnu"])
def test_exact_producer_signed_compiler_image_binding(tmp_path, target_abi):
    """Exercise pinned image-build PR18 resolve(), including actual image bytes.

    Producer's synthetic test signer is not native authority; consumer checks
    its real output schema and byte-for-byte signed receipt independently.
    """
    import sys
    producer=Path("dependencies/image-build-base-observer").resolve()
    sys.path.insert(0,str(producer/"src"))
    sys.path.insert(0,str(producer/"tests"))
    from test_compiler_base_acceptance import signed_fixture
    from zog.image_build import compiler_base_acceptance as upstream
    builder,selection,claim,issuer,sign=signed_fixture(tmp_path,kind="image")
    claim["target_abi"] = target_abi
    claim["native_probe"]["compiler_target"] = target_abi
    receipt_id=sign()
    observed=upstream.resolve(builder,selection,receipt_id)
    bytes_=(Path(issuer["receipt_directory"])/
            (selection.generation+".json")).read_bytes()
    approval={
        "host_id":claim["host_id"],
        "installation_id":claim["installation_id"],
        "accepted_base_generation_id":selection.generation,
        "accepted_base_receipt_sha256":receipt_id,
    }
    lane={"provenance_project_id":claim["project_id"],
          "provenance_host_id":claim["host_id"]}
    consumed=base.checked_base(
        bytes_,issuer,observed,approval=approval,lane=lane)
    assert consumed["target_abi"] == target_abi
    assert consumed["kind"]=="image"
    assert consumed["generation_id"]==selection.generation
    assert consumed["accepted_receipt_sha256"]==receipt_id
    assert consumed["generation_record_sha256"] is None
    assert consumed["historical_provenance"]==claim["historical_provenance"]
    assert consumed["status"]==observed["status"]
    # Signatures and binding are separate; a changing issued receipt must
    # never be accepted using the old immutable approval's hash.
    with pytest.raises(base.BaseAcceptanceDenied):
        base.checked_base(bytes_+b" ",issuer,observed,approval=approval,lane=lane)
    with pytest.raises(base.BaseAcceptanceDenied):
        base.checked_base(bytes_,issuer,{**observed,"generation_kind":"toolchain"},
                          approval=approval,lane=lane)


def test_legacy_isolation_denied_despite_matching_signature_and_binding():
    a,lane,_,_=example()
    raw,issuer,binding=base_evidence(a,lane)
    row=json.loads(raw)
    row["claim"]["native_probe"]["isolation"]={"pivot_root":True,"host_mounts_visible":False}
    key=Ed25519PrivateKey.from_private_bytes(bytes([3])*32)
    row["signature"]=base64.b64encode(key.sign(base.DOMAIN+base.canonical(row["claim"]))).decode()
    raw=base.canonical(row);a["accepted_base_receipt_sha256"]=base.digest(raw)
    binding["acceptance_receipt_sha256"]=base.digest(raw)
    binding["native_probe_sha256"]=base.digest(base.canonical(row["claim"]["native_probe"]))
    with pytest.raises(base.BaseAcceptanceDenied):base.checked_base(raw,issuer,binding,approval=a,lane=lane)
