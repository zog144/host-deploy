"""Privileged TEST-ONLY root O_EXCL catalogue writer. No native host mounts.

The test substitutes installed native readers and uses a temporary root-owned
directory. It does not provision compiler storage, enable the gateway, invoke
SSM, change PID1 or select a real compiler generation.
"""
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile

import pytest
from zog.host_deploy.gateway import graphics_catalogue_owner as g
from zog.host_deploy.gateway import task_catalogue, fresh_native_owner
from test_gateway_first_graphics_catalogue import example, accepted_pin_bytes, base_evidence



@pytest.fixture
def protected_tmp():
    # /tmp is world writable even when the fixture child is root-owned;
    # _protected_root intentionally rejects that ancestry.
    root=Path(tempfile.mkdtemp(prefix="zog-test-",dir="/root"))
    root.chmod(0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root)


@pytest.mark.skipif(os.geteuid()!=0, reason="root-only disposable test")
def test_root_owned_one_shot_receipt_and_no_replacement(protected_tmp, monkeypatch):
    a, lane, base = example()
    state=protected_tmp/"protected-owner-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    pin=accepted_pin_bytes()
    signed_receipt, pinned_issuer, producer_binding = base_evidence(a,lane)
    monkeypatch.setattr(g, "STORE", state)
    monkeypatch.setattr(g, "CATALOGUE", state/"graphics-foundation-catalogue-v1.json")
    monkeypatch.setattr(g, "RECEIPT", state/"graphics-foundation-catalogue-receipt-v1.json")
    observed=[]
    def attested_source(revision):
        assert revision in (g.SOURCE, g.READER_SOURCE)
        observed.append("source" if revision == g.SOURCE else "reader")
        return True
    def attested_host(host, installation):
        assert (host,installation)==(a["host_id"],a["installation_id"])
        observed.append("host")
        return True
    def attested_lane(name):
        assert name == lane["lane"]
        observed.append("lane")
        return lane
    def attested_base(identity):
        assert identity == a["accepted_base_generation_id"]
        observed.append("base")
        return base
    def attested_producer(identity):
        assert identity == a["accepted_base_generation_id"]
        observed.append("signed-receipt")
        return signed_receipt
    def attested_issuer():
        observed.append("issuer")
        return pinned_issuer
    def attested_native(identity,receipt_sha):
        assert identity == a["accepted_base_generation_id"]
        assert receipt_sha == a["accepted_base_receipt_sha256"]
        observed.append("canonical-binding")
        return producer_binding
    def attested_pin(revision,path):
        assert (revision,path)==(g.SOURCE,g.PIN_PATH)
        observed.append("pin")
        return pin
    def install():
        return g.install_native(
            lane_name=lane["lane"],
            generation_id=a["accepted_base_generation_id"],
            read_managed_lane=attested_lane,
            read_accepted_base=attested_base,
            read_compiler_base_receipt=attested_producer,
            read_compiler_base_issuer=attested_issuer,
            read_compiler_base_binding=attested_native,
            read_installed_pin=attested_pin,
            attest_installed_source=attested_source,
            attest_host_identity=attested_host)
    # The gateway has no filesystem/quota space precondition: only a tiny
    # root-owned metadata file is installed on this disposable test Host.
    receipt=install()
    assert observed == ["source","reader","base","lane",
                        "signed-receipt","issuer","canonical-binding","pin","host"]
    assert receipt["compiler_authorized"] is False
    assert set(task_catalogue.load(g.CATALOGUE,require_root_owned=True)[0]["tasks"])=={g.TASK}
    assert receipt["accepted_base_generation_id"] == base["generation_id"]
    assert receipt["retained_acceptance_sha256"].startswith("sha256:")
    assert receipt["status"]=="installed-catalogue-not-build-authorization"
    for file in (g.CATALOGUE,g.RECEIPT):
        st=file.lstat()
        assert st.st_uid == 0
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_nlink == 1
    data,digest=task_catalogue.load(g.CATALOGUE,require_root_owned=True)
    assert digest==receipt["catalogue_sha256"]
    assert set(data["tasks"])=={g.TASK}
    assert json.loads(g.RECEIPT.read_text())==receipt
    assert sorted(p.name for p in state.iterdir())==sorted((g.CATALOGUE.name,g.RECEIPT.name))
    with pytest.raises(g.GraphicalCatalogueBlocked):
        install()
    assert task_catalogue.load(g.CATALOGUE,require_root_owned=True)[1]==digest


@pytest.mark.skipif(os.geteuid()!=0, reason="root-only disposable test")
def test_partial_original_catalogue_cannot_be_repaired(protected_tmp,monkeypatch):
    a,lane,_=example()
    owner=protected_tmp/"state"
    owner.mkdir(mode=0o700)
    monkeypatch.setattr(g,"STORE",owner)
    monkeypatch.setattr(g,"CATALOGUE",owner/"catalogue")
    monkeypatch.setattr(g,"RECEIPT",owner/"receipt")
    g.CATALOGUE.write_bytes(b"interrupted-first-write")
    g.CATALOGUE.chmod(0o600)
    original=g.CATALOGUE.read_bytes()
    with pytest.raises(g.GraphicalCatalogueBlocked):
        g.install_native(
            lane_name=lane["lane"],generation_id=a["accepted_base_generation_id"],
            read_managed_lane=lambda _:pytest.fail("no lane read after interrupt"),
            read_accepted_base=lambda _:pytest.fail("no base read after interrupt"),
            read_installed_pin=lambda *_:pytest.fail("no pin read after interrupt"),
            attest_installed_source=lambda _:True,
            attest_host_identity=lambda *_:True)
    assert g.CATALOGUE.read_bytes()==original
    assert not g.RECEIPT.exists()


def test_gateway_catalogue_has_no_budget_quota_deadline_or_approval_file():
    """Only the installed gateway StateDirectory, catalogue and receipt remain."""
    import inspect
    source=inspect.getsource(g)
    assert g.STORE == Path("/var/lib/host-deploy-gateway")
    assert not hasattr(g, "APPROVAL")
    for forbidden in ("APPROVAL_SCHEMA", "graphics-foundation-approval-v1.json",
                      "fonts_resource_admission", "read_resource_observation",
                      "actual_reservation", "disk_reservation_bytes",
                      "execution_limit_seconds", "Q_XGETQUOTA", "statvfs"):
        assert forbidden not in source
    assert "os.O_EXCL" in source
    assert "accepted_base_receipt_sha256" in source


@pytest.mark.skipif(os.geteuid()!=0, reason="root-only disposable test")
def test_distinct_fonts_lane_installs_from_original_compiler_project(protected_tmp,monkeypatch):
    """Two-file install uses native original project, without rewriting its lane."""
    import copy
    from zog.host_deploy.gateway import graphics_base_acceptance as base
    original_identity,old_lane,selected=example("image")
    old_lane=copy.deepcopy(old_lane)
    old_lane["source_revision"]="a"*40
    target=copy.deepcopy(old_lane)
    target["lane"]="compiler-fonts"
    target["project_root"]="/home/owner/compiler-fonts"
    target["provenance_project_id"]="new-unique-fonts-project"
    target["source_revision"]=g.SOURCE
    raw,issuer,binding=base_evidence(original_identity,old_lane,"image")
    selected["acceptance_receipt_sha256"]=base.digest(raw)

    store=protected_tmp/"existing-gateway-state"
    store.mkdir(mode=0o700)
    monkeypatch.setattr(g,"STORE",store)
    monkeypatch.setattr(g,"CATALOGUE",store/"first-fonts-catalogue-v1.json")
    monkeypatch.setattr(g,"RECEIPT",store/"first-fonts-catalogue-receipt-v1.json")
    with pytest.raises(base.BaseAcceptanceDenied):
        g.install_native(
            lane_name=target["lane"],generation_id=selected["generation_id"],
            read_managed_lane=lambda _:target,read_accepted_base=lambda _:selected,
            read_installed_pin=lambda *_:accepted_pin_bytes(),
            attest_installed_source=lambda _:True,
            attest_host_identity=lambda *_:True,
            read_compiler_base_receipt=lambda _:raw,
            read_compiler_base_issuer=lambda:issuer,
            read_compiler_base_binding=lambda *_:binding,
        )
    assert list(store.iterdir())==[]
    receipt=g.install_native(
        lane_name=target["lane"],generation_id=selected["generation_id"],
        read_managed_lane=lambda _:target,read_accepted_base=lambda _:selected,
        read_installed_pin=lambda *_:accepted_pin_bytes(),
        attest_installed_source=lambda _:True,
        attest_host_identity=lambda host,installation: (
            host==original_identity["host_id"]
            and installation==original_identity["installation_id"]),
        read_compiler_base_receipt=lambda _:raw,
        read_compiler_base_issuer=lambda:issuer,
        read_compiler_base_binding=lambda *_:binding,
        read_compiler_base_origin_lane=lambda _:old_lane,
    )
    assert receipt["lane"]==target["lane"]
    assert receipt["accepted_base_generation_id"]==selected["generation_id"]
    assert receipt["catalogue_sha256"]==task_catalogue.load(
        g.CATALOGUE,require_root_owned=True)[1]
    assert sorted(x.name for x in store.iterdir())==[
        "first-fonts-catalogue-receipt-v1.json",
        "first-fonts-catalogue-v1.json",
    ]
    assert old_lane["source_revision"]=="a"*40
    assert target["source_revision"]==g.SOURCE
