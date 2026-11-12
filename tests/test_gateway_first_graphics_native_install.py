"""Privileged TEST-ONLY root O_EXCL catalogue writer. No native host mounts.

The test substitutes only the four independently trusted native attesters
and uses a temporary root-owned directory. It does not provision or enable
the real 30+2 GiB worker, compiler gateway, SSM, PID1 or selected generation.
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
    a, lane, base, reservation = example()
    state=protected_tmp/"protected-owner-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    pin=accepted_pin_bytes()
    signed_receipt, pinned_issuer, producer_binding = base_evidence(a,lane)
    monkeypatch.setattr(g, "STORE", state)
    monkeypatch.setattr(g, "APPROVAL", state/"graphics-foundation-approval-v1.json")
    monkeypatch.setattr(g, "CATALOGUE", state/"graphics-foundation-catalogue-v1.json")
    monkeypatch.setattr(g, "RECEIPT", state/"graphics-foundation-catalogue-receipt-v1.json")
    g.APPROVAL.write_text(json.dumps(a),encoding="ascii")
    g.APPROVAL.chmod(0o600)
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
        assert name == a["lane"]
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
    assert observed == ["source","reader","host","lane","base",
                        "signed-receipt","issuer","canonical-binding","pin"]
    assert receipt["compiler_authorized"] is False
    assert receipt["task_allowlist"]==[g.TASK]
    assert receipt["accepted_base_generation_id"] == base["generation_id"]
    assert receipt["accepted_base_manifest_sha256"] == producer_binding["generation_manifest_sha256"]
    assert receipt["accepted_base_inventory_sha256"] == producer_binding["generation_inventory_sha256"]
    assert receipt["accepted_base_generation_record_sha256"] == producer_binding["generation_record_sha256"]
    assert receipt["dedicated_storage_bytes"]==32*1024**3
    assert receipt["resource_admission_location"]=="compiler-host-before-build"
    assert receipt["compiler_resource_admitted"] is False
    for file in (g.APPROVAL,g.CATALOGUE,g.RECEIPT):
        st=file.lstat()
        assert st.st_uid == 0
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_nlink == 1
    data,digest=task_catalogue.load(g.CATALOGUE,require_root_owned=True)
    assert digest==receipt["catalogue_sha256"]
    assert set(data["tasks"])=={g.TASK}
    assert json.loads(g.RECEIPT.read_text())==receipt
    with pytest.raises(g.GraphicalCatalogueBlocked):
        install()
    assert task_catalogue.load(g.CATALOGUE,require_root_owned=True)[1]==digest


@pytest.mark.skipif(os.geteuid()!=0, reason="root-only disposable test")
def test_partial_original_catalogue_cannot_be_repaired(protected_tmp,monkeypatch):
    a,_,_,_=example()
    owner=protected_tmp/"state"
    owner.mkdir(mode=0o700)
    monkeypatch.setattr(g,"STORE",owner)
    monkeypatch.setattr(g,"APPROVAL",owner/"approval")
    monkeypatch.setattr(g,"CATALOGUE",owner/"catalogue")
    monkeypatch.setattr(g,"RECEIPT",owner/"receipt")
    g.APPROVAL.write_text(json.dumps(a),encoding="ascii")
    g.APPROVAL.chmod(0o600)
    g.CATALOGUE.write_bytes(b"interrupted-first-write")
    g.CATALOGUE.chmod(0o600)
    original=g.CATALOGUE.read_bytes()
    with pytest.raises(g.GraphicalCatalogueBlocked):
        g.install_native(
            read_managed_lane=lambda _:pytest.fail("no lane read after interrupt"),
            read_accepted_base=lambda _:pytest.fail("no base read after interrupt"),
            read_installed_pin=lambda *_:pytest.fail("no pin read after interrupt"),
            attest_installed_source=lambda _:True,
            attest_host_identity=lambda *_:True)
    assert g.CATALOGUE.read_bytes()==original
    assert not g.RECEIPT.exists()


@pytest.mark.skipif(os.geteuid()!=0, reason="root-only disposable test")
def test_gateway_catalogue_never_reads_compiler_host_resource_admission(protected_tmp,monkeypatch):
    """Prevent accidentally moving compiler quota/free-space checks to gateway."""
    from zog.host_deploy.gateway import fonts_resource_admission as resources
    def forbidden(*args,**kwargs):
        pytest.fail("gateway must not inspect compiler Host resources")
    monkeypatch.setattr(resources,"checked",forbidden)
    monkeypatch.setattr(resources,"inspect_native",forbidden)
    # The disposable root installation test above invokes the same genuine
    # install_native() entrypoint with these functions absent from its call.
    import inspect
    src=inspect.getsource(g.install_native)
    assert "read_resource_observation" not in src
    assert "resource.checked" not in src
    assert "inspect_native" not in src
    assert "actual_reservation" not in src
    assert "compiler_resource_admitted" in src
