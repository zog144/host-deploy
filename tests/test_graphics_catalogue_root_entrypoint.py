"""Real root-owned evidence readers for first Fonts; no AWS or issuer writes."""
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile

import pytest

from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy.gateway import graphics_catalogue_owner as catalogue
from zog.host_deploy.gateway import graphics_catalogue_native_install as native
from zog.host_deploy.gateway import graphics_attester_import as importer


def _old(host="fixture-compiler-host"):
    return {
        "schema": lanes.SCHEMA, "lane": "gateway-first-fonts-runtime",
        "mode": "managed", "source_repository": catalogue.REPOSITORY,
        "source_revision": catalogue.SOURCE,
        "monthly_pin_repository_path": catalogue.PIN_PATH,
        "monthly_pin_identity": "sha256:" + catalogue.PIN_SHA256,
        "observed_state_dir": None, "python_executable": "/usr/bin/python3",
        "provenance_host_id": host, "provenance_project_id": "original-project",
        "project_root": "/home/owner/gateway-first-fonts-runtime",
        "resource_policy": {
            "memory_maximum_bytes": 2**30, "thread_count_maximum": 8,
            "cpu_weight": 100, "disk_reservation_bytes": 2**30,
        },
        "controller": {
            "socket_path": "/run/zog/root-control.sock",
            "execution_user_id": 24202, "execution_group_id": 24202,
            "startup_timeout_seconds": 30, "execution_timeout_seconds": 3600,
            "termination_grace_seconds": 10, "wait_timeout_seconds": 0,
            "transport_timeout_seconds": 45,
        },
    }


@pytest.fixture
def evidence(monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root-owned file, directory and source tests need root")
    root = Path(tempfile.mkdtemp(prefix="zog-fonts-native-", dir="/root"))
    root.chmod(0o700)
    source_dir = root / "verified-source"
    source_dir.mkdir(mode=0o700)
    refs = [catalogue.SOURCE, catalogue.EXECUTABLE_SOURCE, catalogue.READER_SOURCE]
    source_roots = {}
    for index, revision in enumerate(refs):
        directory = source_dir / ("source" + str(index))
        directory.mkdir(mode=0o700)
        (directory / "sample.py").write_text("v = " + str(index) + "\n")
        (directory / "sample.py").chmod(0o600)
        source_roots[revision] = {
            "root": str(directory),
            "tree_sha256": catalogue._sha(
                native._canonical(importer._inventory(str(directory)))),
        }
    records = root / "installed-input"
    records.mkdir(mode=0o700)
    store = root / "gateway-store"
    store.mkdir(mode=0o700)
    monkeypatch.setattr(native, "EVIDENCE_DIRECTORY", str(records))
    monkeypatch.setattr(catalogue, "STORE", store)
    monkeypatch.setattr(catalogue, "CATALOGUE", store / "first-fonts-catalogue-v1.json")
    monkeypatch.setattr(catalogue, "RECEIPT", store / "first-fonts-catalogue-receipt-v1.json")
    original = lanes.validate(_old())
    inherited = lanes.corrected_first_fonts_specification(original)
    generation = "a" * 64
    receipt = b"original-signed-receipt-placeholder"
    digest = catalogue._sha(receipt)
    row = {
        "schema": native.SCHEMA,
        "lane_record": {
            "schema": lanes.INHERITED_SCHEMA, "lane": inherited["lane"],
            "specification": inherited, "state": "active",
        },
        "accepted_base": {
            "schema": catalogue.EVIDENCE_SCHEMA, "generation_id": generation,
            "kind": "toolchain", "acceptance_receipt_sha256": digest,
            "source_repository": catalogue.REPOSITORY,
            "verified_source_revision": catalogue.READER_SOURCE,
        },
        "issuer_policy": {
            "host_id": original["provenance_host_id"],
            "installation_id": "issuer-install-1",
            "state_volume_id": "state-1",
            "project_id": original["provenance_project_id"],
        },
        "producer_binding": {
            "host_id": original["provenance_host_id"],
            "installation_id": "issuer-install-1",
            "state_volume_id": "state-1",
            "generation_id": generation,
            "acceptance_receipt_sha256": digest,
        },
        "origin_lane": original,
        "host_identity": {
            "schema": native.IDENTITY_SCHEMA,
            "host_id": original["provenance_host_id"],
            "installation_id": "issuer-install-1",
            "state_volume_id": "state-1",
        },
        "installed_sources": {
            "schema": native.SOURCE_SCHEMA, "roots": source_roots,
        },
    }
    def write(value):
        paths = {
            native.EVIDENCE_NAME: native._canonical(value),
            native.RECEIPT_NAME: receipt,
            native.PIN_NAME: b"pin-unknown-to-fixture",
        }
        for name, raw in paths.items():
            path = records / name
            path.write_bytes(raw)
            path.chmod(0o600)
    write(row)
    yield row, write, records, store, source_roots
    shutil.rmtree(root)


def test_root_owned_entry_uses_real_selected_readers(evidence, monkeypatch):
    row, write, directory, store, roots = evidence
    observed = []
    def actual_wiring(**callbacks):
        assert set(callbacks) == {
            "lane_name", "generation_id", "read_managed_lane",
            "read_accepted_base", "read_installed_pin",
            "attest_installed_source", "attest_host_identity",
            "read_compiler_base_receipt", "read_compiler_base_issuer",
            "read_compiler_base_binding", "read_compiler_base_origin_lane",
        }
        lane = callbacks["lane_name"]
        gen = callbacks["generation_id"]
        assert callbacks["read_managed_lane"](lane) == row["lane_record"]["specification"]
        assert callbacks["read_accepted_base"](gen) == row["accepted_base"]
        assert callbacks["read_compiler_base_receipt"](gen) == (
            directory / native.RECEIPT_NAME).read_bytes()
        assert callbacks["read_compiler_base_issuer"]() == row["issuer_policy"]
        assert callbacks["read_compiler_base_origin_lane"](gen) == row["origin_lane"]
        assert callbacks["read_compiler_base_binding"](
            gen, row["accepted_base"]["acceptance_receipt_sha256"]) == row["producer_binding"]
        assert callbacks["read_installed_pin"](
            catalogue.SOURCE, catalogue.PIN_PATH) == (
            directory / native.PIN_NAME).read_bytes()
        assert callbacks["attest_host_identity"](
            row["host_identity"]["host_id"],
            row["host_identity"]["installation_id"]) is True
        assert callbacks["attest_host_identity"]("foreign", "issuer-install-1") is False
        for revision in roots:
            assert callbacks["attest_installed_source"](revision) is True
        observed.append("exact-readers")
        return {"compiler_authorized": False}
    monkeypatch.setattr(catalogue, "install_native", actual_wiring)
    got = native.install(
        lane=row["lane_record"]["lane"],
        generation=row["accepted_base"]["generation_id"])
    assert got == {"compiler_authorized": False}
    assert observed == ["exact-readers"]
    assert list(store.iterdir()) == []


@pytest.mark.parametrize("field,value", [
    ("host_identity.host_id", "foreign-host"),
    ("host_identity.installation_id", "foreign-install"),
    ("host_identity.state_volume_id", "wrong-state"),
    ("issuer_policy.installation_id", "foreign-install"),
    ("producer_binding.host_id", "foreign-host"),
    ("accepted_base.generation_id", "b" * 64),
    ("lane_record.state", "prepared"),
    ("lane_record.lane", "wrong-lane"),
    ("origin_lane.provenance_project_id", "wrong-origin"),
])
def test_conflicting_identity_fails_before_writer(evidence, monkeypatch, field, value):
    row, write, _, store, _ = evidence
    changed = copy.deepcopy(row)
    a, b = field.split(".")
    changed[a][b] = value
    write(changed)
    monkeypatch.setattr(catalogue, "install_native", lambda **kwargs:
                        pytest.fail("no file writer on identity failure"))
    with pytest.raises((native.NativeCatalogueHeld, ValueError)):
        native.install(lane=row["lane_record"]["lane"],
                       generation=row["accepted_base"]["generation_id"])
    assert list(store.iterdir()) == []


def test_foreign_selection_fails_before_writer(evidence, monkeypatch):
    row, _, _, store, _ = evidence
    monkeypatch.setattr(catalogue, "install_native", lambda **kwargs:
                        pytest.fail("caller cannot change selected identity"))
    for lane, generation in (
        ("foreign", row["accepted_base"]["generation_id"]),
        (row["lane_record"]["lane"], "b" * 64),
    ):
        with pytest.raises(native.NativeCatalogueHeld):
            native.install(lane=lane, generation=generation)
    assert list(store.iterdir()) == []


def test_symlink_and_writable_evidence_are_denied(evidence, monkeypatch):
    row, _, root, store, _ = evidence
    file = root / native.EVIDENCE_NAME
    fake = root / "substitute"
    fake.write_bytes(file.read_bytes())
    file.unlink()
    file.symlink_to(fake)
    with pytest.raises((native.NativeCatalogueHeld, importer.ImportBoundaryBlocked)):
        native.install(lane=row["lane_record"]["lane"],
                       generation=row["accepted_base"]["generation_id"])
    assert list(store.iterdir()) == []
    file.unlink()
    file.write_bytes(fake.read_bytes())
    file.chmod(0o666)
    with pytest.raises((native.NativeCatalogueHeld, importer.ImportBoundaryBlocked)):
        native.install(lane=row["lane_record"]["lane"],
                       generation=row["accepted_base"]["generation_id"])


def test_source_drift_is_denied(evidence, monkeypatch):
    row, _, _, store, roots = evidence
    p = Path(next(iter(roots.values()))["root"]) / "sample.py"
    p.write_bytes(b"changed")
    with pytest.raises((native.NativeCatalogueHeld, importer.ImportBoundaryBlocked)):
        native.install(lane=row["lane_record"]["lane"],
                       generation=row["accepted_base"]["generation_id"])
    assert list(store.iterdir()) == []


def test_unverified_signature_never_creates_catalogue(evidence):
    row, _, _, store, _ = evidence
    # The root-owned selected bundle does NOT make this placeholder a signed
    # compiler acceptance; the original signature validator must reject it.
    with pytest.raises((catalogue.GraphicalCatalogueBlocked, ValueError)):
        native.install(lane=row["lane_record"]["lane"],
                       generation=row["accepted_base"]["generation_id"])
    assert list(store.iterdir()) == []


def test_root_boundary_precedes_readers(monkeypatch):
    monkeypatch.setattr(native.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(native, "RootReaders", lambda:
                        pytest.fail("never read evidence as unprivileged caller"))
    with pytest.raises(PermissionError):
        native.install(lane="lane", generation="a" * 64)


def test_cli_rejects_evidence_path_override():
    with pytest.raises(SystemExit):
        native.main(["--lane", "fixture", "--generation", "a" * 64,
                     "--evidence-directory", "/tmp/substitute"])
