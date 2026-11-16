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


def execution_spec(host="fixture-compiler-host"):
    """Only the active execution lane; no historical origin lane is invented."""
    return lanes.specification(
        "gateway-first-fonts-runtime", mode="managed",
        source_repository=catalogue.REPOSITORY,
        source_revision=catalogue.EXECUTABLE_SOURCE,
        monthly_pin_repository_path=catalogue.PIN_PATH,
        monthly_pin_identity="sha256:" + catalogue.PIN_SHA256,
        provenance_host_id=host, provenance_project_id="fonts-execution-project",
        project_root="/var/lib/zog/image-build/projects/gateway-first-fonts-runtime",
        memory_maximum_bytes=2**30, thread_count_maximum=8,
        cpu_weight=100, disk_reservation_bytes=2**30,
        python_executable="/usr/bin/python3",
    )


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
    inherited = execution_spec()
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
            "host_id": inherited["provenance_host_id"],
            "installation_id": "issuer-install-1",
            "state_volume_id": "state-1",
            "project_id": "original-compiler-project",
        },
        "producer_binding": {
            "host_id": inherited["provenance_host_id"],
            "installation_id": "issuer-install-1",
            "state_volume_id": "state-1",
            "generation_id": generation,
            "acceptance_receipt_sha256": digest,
        },
        "compiler_provenance": {
            "schema": "host-deploy-verified-compiler-generation-origin-v1",
            "project_root": "/home/certbot-build-owner/certbot-seed",
            "project_id": "original-compiler-project",
            "generation_id": generation,
            "generation_kind": "toolchain",
            "host_id": inherited["provenance_host_id"],
            "installation_id": "issuer-install-1",
            "state_volume_id": "state-1",
            "generation_manifest_sha256": "sha256:" + "1" * 64,
            "generation_inventory_sha256": "sha256:" + "2" * 64,
            "generation_record_sha256": "sha256:" + "3" * 64,
            "execution_environment_sha256": "sha256:" + "e" * 64,
            "acceptance_receipt_sha256": digest,
        },
        "host_identity": {
            "schema": native.IDENTITY_SCHEMA,
            "host_id": inherited["provenance_host_id"],
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
            "read_compiler_base_binding", "read_compiler_base_provenance",
        }
        lane = callbacks["lane_name"]
        gen = callbacks["generation_id"]
        assert callbacks["read_managed_lane"](lane) == row["lane_record"]["specification"]
        assert callbacks["read_accepted_base"](gen) == row["accepted_base"]
        assert callbacks["read_compiler_base_receipt"](gen) == (
            directory / native.RECEIPT_NAME).read_bytes()
        assert callbacks["read_compiler_base_issuer"]() == row["issuer_policy"]
        assert callbacks["read_compiler_base_provenance"](gen) == row["compiler_provenance"]
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
    ("compiler_provenance.project_id", "wrong-origin"),
    ("compiler_provenance.generation_id", "b" * 64),
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


def _genuine_disposable_approval(row):
    """One test-owned Ed25519 issuer, never an installed real compiler authority."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from zog.host_deploy.gateway import graphics_base_acceptance as base

    private = Ed25519PrivateKey.generate()
    issuer = dict(row["issuer_policy"])
    issuer.update({
        "schema": base.ISSUER_SCHEMA,
        "key_id": "test-native-root-owner",
        "ed25519_public_key": private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex(),
        "receipt_directory": "/state/accepted-disposable-receipts",
        "execution_environment_sha256": "sha256:" + "e" * 64,
    })
    installed_paths = {
        role: {"path": "usr/bin/" + role,
               "sha256": "sha256:" + format(i + 1, "064x")}
        for i, role in enumerate(base.ROLES)
    }
    probe = {
        "isolation": {
            "schema": "image-build-compiler-isolation-v2",
            "profile": "selected-root-kernel-mounts-v1",
            "witness_sha256": "sha256:" + "9" * 64,
        }
    }
    history = {"status": "complete", "missing": [],
               "retained_evidence_sha256": None}
    claim = {
        "schema": base.ACCEPTANCE_SCHEMA,
        "status": "independently-accepted-for-compiler-use",
        "generation_id": row["accepted_base"]["generation_id"],
        "generation_kind": "toolchain",
        "generation_manifest_sha256": "sha256:" + "1" * 64,
        "generation_inventory_sha256": "sha256:" + "2" * 64,
        "generation_record_sha256": "sha256:" + "3" * 64,
        "host_id": issuer["host_id"],
        "installation_id": issuer["installation_id"],
        "state_volume_id": issuer["state_volume_id"],
        "project_id": issuer["project_id"],
        "execution_environment_sha256": issuer["execution_environment_sha256"],
        "target_abi": "x86_64-zog-linux-gnu",
        "installed_paths": installed_paths,
        "historical_provenance": history,
        "native_probe": probe,
        "required_probe_command_sha256": "sha256:" + "7" * 64,
    }
    signature = base64.b64encode(
        private.sign(base.DOMAIN + base.canonical(claim))).decode("ascii")
    receipt = base.canonical({
        "schema": base.ACCEPTANCE_SCHEMA, "key_id": issuer["key_id"],
        "claim": claim, "signature": signature,
    })
    binding = {
        "schema": base.BINDING_SCHEMA,
        "generation_id": claim["generation_id"],
        "generation_kind": claim["generation_kind"],
        "generation_manifest_sha256": claim["generation_manifest_sha256"],
        "generation_inventory_sha256": claim["generation_inventory_sha256"],
        "generation_record_sha256": claim["generation_record_sha256"],
        "host_id": claim["host_id"],
        "installation_id": claim["installation_id"],
        "state_volume_id": claim["state_volume_id"],
        "project_id": claim["project_id"],
        "execution_environment_sha256": claim["execution_environment_sha256"],
        "target_abi": claim["target_abi"],
        "compiler_files_sha256": base.digest(base.canonical(installed_paths)),
        "native_probe_sha256": base.digest(base.canonical(probe)),
        "historical_provenance": history,
        "acceptance_receipt_sha256": base.digest(receipt),
        "status": "independent-compiler-capability-observed-not-job-authorization",
    }
    row = copy.deepcopy(row)
    row["issuer_policy"] = issuer
    row["producer_binding"] = binding
    row["accepted_base"]["acceptance_receipt_sha256"] = base.digest(receipt)
    row["compiler_provenance"].update({
        key: claim[key] for key in (
            "generation_id", "generation_kind", "project_id", "host_id",
            "installation_id", "state_volume_id",
            "generation_manifest_sha256", "generation_inventory_sha256",
            "generation_record_sha256", "execution_environment_sha256",
        )
    })
    row["compiler_provenance"]["acceptance_receipt_sha256"] = base.digest(receipt)
    return row, receipt


def test_real_signed_disposable_receipt_installs_twice_without_replacement(evidence):
    row, write, directory, store, _ = evidence
    pin = Path("pinned-image-build/project/pins/2026-10-01/commit-pin.py")
    if not pin.is_file():
        pytest.skip("exact original October pin checkout required")
    pin_bytes = pin.read_bytes()
    assert catalogue._sha(pin_bytes) == "sha256:" + catalogue.PIN_SHA256

    signed_row, signed_bytes = _genuine_disposable_approval(row)
    write(signed_row)
    receipt_path = directory / native.RECEIPT_NAME
    receipt_path.write_bytes(signed_bytes)
    receipt_path.chmod(0o600)
    pin_path = directory / native.PIN_NAME
    pin_path.write_bytes(pin_bytes)
    pin_path.chmod(0o600)

    selected = signed_row["accepted_base"]["generation_id"]
    lane = signed_row["lane_record"]["lane"]
    installed = native.install(lane=lane, generation=selected)
    assert installed["compiler_authorized"] is False
    assert installed["status"] == "installed-catalogue-not-build-authorization"
    assert installed["accepted_base_generation_id"] == selected
    assert installed["compiler_origin_project_id"] == "original-compiler-project"
    assert installed["compiler_origin_project_root"] == "/home/certbot-build-owner/certbot-seed"
    assert installed["execution_project_id"] == "fonts-execution-project"
    assert installed["execution_project_root"] == "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
    assert installed["compiler_origin_project_root"] != installed["execution_project_root"]
    assert installed["host_id"] == signed_row["host_identity"]["host_id"]
    assert installed["installation_id"] == signed_row["host_identity"]["installation_id"]
    assert catalogue.CATALOGUE.is_file() and catalogue.RECEIPT.is_file()
    inodes = {p.name: (p.stat().st_ino, p.read_bytes()) for p in store.iterdir()}
    assert native.install(lane=lane, generation=selected) == installed
    assert inodes == {p.name: (p.stat().st_ino, p.read_bytes())
                     for p in store.iterdir()}
    assert json.loads(catalogue.RECEIPT.read_bytes()) == installed


def test_disposable_signed_receipt_bound_to_wrong_project_is_denied(evidence):
    row, write, directory, store, _ = evidence
    signed_row, signed_bytes = _genuine_disposable_approval(row)
    signed_row["compiler_provenance"]["project_id"] = "foreign-project"
    write(signed_row)
    p = directory / native.RECEIPT_NAME
    p.write_bytes(signed_bytes)
    p.chmod(0o600)
    with pytest.raises((native.NativeCatalogueHeld, ValueError)):
        native.install(lane=row["lane_record"]["lane"],
                       generation=row["accepted_base"]["generation_id"])
    assert list(store.iterdir()) == []
