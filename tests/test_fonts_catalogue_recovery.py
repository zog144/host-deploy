"""First-Fonts catalogue two-file recovery, synthetic native attestations only."""
import json
import os
from pathlib import Path
import tempfile

import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as owner


@pytest.fixture
def install_case(tmp_path, monkeypatch):
    # Privileged filesystem metadata is genuinely checked; nonroot CI cannot
    # simulate it by falsifying the process uid.
    if os.geteuid() != 0:
        pytest.skip("root-owned-file acceptance requires disposable root test")
    state = Path(tempfile.mkdtemp(prefix="zog-fonts-recovery-", dir="/root"))
    state.chmod(0o700)
    monkeypatch.setattr(owner, "STORE", state)
    monkeypatch.setattr(owner, "CATALOGUE", state / "first-fonts-catalogue-v1.json")
    monkeypatch.setattr(owner, "RECEIPT", state / "first-fonts-catalogue-receipt-v1.json")
    candidate = {
        "bytes": b'{"schema":2,"tasks":{}}',
        "catalogue": {"schema": 2, "tasks": {}},
        "sha256": owner._sha(b'{"schema":2,"tasks":{}}'),
        "accepted_base_generation_id": "a" * 64,
        "accepted_base_receipt_sha256": "sha256:" + "b" * 64,
        "retained_acceptance_sha256": "sha256:" + "c" * 64,
        "host_id": "host-fixture", "installation_id": "installation-fixture",
        "lane": "synthetic-fonts", "compiler_authorized": False,
    }
    invocations = []
    def vetted_prepare(**kwargs):
        invocations.append(kwargs)
        return candidate
    monkeypatch.setattr(owner, "prepare", vetted_prepare)
    def checked_load(path, require_root_owned):
        assert require_root_owned is True
        assert path.read_bytes() == candidate["bytes"]
        return candidate["catalogue"], candidate["sha256"]
    monkeypatch.setattr(owner.task_catalogue, "load", checked_load)
    def install():
        return owner.install_native(
            lane_name="synthetic-fonts", generation_id="a" * 64,
            read_managed_lane=lambda lane: {"lane": lane},
            read_accepted_base=lambda generation: {
                "generation_id": generation,
                "acceptance_receipt_sha256": "sha256:" + "b" * 64,
            },
            read_installed_pin=lambda *_: b"pin-fixture",
            read_compiler_base_receipt=lambda _: b"receipt-fixture",
            read_compiler_base_issuer=lambda: {"installation_id": "installation-fixture"},
            read_compiler_base_binding=lambda *args: {},
            attest_installed_source=lambda src: True,
            attest_host_identity=lambda host, installation:
                (host, installation) == ("host-fixture", "installation-fixture"),
        )
    yield install, state, candidate, invocations
    import shutil
    shutil.rmtree(state)


def test_identical_completed_catalogue_returns_without_file_replacement(install_case):
    install, state, candidate, invocations = install_case
    first = install()
    original = {p.name: (p.stat().st_ino, p.read_bytes()) for p in state.iterdir()}
    assert install() == first
    assert {p.name: (p.stat().st_ino, p.read_bytes()) for p in state.iterdir()} == original
    assert len(invocations) == 2  # signed base selection rechecked on retry
    assert first["compiler_authorized"] is False


def test_complete_catalogue_without_receipt_recovers_only_second_file(install_case, monkeypatch):
    install, state, candidate, invocations = install_case
    original = owner._write_exclusive
    def interrupted(path, content):
        if path == owner.RECEIPT:
            raise RuntimeError("simulated power loss before receipt write")
        return original(path, content)
    monkeypatch.setattr(owner, "_write_exclusive", interrupted)
    with pytest.raises(RuntimeError, match="simulated power loss"):
        install()
    old_inode = owner.CATALOGUE.stat().st_ino
    assert owner.CATALOGUE.read_bytes() == candidate["bytes"]
    assert not owner.RECEIPT.exists()
    monkeypatch.setattr(owner, "_write_exclusive", original)
    receipt = install()
    assert owner.CATALOGUE.stat().st_ino == old_inode
    assert json.loads(owner.RECEIPT.read_text()) == receipt
    assert len(invocations) == 2


@pytest.mark.parametrize("conflict", ["catalogue", "receipt", "receipt-only", "symlink"])
def test_conflicting_or_unsafe_existing_files_are_not_modified(install_case, conflict):
    install, state, candidate, invocations = install_case
    if conflict == "receipt-only":
        owner.RECEIPT.write_bytes(b"foreign")
        owner.RECEIPT.chmod(0o600)
    else:
        install()
        if conflict == "catalogue":
            owner.CATALOGUE.write_bytes(b"foreign")
        elif conflict == "receipt":
            owner.RECEIPT.write_bytes(b"foreign")
        else:
            owner.CATALOGUE.unlink()
            owner.CATALOGUE.symlink_to(owner.RECEIPT)
    before = {p.name: (p.is_symlink(), p.read_bytes()) for p in state.iterdir()}
    with pytest.raises((owner.GraphicalCatalogueBlocked, OSError)):
        install()
    assert {p.name: (p.is_symlink(), p.read_bytes()) for p in state.iterdir()} == before
