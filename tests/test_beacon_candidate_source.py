"""Native-independent tests of exact installed beacon candidate source selection.

The CI source job clones the three exact public commits and passes ONE explicit
candidate root. A socket-restricted sandbox can run static baseline tests
without pretending a Unix-socket failure is a source-pin mismatch.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

import pytest

from zog.host_deploy import beacon_payload, discovery

from test_public_publisher_selection import BEACON, validate_candidate


def selected_root():
    name = os.environ.get("HOST_DEPLOY_CANDIDATE_SOURCE_DIRECTORY")
    if not name:
        pytest.skip("exact candidate checkouts require HOST_DEPLOY_CANDIDATE_SOURCE_DIRECTORY")
    root = Path(name)
    assert root.is_absolute() and root.is_dir()
    return root


def test_candidate_descriptor_matches_all_exact_clean_git_checkouts():
    import importlib.util
    script = Path(__file__).resolve().parents[1] / "scripts/beacon_candidate_selection.py"
    spec = importlib.util.spec_from_file_location("beacon_candidate_selection", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    selected = selected_root()
    actual = module.candidate(selected)
    descriptor = json.loads(BEACON.read_text())
    validate_candidate(descriptor)
    assert actual == descriptor
    assert len(actual["packages"]["host-identify"]["files"]) == 17
    assert len(actual["packages"]["host-discover"]["files"]) == 35
    assert len(actual["packages"]["host-install"]["files"]) == 76


def test_installer_package_uses_only_explicit_candidate_source_directory(monkeypatch):
    directory = selected_root()
    # Never rely on ambient HOST_DEPLOY_SOURCE_DIRECTORY; the installer must
    # receive the exact candidate selection from the caller.
    monkeypatch.delenv("HOST_DEPLOY_SOURCE_DIRECTORY", raising=False)
    package = beacon_payload.payload(source=directory)
    assert beacon_payload.payload(source=directory) == package
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        names = set(archive.namelist())
        descriptor = json.loads(BEACON.read_text())
        for name, selected in descriptor["packages"].items():
            for relative, digest in selected["files"].items():
                data = archive.read(name + "/" + relative)
                assert hashlib.sha256(data).hexdigest() == digest
        included = json.loads(archive.read("beacon-source-versions.json"))
        assert included == descriptor
        assert "deployment/signed-identity/host-discover.service" in names
        assert "beacon_install.py" in names


def test_install_preflight_uses_the_explicit_candidate_and_never_contacts_host(
        tmp_path, monkeypatch):
    directory = selected_root()
    monkeypatch.delenv("HOST_DEPLOY_SOURCE_DIRECTORY", raising=False)
    hits = []
    real_payload = beacon_payload.payload
    def check_selected(source):
        hits.append(source)
        return real_payload(source)
    monkeypatch.setattr(beacon_payload, "payload", check_selected)
    def no_host(_):
        raise RuntimeError("host-side preflight boundary reached")
    monkeypatch.setattr(discovery, "owned_host", no_host)
    with pytest.raises(RuntimeError, match="host-side preflight boundary"):
        discovery.install(
            tmp_path / "workspace", source=directory,
            server="https://registry.example.test", server_ready=True,
        )
    assert hits == [directory]


def test_candidate_path_tampering_fails_without_touching_release_manifest(
        tmp_path, monkeypatch):
    directory = selected_root()
    destination = tmp_path / "partial"
    destination.mkdir()
    with pytest.raises(ValueError, match="Missing pinned"):
        beacon_payload.payload(source=destination)
    assert json.loads(BEACON.read_text())["packages"]["host-discover"]["version"] == "0.4.14"
