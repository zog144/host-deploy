"""Historical beacon pins are privileged/native fixtures, not public CI inputs."""
import io
import json
import os
from pathlib import Path
import shutil
import zipfile
import hashlib
import pytest

from zog.host_deploy import beacon_payload as module


@pytest.fixture
def selected(tmp_path, monkeypatch):
    """Only synthetic public-safe bytes; exact old private commits not implied."""
    root = tmp_path / "inputs"
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    (manifests / "beacon_install.py").write_text("print('synthetic')\n")
    (manifests / "beacon_installation").mkdir()
    (manifests / "beacon_installation/requirements-security-tested.txt").write_text("")
    paths = {
        "host-identify": "src/zog/host_identify/signatures.py",
        "host-install": "src/zog/host_install/state_admission.py",
        "host-discover": "deployment/host-discover.service",
    }
    packages = {}
    for name, relative in paths.items():
        p = root / name / relative
        p.parent.mkdir(parents=True)
        value = (name + " public unit fixture\n").encode()
        p.write_bytes(value)
        packages[name] = {
            "repository": "example/" + name,
            "commit": "a"*40,
            "files": {relative: hashlib.sha256(value).hexdigest()},
        }
    (manifests / "beacon_sources.json").write_text(
        json.dumps({"schema": 1, "packages": packages}))
    monkeypatch.setattr(module.resources, "files", lambda unused: manifests)
    return root, paths


def test_payload_uses_only_hash_bound_offline_source_files(selected):
    root, paths = selected
    value = module.payload(root)
    assert module.payload(root) == value
    with zipfile.ZipFile(io.BytesIO(value)) as archive:
        names = archive.namelist()
        for name, path in paths.items():
            assert f"{name}/{path}" in names
        assert "beacon-source-versions.json" in names
        assert "beacon_install.py" in names
        assert "requirements-security-tested.txt" in names
        assert "deployment/signed-identity/host-discover.service" in names
        assert not any(".git" in name or "tests/" in name for name in names)


def test_tampered_missing_and_symlinked_source_fails_closed(selected):
    root, paths = selected
    target = root / "host-discover" / paths["host-discover"]
    target.write_text("changed after pin")
    with pytest.raises(ValueError, match="differs from pinned"):
        module.payload(root)
    target.unlink()
    with pytest.raises(ValueError, match="Missing pinned"):
        module.payload(root)
    target.write_text("source")
    target.unlink()
    target.symlink_to(root / "host-install" / paths["host-install"])
    with pytest.raises(ValueError, match="symbolic"):
        module.payload(root)


@pytest.mark.skipif(
    os.environ.get("HOST_DEPLOY_HISTORICAL_PIN_ACCEPTANCE") != "1",
    reason="historical exact pin compatibility is a separate isolated Work gate",
)
def test_opt_in_legacy_exact_companion_acceptance():
    directory = os.environ.get("HOST_DEPLOY_SOURCE_DIRECTORY")
    if not directory:
        pytest.skip("requires exact historical private companion checkouts")
    value = module.payload(Path(directory))
    with zipfile.ZipFile(io.BytesIO(value)) as archive:
        assert len(archive.namelist()) >= 40
