"""Separate released-public-publisher and exact candidate beacon selections.

The publisher's Git-object index describes the historical released commits.
The live candidate beacon descriptor is a different selection with its own
SHA256 inventory. Neither can silently rewrite the other.
"""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "public-companion-publisher.json"
INDEX = ROOT / "docs/host-deploy/public-companion-git-objects-2026-10-18.json"
BEACON = ROOT / "src/zog/host_deploy/beacon_sources.json"

RELEASED = {
    "root-control": "3a2dd9c935e332e811adaccedf04b16bd2de1ea7",
    "box-control": "dec2def825a474675def51df44d75d534e76508f",
    "image-build": "0fd3f00cafc7138d3bac9695c87a8ece65821868",
    "host-identify": "1a5eac0b255c995022db6a3a4c0051efffa748cc",
    "host-discover": "0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80",
    "host-install": "325b6c95320d04ad14b987f25e07c1361b7e6f04",
}
BEACON_NAMES = {"host-identify", "host-discover", "host-install"}
RELEASE_COUNTS = {"host-identify": 15, "host-discover": 33, "host-install": 42}
CANDIDATE = {
    "host-discover": "a6f3f402cee87eb7079d94c7eb36474930d45444",
    "host-identify": "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b",
    "host-install": "71643eef03739749c7c272f7c6be23d7063a51d8",
}
VERSIONS = {
    "host-discover": "0.4.14",
    "host-identify": "0.3.5",
    "host-install": "0.14.9",
}
REQUIRED = {
    "host-discover": {
        "src/zog/host_discover/__init__.py",
        "src/zog/host_discover/daemon.py",
        "src/zog/host_discover/fresh_state_identity.py",
        "src/zog/host_discover/role_state.py",
        "src/zog/host_discover/bootstrap.py",
        "deployment/host-discover.service",
        "src/zog/host_discover/systemd/host-discover.service",
    },
    "host-identify": {
        "src/zog/host_identify/__init__.py",
        "src/zog/host_identify/storage.py",
        "src/zog/host_identify/signatures.py",
    },
    "host-install": {
        "src/zog/host_install/__init__.py",
        "src/zog/host_install/beacon_profile.py",
        "src/zog/host_install/state_admission.py",
        "src/zog/host_install/identity_worker.py",
        "src/zog/host_install/state_provision.py",
        "src/zog/host_install/systemd/host-install-identity.service",
    },
}
COMMON = {"LICENSE", "LICENSES/BSD-3-Clause.txt",
          "LICENSES/GPL-3.0-only.txt", "THIRD-PARTY-NOTICES.md",
          "README.md", "pyproject.toml"}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def read():
    return (json.loads(PUBLISHER.read_text()),
            json.loads(INDEX.read_text()),
            json.loads(BEACON.read_text()))


def validate_publisher(publisher, index):
    """The publisher and full Git index MUST remain at released commits."""
    assert publisher["schema"] == "zog-host-deploy-public-publisher-v1"
    assert publisher["status"] == "SOURCE-REVIEW-ONLY"
    assert publisher["acceptance"]["public_export"] == "not-authorized"
    assert publisher["beacon_sources"] == "src/zog/host_deploy/beacon_sources.json"
    # Historical blob digest, not the current candidate descriptor digest.
    assert publisher["beacon_descriptor_git_blob_sha1"] == "dabe6a5bb6f3d9f5732fc18437f8f9b042ed3026"
    assert publisher["git_object_index"] == "docs/host-deploy/public-companion-git-objects-2026-10-18.json"
    assert index["schema"] == "zog-host-deploy-public-file-git-index-v1"
    assert index["status"] == "SOURCE-REVIEW-ONLY"
    assert index["hash_format"] == "Git blob SHA-1 anchored by exact commit and tree"
    assert set(publisher["packages"]) == set(index["packages"]) == set(RELEASED)
    assert publisher["beacon_versions"] == {
        "host-identify": "0.3.4", "host-discover": "0.4.9",
        "host-install": "0.10.0",
    }
    assert publisher["beacon_dependency_claims"] == {
        "host-discover": ["host-identify==0.3.4", "host-install==0.10.0"]
    }
    for name, sha in RELEASED.items():
        selected = publisher["packages"][name]
        obj = index["packages"][name]
        assert selected["repository"] == obj["repository"] == "zog144/" + name
        assert selected["commit"] == obj["commit"] == sha
        assert HEX40.fullmatch(selected["tree_sha1"])
        assert selected["tree_sha1"] == obj["tree_sha1"]
        assert selected["tracked_file_count"] == len(obj["files"]) > 0
        for path, entry in obj["files"].items():
            assert isinstance(path, str) and path and not path.startswith("/")
            assert ".." not in path.split("/") and "\\" not in path
            assert entry["mode"] in ("100644", "100755")
            assert HEX40.fullmatch(entry["git_blob_sha1"])
            assert type(entry["size"]) is int and entry["size"] >= 0
    for name, count in RELEASE_COUNTS.items():
        assert publisher["packages"][name]["beacon_sha256_file_count"] == count


def validate_candidate(beacon):
    """Current installer pinning has its own exact source/metadata contract."""
    assert beacon["schema"] == 1
    assert set(beacon["packages"]) == BEACON_NAMES
    for name in BEACON_NAMES:
        item = beacon["packages"][name]
        assert set(item) == {"repository", "commit", "version", "dependencies", "files"}
        assert item["repository"] == "zog144/" + name
        assert item["commit"] == CANDIDATE[name]
        assert item["version"] == VERSIONS[name]
        assert type(item["dependencies"]) is list
        assert all(type(d) is str for d in item["dependencies"])
        assert type(item["files"]) is dict and item["files"]
        assert COMMON | REQUIRED[name] <= set(item["files"])
        assert set(item["files"]) == {
            path for path in item["files"]
            if (path.startswith("src/zog/" + name.replace("-", "_") + "/")
                or path in COMMON or path.startswith(
                    ("LICENSES/", "deployment/", "systemd/")))
        }
        for path, digest in item["files"].items():
            assert path and not path.startswith("/") and "\\" not in path
            assert all(part not in ("", ".", "..") for part in path.split("/"))
            assert isinstance(digest, str) and HEX64.fullmatch(digest)
    deps = beacon["packages"]["host-discover"]["dependencies"]
    assert "host-identify==0.3.5" in deps
    assert "host-install==0.14.9" in deps
    for name in BEACON_NAMES:
        for other in BEACON_NAMES:
            for item in beacon["packages"][name]["dependencies"]:
                if item.startswith(other + "=="):
                    assert item == other + "==" + VERSIONS[other]


def test_historical_public_publisher_and_git_object_index_are_frozen():
    p, index, candidate = read()
    validate_publisher(p, index)


def test_candidate_beacon_commits_and_package_metadata_are_independent():
    p, index, candidate = read()
    validate_candidate(candidate)


@pytest.mark.parametrize("mutation", [
    "wrong-released-discover-pin", "wrong-root-tree",
    "missing-git-object", "wrong-released-dependency", "premature-go",
    "wrong-historical-descriptor-blob",
])
def test_publisher_drift_cannot_silently_change_released_baseline(mutation):
    p, index, candidate = read()
    if mutation == "wrong-released-discover-pin":
        p["packages"]["host-discover"]["commit"] = "0" * 40
    elif mutation == "wrong-root-tree":
        index["packages"]["root-control"]["tree_sha1"] = "a" * 40
    elif mutation == "missing-git-object":
        del index["packages"]["box-control"]["files"][
            next(iter(index["packages"]["box-control"]["files"]))]
    elif mutation == "wrong-released-dependency":
        p["beacon_dependency_claims"]["host-discover"][1] = "host-install==0.4.4"
    elif mutation == "premature-go":
        p["status"] = "APPROVED"
    else:
        p["beacon_descriptor_git_blob_sha1"] = "f" * 40
    with pytest.raises(AssertionError):
        validate_publisher(p, index)


@pytest.mark.parametrize("mutation", [
    "wrong-candidate-commit", "missing-required-runtime-module",
    "bad-file-sha", "missing-license", "wrong-version",
    "missing-exact-dependency", "wrong-namespace",
])
def test_candidate_drift_rejected_without_rewriting_public_release(mutation):
    p, index, b = read()
    if mutation == "wrong-candidate-commit":
        b["packages"]["host-discover"]["commit"] = "a" * 40
    elif mutation == "missing-required-runtime-module":
        del b["packages"]["host-discover"]["files"][
            "src/zog/host_discover/fresh_state_identity.py"]
    elif mutation == "bad-file-sha":
        b["packages"]["host-install"]["files"]["pyproject.toml"] = "not-sha256"
    elif mutation == "missing-license":
        del b["packages"]["host-install"]["files"]["LICENSES/BSD-3-Clause.txt"]
    elif mutation == "wrong-version":
        b["packages"]["host-identify"]["version"] = "0.3.4"
    elif mutation == "missing-exact-dependency":
        b["packages"]["host-discover"]["dependencies"] = []
    else:
        b["packages"]["host-identify"]["files"]["other/strange.py"] = "f" * 64
    with pytest.raises(AssertionError):
        validate_candidate(b)
    # Candidate mutation is never an excuse to move the released publisher.
    validate_publisher(p, index)
