"""Exact six-component public source selection and complete beacon closure.

These are static, credential-free guards, not evidence of live installation.
"""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "public-companion-publisher.json"
INDEX = ROOT / "docs/host-deploy/public-companion-git-objects-2026-10-18.json"
BEACON = ROOT / "src/zog/host_deploy/beacon_sources.json"
REVISIONS = {
    "root-control": "3a2dd9c935e332e811adaccedf04b16bd2de1ea7",
    "box-control": "dec2def825a474675def51df44d75d534e76508f",
    "image-build": "0fd3f00cafc7138d3bac9695c87a8ece65821868",
    "host-identify": "1a5eac0b255c995022db6a3a4c0051efffa748cc",
    "host-discover": "0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80",
    "host-install": "325b6c95320d04ad14b987f25e07c1361b7e6f04",
}
BEACON_NAMES = {"host-identify", "host-discover", "host-install"}
RELEASE_COUNTS = {"host-identify": 15, "host-discover": 33, "host-install": 42}
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def read():
    return (json.loads(PUBLISHER.read_text()),
            json.loads(INDEX.read_text()),
            json.loads(BEACON.read_text()))


def validate(publisher, index, beacon):
    assert publisher["schema"] == "zog-host-deploy-public-publisher-v1"
    assert publisher["status"] == "SOURCE-REVIEW-ONLY"
    assert publisher["acceptance"]["public_export"] == "not-authorized"
    assert publisher["beacon_sources"] == "src/zog/host_deploy/beacon_sources.json"
    assert publisher["git_object_index"] == "docs/host-deploy/public-companion-git-objects-2026-10-18.json"
    assert index["schema"] == "zog-host-deploy-public-file-git-index-v1"
    assert index["status"] == "SOURCE-REVIEW-ONLY"
    assert index["hash_format"] == "Git blob SHA-1 anchored by exact commit and tree"
    assert beacon["schema"] == 1
    assert set(publisher["packages"]) == set(index["packages"]) == set(REVISIONS)
    assert set(beacon["packages"]) == BEACON_NAMES
    assert publisher["beacon_versions"] == {
        "host-identify": "0.3.4", "host-discover": "0.4.9", "host-install": "0.10.0",
    }
    assert publisher["beacon_dependency_claims"] == {
        "host-discover": ["host-identify==0.3.4", "host-install==0.10.0"]
    }
    for name, sha in REVISIONS.items():
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
        selected = publisher["packages"][name]
        beacon_value = beacon["packages"][name]
        assert selected["beacon_sha256_file_count"] == count
        assert beacon_value["repository"] == "zog144/" + name
        assert beacon_value["commit"] == REVISIONS[name]
        assert len(beacon_value["files"]) == count
        prefix = "src/zog/" + name.replace("-", "_") + "/"
        assert prefix + "__init__.py" in beacon_value["files"]
        for filename in ("LICENSE", "LICENSES/BSD-3-Clause.txt",
                         "LICENSES/GPL-3.0-only.txt",
                         "THIRD-PARTY-NOTICES.md", "pyproject.toml"):
            assert filename in beacon_value["files"]
        for path, digest in beacon_value["files"].items():
            assert HEX64.fullmatch(digest)
            assert path in index["packages"][name]["files"]
            assert (path.startswith(prefix)
                    or path in ("README.md", "LICENSE", "THIRD-PARTY-NOTICES.md",
                                "pyproject.toml")
                    or path.startswith(("LICENSES/", "deployment/", "systemd/")))
    assert "src/zog/host_discover/certificate_assignment.py" in beacon["packages"]["host-discover"]["files"]
    for filename in ("certificate_gate.py", "welcome_readiness.py",
                     "certificate_lifecycle.py"):
        assert "src/zog/host_install/" + filename in beacon["packages"]["host-install"]["files"]
    for filename in ("host-discover.service", "host-discover-supervisor@.service"):
        assert "deployment/" + filename in beacon["packages"]["host-discover"]["files"]


def test_public_publisher_selection_and_beacon_closure_are_frozen():
    validate(*read())


@pytest.mark.parametrize("mutation", [
    "wrong-discover-pin", "wrong-root-tree", "missing-issuer-module",
    "bad-file-sha", "missing-git-object", "wrong-dependency",
    "premature-go", "missing-license",
])
def test_drift_cannot_silently_change_public_release(mutation):
    p, i, b = read()
    if mutation == "wrong-discover-pin":
        p["packages"]["host-discover"]["commit"] = "0"*40
    elif mutation == "wrong-root-tree":
        i["packages"]["root-control"]["tree_sha1"] = "a"*40
    elif mutation == "missing-issuer-module":
        del b["packages"]["host-discover"]["files"]["src/zog/host_discover/certificate_assignment.py"]
    elif mutation == "bad-file-sha":
        b["packages"]["host-install"]["files"]["pyproject.toml"] = "not-a-sha256"
    elif mutation == "missing-git-object":
        del i["packages"]["box-control"]["files"][next(iter(i["packages"]["box-control"]["files"]))]
    elif mutation == "wrong-dependency":
        p["beacon_dependency_claims"]["host-discover"][1] = "host-install==0.4.4"
    elif mutation == "premature-go":
        p["status"] = "APPROVED"
    elif mutation == "missing-license":
        del b["packages"]["host-install"]["files"]["LICENSES/BSD-3-Clause.txt"]
    with pytest.raises(AssertionError):
        validate(p, i, b)
