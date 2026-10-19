"""Aggregate release metadata must not silently omit public CLI/services."""
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_zog_component_metadata_matches_build_source_entry_points_and_payload():
    component = json.loads((ROOT / "zog-component.json").read_text())
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert component["scripts"] == project["project"]["scripts"]
    package_data = project["tool"]["setuptools"]["package-data"]
    expected = sorted(package_data["zog.host_deploy"] + [
        "gateway/" + item for item in package_data["zog.host_deploy.gateway"]
    ])
    assert sorted(component["package_data"]) == expected
    assert component["version"] == "0.10.6"
    assert project["project"]["license"] == "BSD-3-Clause OR GPL-3.0-only"
