"""Regression coverage for the aggregate Zog namespace layout."""
from importlib import resources
from pathlib import Path
import re

from zog import host_deploy
from zog.host_deploy.cli import main


def test_canonical_namespace_version_and_entry_point():
    assert host_deploy.__name__ == "zog.host_deploy"
    assert host_deploy.__version__ == "0.10.6"
    assert callable(main)


def test_runtime_package_data_is_available():
    package = resources.files("zog.host_deploy")
    assert package.joinpath("beacon_sources.json").is_file()
    assert package.joinpath("beacon_installation").joinpath("requirements-security-tested.txt").is_file()
    gateway = resources.files("zog.host_deploy.gateway")
    assert gateway.joinpath("host-deploy-gateway.service").is_file()


def test_legacy_top_level_package_does_not_return():
    repository = Path(__file__).resolve().parents[1]
    assert not (repository / "host_deploy").exists()
    assert not (repository / "src" / "zog" / "__init__.py").exists()
    legacy = re.compile(r"(?m)^\s*(?:from|import)\s+host_deploy\b|[\"']host_deploy\.")
    for base in (repository / "src", repository / "tests"):
        for path in base.rglob("*.py"):
            if path == Path(__file__):
                continue
            assert not legacy.search(path.read_text()), path
    metadata = (repository / "pyproject.toml").read_text()
    assert '"host_deploy.' not in metadata
    assert "'host_deploy." not in metadata
