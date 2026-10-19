"""Offline public companion revision review—no network or credentials."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_public_companions.py"
spec = importlib.util.spec_from_file_location("public_companion_review", SCRIPT)
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

def fixture(tmp_path):
    old, new = {"schema": 1, "packages": {}}, {"schema": reviewer.SCHEMA, "packages": {}}
    for name, repo in reviewer.REPOS.items():
        root = (tmp_path / name).resolve()
        root.mkdir()
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        git(root, "config", "user.email", "review@example.invalid")
        git(root, "config", "user.name", "Source review")
        (root / "pyproject.toml").write_text(name + "\n")
        git(root, "add", ".")
        git(root, "commit", "-qm", "test fixture")
        sha = git(root, "rev-parse", "HEAD")
        old["packages"][name] = {"repository": repo, "commit": "a"*40,
            "files": {"pyproject.toml": hashlib.sha256((name + "\n").encode()).hexdigest()}}
        new["packages"][name] = {"repository": repo, "commit": sha, "directory": str(root)}
    return old, new

def test_exact_hashes_are_still_unapproved(tmp_path):
    old, new = fixture(tmp_path)
    status = reviewer.review(old, new)
    assert status["status"] == "UNAPPROVED-SOURCE-REVIEW"
    assert all(row["matched_count"] == 1 and row["changed_count"] == 0
               and row["validated_replacement"] is False
               for row in status["packages"].values())

def test_changed_clean_source_is_reported_not_accepted(tmp_path):
    old, new = fixture(tmp_path)
    item = new["packages"]["host-install"]
    root = Path(item["directory"])
    (root / "pyproject.toml").write_text("different\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "different public code")
    item["commit"] = git(root, "rev-parse", "HEAD")
    status = reviewer.review(old, new)
    assert status["packages"]["host-install"]["changed_count"] == 1
    assert status["packages"]["host-install"]["validated_replacement"] is False

@pytest.mark.parametrize("condition", ["dirty", "wrong-revision", "foreign", "symlink", "traversal"])
def test_wrong_source_refuse(condition, tmp_path):
    old, new = fixture(tmp_path)
    selected = new["packages"]["host-identify"]
    root = Path(selected["directory"])
    if condition == "dirty":
        (root / "pyproject.toml").write_text("uncommitted\n")
    elif condition == "wrong-revision":
        selected["commit"] = "b"*40
    elif condition == "foreign":
        selected["repository"] = "unknown/source"
    elif condition == "symlink":
        (root / "pyproject.toml").unlink()
        (root / "target").write_text("content")
        (root / "pyproject.toml").symlink_to("target")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "replacement")
        selected["commit"] = git(root, "rev-parse", "HEAD")
    else:
        old["packages"]["host-identify"]["files"] = {"../escape": "a"*64}
    with pytest.raises(reviewer.ReviewBlocked):
        reviewer.review(old, new)

def test_missing_component_denied(tmp_path):
    old, new = fixture(tmp_path)
    del new["packages"]["host-discover"]
    with pytest.raises(reviewer.ReviewBlocked):
        reviewer.review(old, new)


def candidate_modules(tmp_path):
    old, new = fixture(tmp_path)
    for name, info in new["packages"].items():
        root = Path(info["directory"])
        module = root / "src" / "zog" / name.replace("-", "_")
        module.mkdir(parents=True)
        (module / "__init__.py").write_text('__version__ = "0.10.0"\n')
        for new_module in (
                ["certificate_assignment.py"] if name == "host-discover"
                else ["certificate_gate.py", "welcome_readiness.py",
                      "certificate_lifecycle.py"] if name == "host-install"
                else ["identity.py"]):
            (module / new_module).write_text("# newly imported public source\n")
        (root / "LICENSE").write_text("test fixture\n")
        (root / "LICENSES").mkdir()
        (root / "LICENSES/BSD-3-Clause.txt").write_text("test notice\n")
        deps = ['"host-install==0.4.4"'] if name == "host-discover" else []
        (root / "pyproject.toml").write_text(
            '[project]\nname = "' + name + '"\nversion = "0.10.0"\n'
            'license-files = ["LICENSE", "LICENSES/*.txt"]\n'
            'dependencies = [' + ", ".join(deps) + ']\n'
        )
        git(root, "add", ".")
        git(root, "commit", "-qm", "complete source module fixture")
        info["commit"] = git(root, "rev-parse", "HEAD")
    return old, new


def test_complete_module_and_license_closure_is_reported_without_approval(tmp_path):
    old, new = candidate_modules(tmp_path)
    status = reviewer.source_closure(old, new)
    assert status["status"] == "BLOCKED-INCOMPATIBLE"
    assert status["dependency_conflicts"] == [{
        "consumer": "host-discover", "requirement": "host-install==0.4.4",
        "selected_package": "host-install", "selected_version": "0.10.0",
    }]
    included = status["packages"]["host-discover"]["files"]
    assert "src/zog/host_discover/certificate_assignment.py" in included
    assert "LICENSES/BSD-3-Clause.txt" in included
    for module in ("certificate_gate", "welcome_readiness", "certificate_lifecycle"):
        assert ("src/zog/host_install/" + module + ".py") in (
            status["packages"]["host-install"]["files"]
        )
    assert not any(v["approved"] for v in status["packages"].values())


def test_missing_license_and_bad_version_do_not_create_valid_closure(tmp_path):
    old, new = candidate_modules(tmp_path)
    root = Path(new["packages"]["host-install"]["directory"])
    (root / "LICENSES/BSD-3-Clause.txt").unlink()
    git(root, "add", "-u")
    git(root, "commit", "-qm", "remove required license")
    new["packages"]["host-install"]["commit"] = git(root, "rev-parse", "HEAD")
    with pytest.raises(reviewer.ReviewBlocked, match="license-closure"):
        reviewer.source_closure(old, new)


def test_consistent_dependency_still_requires_separate_source_approval(tmp_path):
    old, new = candidate_modules(tmp_path)
    root = Path(new["packages"]["host-discover"]["directory"])
    source = root / "pyproject.toml"
    source.write_text(source.read_text().replace(
        "host-install==0.4.4", "host-install==0.10.0"
    ))
    git(root, "add", ".")
    git(root, "commit", "-qm", "aligned fixture dependency")
    new["packages"]["host-discover"]["commit"] = git(root, "rev-parse", "HEAD")
    status = reviewer.source_closure(old, new)
    assert status["status"] == "UNAPPROVED-SOURCE-REVIEW"
    assert status["dependency_conflicts"] == []
    assert status["packages"]["host-discover"]["approved"] is False
