#!/usr/bin/env python3
"""Offline review of exact public beacon companion checkouts.

Read only. Emits hashes for human/API compatibility review; never edits the
live beacon_sources.json or accepts a branch name as a release selector.
No network, AWS, privileged commands, private repository tokens or installs.
"""
from __future__ import annotations

import argparse
import tomllib
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

SCHEMA = "zog-host-deploy-public-companion-review-v1"
REPOS = {
    "host-identify": "zog144/host-identify",
    "host-discover": "zog144/host-discover",
    "host-install": "zog144/host-install",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")


class ReviewBlocked(ValueError):
    pass


def _git(root: Path, *args: str) -> str:
    command = subprocess.run(
        ["git", "-C", str(root), *args], check=False,
        capture_output=True, text=True, timeout=10,
    )
    if command.returncode:
        raise ReviewBlocked("local-public-checkout-unverifiable")
    return command.stdout.strip()


def _read_regular(root: Path, relative: str) -> bytes:
    # Never resolve source symlinks: exact canonical source paths only.
    if (not relative or relative.startswith("/") or "\\" in relative
            or any(p in ("", ".", "..") for p in relative.split("/"))):
        raise ReviewBlocked("unsafe-companion-source-path")
    candidate = root
    for item in relative.split("/")[:-1]:
        candidate /= item
        try:
            mode = candidate.lstat().st_mode
        except OSError:
            raise ReviewBlocked("missing-companion-source") from None
        if not stat.S_ISDIR(mode):
            raise ReviewBlocked("symlink-or-invalid-source-directory")
    path = candidate / relative.rsplit("/", 1)[-1]
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ReviewBlocked("symlink-or-invalid-source-file")
        return path.read_bytes()
    except OSError:
        raise ReviewBlocked("missing-companion-source") from None


def review(historical: dict, candidate: dict) -> dict:
    if (type(historical) is not dict or historical.get("schema") != 1
            or set(historical.get("packages", {})) != set(REPOS)):
        raise ReviewBlocked("historical-beacon-manifest-invalid")
    if (type(candidate) is not dict or candidate.get("schema") != SCHEMA
            or set(candidate.get("packages", {})) != set(REPOS)):
        raise ReviewBlocked("candidate-selection-invalid")
    reviews = {}
    for name, repo in sorted(REPOS.items()):
        selected = candidate["packages"][name]
        historic = historical["packages"][name]
        if (type(selected) is not dict
                or set(selected) != {"repository", "commit", "directory"}
                or selected["repository"] != repo
                or not isinstance(selected["commit"], str)
                or not SHA.fullmatch(selected["commit"])
                or type(selected["directory"]) is not str
                or not Path(selected["directory"]).is_absolute()
                or not isinstance(historic, dict)
                or historic.get("repository") != repo
                or not isinstance(historic.get("files"), dict)
                or not historic["files"]):
            raise ReviewBlocked("candidate-binding-invalid")
        root = Path(selected["directory"])
        if root.is_symlink() or not root.is_dir() or root.resolve() != root:
            raise ReviewBlocked("candidate-root-untrusted")
        if _git(root, "rev-parse", "--show-toplevel") != str(root):
            raise ReviewBlocked("candidate-not-checkout-root")
        if _git(root, "rev-parse", "HEAD") != selected["commit"]:
            raise ReviewBlocked("candidate-revision-mismatch")
        if _git(root, "status", "--porcelain", "--untracked-files=all"):
            raise ReviewBlocked("candidate-checkout-dirty")
        results = []
        for path, expected in sorted(historic["files"].items()):
            if type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ReviewBlocked("historical-file-digest-invalid")
            data = _read_regular(root, path)
            actual = hashlib.sha256(data).hexdigest()
            results.append({
                "path": path,
                "historical_sha256": expected,
                "candidate_sha256": actual,
                "byte_identical": actual == expected,
            })
        reviews[name] = {
            "repository": repo, "candidate_commit": selected["commit"],
            "historical_commit": historic["commit"],
            "matched_count": sum(x["byte_identical"] for x in results),
            "changed_count": sum(not x["byte_identical"] for x in results),
            "files": results,
            "validated_replacement": False,
            "blocker": "API, packaging, negative tests, native ownership and audit pending",
        }
    return {
        "schema": SCHEMA, "status": "UNAPPROVED-SOURCE-REVIEW",
        "note": "Never replace live beacon pins based only on this hash report.",
        "packages": reviews,
    }


def source_closure(historical: dict, candidate: dict) -> dict:
    """Inspect every runtime Python module and required package notice.

    Source review ONLY: the resulting hashes are not an approved beacon
    descriptor. This catches files newly imported after historical pinning.
    """
    review(historical, candidate)  # exact Git revision, clean-tree and old hash checks
    packages = {}
    for name, repo in sorted(REPOS.items()):
        root = Path(candidate["packages"][name]["directory"])
        prefix = "src/zog/" + name.replace("-", "_") + "/"
        tracked = _git(root, "ls-files", "--cached", "--full-name").splitlines()
        if any(not path or "\t" in path or "\r" in path or "\x00" in path
               for path in tracked):
            raise ReviewBlocked("unsafe-tracked-path")
        # Retain the *whole* first-party runtime package, not just modules
        # named in the historical file manifest. This is intentionally broad.
        runtime = [
            p for p in tracked if p.startswith(prefix)
            or p == "pyproject.toml"
            or p in ("LICENSE", "THIRD-PARTY-NOTICES.md", "README.md")
            or p.startswith("LICENSES/")
            or p.startswith("deployment/")
            or p.startswith("systemd/")
        ]
        if "pyproject.toml" not in runtime or not any(
                p.endswith("/__init__.py") and p.startswith(prefix)
                for p in runtime):
            raise ReviewBlocked("companion-package-closure-incomplete")
        project = tomllib.loads(_read_regular(root, "pyproject.toml").decode("utf-8"))
        metadata = project.get("project", {})
        for pattern in metadata.get("license-files", []):
            if not any(Path(p).match(pattern) for p in runtime):
                raise ReviewBlocked("companion-license-closure-incomplete")
        version = metadata.get("version")
        if not version:
            code = _read_regular(root, prefix + "__init__.py").decode("utf-8")
            match = re.search(r'(?m)^__version__\s*=\s*["\x27]([^"\x27]+)["\x27]', code)
            if match is None:
                raise ReviewBlocked("companion-version-unresolved")
            version = match.group(1)
        records = {
            path: hashlib.sha256(_read_regular(root, path)).hexdigest()
            for path in sorted(set(runtime))
        }
        old_paths = set(historical["packages"][name]["files"])
        packages[name] = {
            "repository": repo,
            "commit": candidate["packages"][name]["commit"],
            "version": version,
            "dependencies": metadata.get("dependencies", []),
            "files": records,
            "new_paths_not_in_historical": sorted(set(records) - old_paths),
            "historical_paths_missing": sorted(old_paths - set(records)),
            "approved": False,
        }
    conflicts = []
    for name, value in packages.items():
        for dependency in value["dependencies"]:
            for other in sorted(REPOS):
                pin = re.fullmatch(
                    re.escape(other) + r"==([0-9]+(?:\.[0-9]+)*)",
                    dependency.strip(), re.IGNORECASE,
                )
                if pin and pin.group(1) != packages[other]["version"]:
                    conflicts.append({
                        "consumer": name, "requirement": dependency,
                        "selected_package": other,
                        "selected_version": packages[other]["version"],
                    })
    return {
        "schema": "zog-host-deploy-beacon-closure-review-v1",
        "status": "BLOCKED-INCOMPATIBLE" if conflicts else "UNAPPROVED-SOURCE-REVIEW",
        "packages": packages, "dependency_conflicts": conflicts,
        "note": "Read-only complete runtime package scan, not a validated release.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-closure", action="store_true",
                        help="Include all tracked runtime modules, notices and version conflicts")
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("Refusing to overwrite retained review")
    try:
        old = json.loads(args.historical.read_text())
        candidates = json.loads(args.candidates.read_text())
        result = source_closure(old, candidates) if args.include_closure else review(old, candidates)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.error(f"Public companion review blocked: {error}")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
