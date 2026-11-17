#!/usr/bin/env python3
"""Generate or verify the three explicit, review-pending beacon candidate source pins.

The public publisher/index remain a historical release selection. This tool
only covers the candidate beacon-source tree, using exact clean Git checkouts
under one explicit --source directory. No network, AWS, credentials or install.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tomllib

COMMITS = {
    "host-discover": "a6f3f402cee87eb7079d94c7eb36474930d45444",
    "host-identify": "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b",
    "host-install": "71643eef03739749c7c272f7c6be23d7063a51d8",
}
VERSIONS = {
    "host-discover": "0.4.14",
    "host-identify": "0.3.5",
    "host-install": "0.14.9",
}
DEPENDENCIES = {
    "host-discover": ["host-identify==0.3.5", "host-install==0.14.9"],
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


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True,
        capture_output=True, timeout=20, check=False,
    )
    if result.returncode:
        raise ValueError("exact candidate Git checkout cannot be inspected")
    return result.stdout.strip()


def checked_file(root, relative):
    if (not relative or relative.startswith("/")
            or any(part in ("", ".", "..") for part in relative.split("/"))
            or "\\" in relative):
        raise ValueError("unsafe candidate path")
    current = root
    for part in relative.split("/")[:-1]:
        current = current / part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("symlink or unsafe candidate parent")
    leaf = current / relative.split("/")[-1]
    observed = leaf.lstat()
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
        raise ValueError("nonregular, linked or symlink candidate file")
    return leaf.read_bytes()


def selected_paths(name, root):
    prefix = "src/zog/" + name.replace("-", "_") + "/"
    listing = git(root, "ls-files", "--stage").splitlines()
    selected = []
    for line in listing:
        match = re.fullmatch(r"(100644|100755|120000) ([0-9a-f]{40}) 0\t(.+)", line)
        if match is None:
            raise ValueError("invalid tracked Git file entry")
        mode, _, path = match.groups()
        if mode == "120000":
            if path.startswith(prefix) or path in COMMON or path.startswith(
                    ("LICENSES/", "deployment/", "systemd/")):
                raise ValueError("candidate source closure includes a symlink")
            continue
        if (path.startswith(prefix) or path in COMMON
                or path.startswith(("LICENSES/", "deployment/", "systemd/"))):
            selected.append(path)
    if not REQUIRED[name] | COMMON <= set(selected):
        raise ValueError("candidate missing required runtime/license files")
    return sorted(selected)


def candidate(source):
    source = Path(source).absolute()
    if source.is_symlink() or not source.is_dir():
        raise ValueError("explicit candidate source directory unavailable")
    packages = {}
    for name, revision in COMMITS.items():
        root = source / name
        if (root.is_symlink() or not root.is_dir()
                or root.resolve() != root
                or git(root, "rev-parse", "--show-toplevel") != str(root)
                or git(root, "rev-parse", "HEAD") != revision
                or git(root, "status", "--porcelain", "--untracked-files=all")):
            raise ValueError("candidate checkout revision or cleanliness mismatch: " + name)
        paths = selected_paths(name, root)
        pyproject = tomllib.loads(checked_file(root, "pyproject.toml").decode())
        project = pyproject.get("project", {})
        version = project.get("version")
        if not version:
            text = checked_file(root, "src/zog/" + name.replace("-", "_") +
                                "/__init__.py").decode()
            found = re.search(r'(?m)^__version__\s*=\s*["\x27]([^"\x27]+)["\x27]', text)
            if found is None:
                raise ValueError("candidate version unresolved")
            version = found.group(1)
        if version != VERSIONS[name]:
            raise ValueError("selected candidate version mismatch: " + name)
        dependencies = project.get("dependencies", [])
        if (type(dependencies) is not list
                or any(type(item) is not str for item in dependencies)):
            raise ValueError("malformed candidate dependencies")
        for dep in DEPENDENCIES.get(name, []):
            if dep not in dependencies:
                raise ValueError("selected candidate dependency mismatch: " + dep)
        for dep in dependencies:
            for selected, expected_version in VERSIONS.items():
                m = re.fullmatch(re.escape(selected) + r"==([0-9.]+)", dep)
                if m and m.group(1) != expected_version:
                    raise ValueError("candidate dependency conflicts with selection")
        packages[name] = {
            "repository": "zog144/" + name,
            "commit": revision,
            "version": version,
            "dependencies": dependencies,
            "files": {p: hashlib.sha256(checked_file(root, p)).hexdigest()
                      for p in paths},
        }
    return {"schema": 1, "packages": packages}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    found = candidate(args.source)
    if args.verify:
        recorded = json.loads(args.verify.read_text())
        if recorded != found:
            raise SystemExit("candidate beacon descriptor differs from exact source bytes")
        print("BEACON_CANDIDATE_VERIFIED " + " ".join(
            name + "=" + COMMITS[name] for name in sorted(COMMITS)))
    else:
        raw = json.dumps(found, sort_keys=True, separators=(",", ":"))
        # Print bounded *plain JSON* chunks, so the exact public inventory
        # can be reviewed without artifact extraction or local Git access.
        for number, offset in enumerate(range(0, len(raw), 850)):
            print("BEACON_CANDIDATE_JSON_PART %04d %s" % (
                number, raw[offset:offset + 850]))


if __name__ == "__main__":
    main()
