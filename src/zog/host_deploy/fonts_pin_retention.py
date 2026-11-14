"""Retain the genuine first-Fonts October pin before changing executable source.

Run the explicit --retain operation on the *copied* historical project, while
its original clean Git checkout is still in /source. This does not install
code, select a user, change the old source or authorize a compiler job.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

ORIGINAL_SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
PROJECT = "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
RELATIVE_PIN = "project/pins/2026-10-01/commit-pin.py"
PIN_SHA256 = "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
ARTIFACT_PARTS = ("state", "image-build", "build-record", "artifacts")
SCHEMA = "host-deploy-original-fonts-pin-retention-v1"


def _reject_linked_path(root, path):
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("project root absent or linked")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError("pin retention path contains a symlink")


def _git(source, *args):
    result = subprocess.run(
        ["git", "-C", str(source), *args], capture_output=True,
        text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise RuntimeError("historical Fonts Git checkout unavailable")
    return result.stdout.strip()


def _bytes(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > 1024 * 1024):
            raise RuntimeError("historical original pin is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(1024 * 1024 + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != PIN_SHA256:
        raise RuntimeError("retained original October pin digest mismatch")
    try:
        parsed = ast.literal_eval(raw.decode("utf-8"))
    except (ValueError, SyntaxError, UnicodeError, TypeError) as error:
        raise RuntimeError("invalid historical October pin data") from error
    if (not isinstance(parsed, dict) or parsed.get("schema") != 1
            or parsed.get("date") != "2026-10-01"
            or not isinstance(parsed.get("packages"), dict)
            or "monthly_identity" in parsed):
        raise RuntimeError("original monthly pin schema differs")
    return raw


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def operation(action, *, filesystem_root=Path("/"), source_revision=ORIGINAL_SOURCE):
    """Fixed paths; filesystem_root/source_revision are disposable-test fixtures only."""
    if action not in {"inspect", "retain"}:
        raise ValueError("unsupported retained original pin operation")
    root = Path(filesystem_root)
    if root == Path("/") and source_revision != ORIGINAL_SOURCE:
        raise RuntimeError("installed pin capture must use the original reviewed source")
    project = root / PROJECT.lstrip("/")
    source = project / "source"
    original = source / RELATIVE_PIN
    artifacts = project.joinpath(*ARTIFACT_PARTS)
    target = artifacts / PIN_SHA256
    _reject_linked_path(project, original)
    if not source.is_dir() or _git(source, "rev-parse", "--verify", "HEAD") != source_revision:
        raise RuntimeError("historical Fonts checkout revision differs")
    if _git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("historical Fonts checkout has uncommitted changes")
    raw = _bytes(original)
    already_present = False
    if target.exists() or target.is_symlink():
        _reject_linked_path(project, target)
        if _bytes(target) != raw:
            raise RuntimeError("existing retained pin artifact differs")
        already_present = True
    if action == "retain" and not already_present:
        # Only pre-existing Project state may receive the original immutable
        # bytes. Do not create new users, change source trees or chmod homes.
        if not (project / "state").is_dir():
            raise RuntimeError("copied historical Project state is missing")
        current = project
        for part in ARTIFACT_PARTS:
            current = current / part
            if current.is_symlink():
                raise RuntimeError("retained pin state path is linked")
            if not current.exists():
                current.mkdir(mode=0o700)
            if not current.is_dir():
                raise RuntimeError("retained pin state path is not a directory")
        fd, temporary = tempfile.mkstemp(prefix=".original-fonts-pin-", dir=artifacts)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError:
                if _bytes(target) != raw:
                    raise RuntimeError("racing retained pin artifact differs")
            _sync_directory(artifacts)
        finally:
            Path(temporary).unlink(missing_ok=True)
        _reject_linked_path(project, target)
        if _bytes(target) != raw:
            raise RuntimeError("retained pin changed after atomic publication")
    return {
        "schema": SCHEMA,
        "action": action,
        "original_source_revision": source_revision,
        "pin_repository_path": RELATIVE_PIN,
        "pin_sha256": "sha256:" + PIN_SHA256,
        "artifact_path": str(target),
        "artifact_present": target.exists() and target.is_file() and not target.is_symlink(),
        "already_present": already_present,
        "effective_uid": os.geteuid(),
        "effective_gid": os.getegid(),
        "compilation_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", action="store_true",
                        help="explicitly capture verified original bytes in copied Project state")
    args = parser.parse_args()
    print(json.dumps(operation("retain" if args.retain else "inspect"), sort_keys=True))


if __name__ == "__main__":
    main()
