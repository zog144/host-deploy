"""Retain the genuine first-Fonts October pin before changing executable source.

The copy path uses --retain on the actual historical checkout. The prepared-
but-never-created path uses --retain-from-provenance on authenticated original
Git objects, WITHOUT creating a historical source directory. This does not install
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
PROVENANCE_REPOSITORY = "zog144/image-build"


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
    return _validate_pin(raw)


def _validate_pin(raw):
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


def _provenance_object(repository, *, source_revision):
    """Read the genuine original Git blob from an independent bare object store.

    Never check out the old producer into the new public source root.
    A failed or unreachable object holds; we do not invent a monthly pin.
    """
    repository = Path(repository)
    if (not repository.is_absolute() or repository.is_symlink()
            or not repository.is_dir()):
        raise RuntimeError("original provenance Git object store missing or linked")
    def git(*args):
        done = subprocess.run(["git", "--git-dir=" + str(repository), *args],
                              capture_output=True, timeout=30, check=False)
        if done.returncode:
            raise RuntimeError("retained original Git provenance object unavailable")
        return done.stdout
    if git("rev-parse", "--is-bare-repository").strip() != b"true":
        raise RuntimeError("original pin provenance must be a bare Git object store")
    origin = git("remote", "get-url", "origin").decode("utf-8").strip()
    if origin not in ("https://github.com/" + PROVENANCE_REPOSITORY,
                      "https://github.com/" + PROVENANCE_REPOSITORY + ".git"):
        raise RuntimeError("original pin provenance repository differs")
    if git("rev-parse", "--verify", source_revision + "^{commit}").strip() != source_revision.encode():
        raise RuntimeError("original pin provenance revision differs")
    entry = git("ls-tree", source_revision, "--", RELATIVE_PIN).decode("utf-8").strip()
    if not entry.startswith("100644 blob ") or not entry.endswith("\t" + RELATIVE_PIN):
        raise RuntimeError("original pin provenance path is not a regular tracked file")
    blob = source_revision + ":" + RELATIVE_PIN
    length = git("cat-file", "-s", blob).strip()
    try:
        size = int(length)
    except ValueError as error:
        raise RuntimeError("original pin blob size unavailable") from error
    if size < 1 or size > 1024 * 1024:
        raise RuntimeError("original pin provenance blob exceeds size limit")
    return _validate_pin(git("show", blob))


def operation(action, *, filesystem_root=Path("/"), source_revision=ORIGINAL_SOURCE,
              provenance_git_dir=None):
    """Fixed paths; filesystem_root/source_revision are disposable-test fixtures only."""
    if action not in {"inspect", "retain", "retain-from-provenance"}:
        raise ValueError("unsupported retained original pin operation")
    root = Path(filesystem_root)
    if root == Path("/") and source_revision != ORIGINAL_SOURCE:
        raise RuntimeError("installed pin capture must use the original reviewed source")
    project = root / PROJECT.lstrip("/")
    source = project / "source"
    original = source / RELATIVE_PIN
    artifacts = project.joinpath(*ARTIFACT_PARTS)
    target = artifacts / PIN_SHA256
    if action == "retain-from-provenance":
        if provenance_git_dir is None:
            raise RuntimeError("retained original Git provenance store is required")
        _reject_linked_path(project, target)
        if not (project / "state").is_dir():
            raise RuntimeError("initialized Project state is missing")
        if source.is_symlink() or not source.is_dir():
            raise RuntimeError("real corrected producer checkout is missing")
        # The new source must be the reviewed identity-free producer, not a
        # fabricated historical checkout or unverified arbitrary directory.
        from . import image_build_lanes as lanes
        if (_git(source, "rev-parse", "--verify", "HEAD") !=
                lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION or
                _git(source, "status", "--porcelain=v1", "--untracked-files=all")):
            raise RuntimeError("corrected producer checkout differs")
        if original.exists() or original.is_symlink():
            raise RuntimeError("new public producer contains prohibited historical pin")
        raw = _provenance_object(provenance_git_dir, source_revision=source_revision)
    else:
        if provenance_git_dir is not None:
            raise RuntimeError("provenance source is only valid for explicit provenance retention")
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
    if action in {"retain", "retain-from-provenance"} and not already_present:
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
    # Inspect original source again so a checkout edit during staging cannot
    # silently produce an artifact derived from stale filesystem evidence.
    if action == "retain-from-provenance":
        if _provenance_object(provenance_git_dir, source_revision=source_revision) != raw:
            raise RuntimeError("original provenance object changed during pin retention")
    elif (_git(source, "rev-parse", "--verify", "HEAD") != source_revision
          or _git(source, "status", "--porcelain=v1", "--untracked-files=all")
          or _bytes(original) != raw):
        raise RuntimeError("original Fonts source changed during pin retention")
    return {
        "schema": SCHEMA,
        "action": action,
        "original_source_revision": source_revision,
        "pin_repository_path": RELATIVE_PIN,
        "pin_sha256": "sha256:" + PIN_SHA256,
        "artifact_path": str(target),
        "artifact_present": target.exists() and target.is_file() and not target.is_symlink(),
        "already_present": already_present,
        "acquisition_mode": "original-git-object" if action == "retain-from-provenance" else "existing-historical-checkout",
        "effective_uid": os.geteuid(),
        "effective_gid": os.getegid(),
        "compilation_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--retain", action="store_true",
                         help="capture original bytes from a genuinely copied historical Project")
    options.add_argument("--retain-from-provenance", action="store_true",
                         help="capture genuine original Git object without a historical Project")
    parser.add_argument("--provenance-git-dir", type=Path,
                        help="already fetched, authenticated bare Git image-build object store")
    args = parser.parse_args()
    action = ("retain-from-provenance" if args.retain_from_provenance else
              "retain" if args.retain else "inspect")
    if args.retain_from_provenance and args.provenance_git_dir is None:
        parser.error("--retain-from-provenance requires --provenance-git-dir")
    print(json.dumps(operation(action, provenance_git_dir=args.provenance_git_dir), sort_keys=True))


if __name__ == "__main__":
    main()
