"""Ephemeral root-only import-tree attacks. Never modifies a native Host."""
import hashlib
import os
from pathlib import Path
import shutil
import tempfile

import pytest
from zog.host_deploy.gateway import graphics_attester_import as importer


@pytest.fixture
def installed(monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("ephemeral root-owned filesystem fixture only")
    root = Path(tempfile.mkdtemp(prefix="zog-import-boundary-", dir="/root"))
    root.chmod(0o700)
    binroot = root / "bin"
    binroot.mkdir(mode=0o700)
    exe = binroot / "python-immutable"
    exe.write_bytes(b"independently-pinned-installed-python")
    exe.chmod(0o500)
    importroot = root / "installed"
    importroot.mkdir(mode=0o700)
    roots = []
    for name in ("image-build", "build-record"):
        module = importroot / name
        module.mkdir(mode=0o555)
        (module / "module.py").write_text("SAFE=1\n")
        (module / "module.py").chmod(0o444)
        roots.append(str(module))
    monkeypatch.setattr(importer, "SNAPSHOT", str(importroot) + "/")
    def policy():
        return {
            "schema": importer.SCHEMA,
            "source_revision": "a"*40,
            "monthly_pin_identity": "sha256:"+"b"*64,
            "python": str(exe),
            "python_sha256": "sha256:"+hashlib.sha256(exe.read_bytes()).hexdigest(),
            "module_roots": roots,
            "tree_sha256": "sha256:"+hashlib.sha256(importer._canonical([
                [path, importer._inventory(path)] for path in roots
            ])).hexdigest(),
        }
    monkeypatch.setattr(importer, "_read_policy", policy)
    try:
        yield root, policy, roots
    finally:
        for path in roots:
            Path(path).chmod(0o700)
            for child in Path(path).iterdir():
                child.chmod(0o600) if not child.is_symlink() else None
        shutil.rmtree(root)


def test_valid_protected_import_and_ignored_file_injection(installed):
    root, policy, paths = installed
    assert importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)
    file = Path(paths[0]) / ".gitignored_shadow.py"
    Path(paths[0]).chmod(0o755)
    file.write_text("ATTACK=True\n")
    file.chmod(0o444)
    Path(paths[0]).chmod(0o555)
    with pytest.raises(importer.ImportBoundaryBlocked):
        importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)


def test_symlink_swap_inode_and_writable_ancestor_denied(installed):
    root, policy, paths = installed
    module = Path(paths[0])
    original = module / "module.py"
    module.chmod(0o755)
    original.rename(module / "replaced.py")
    (module / "module.py").symlink_to("replaced.py")
    module.chmod(0o555)
    with pytest.raises(importer.ImportBoundaryBlocked):
        importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)
    (module / "module.py").unlink()
    (module / "replaced.py").rename(original)
    assert importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)
    module.chmod(0o757)
    with pytest.raises(importer.ImportBoundaryBlocked):
        importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)


def test_interpreter_bytes_and_owner_protection(installed):
    root, policy, paths = installed
    exe = root / "bin/python-immutable"
    exe.chmod(0o700)
    exe.write_bytes(b"replaced")
    exe.chmod(0o500)
    with pytest.raises(importer.ImportBoundaryBlocked):
        importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)
    exe.chmod(0o522)
    with pytest.raises(importer.ImportBoundaryBlocked):
        importer.verify(source_revision="a"*40, monthly_pin_identity="sha256:"+"b"*64)
