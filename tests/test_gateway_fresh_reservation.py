"""Native-style backing allocation regression without loop mounts or EC2.

The original 2026-10-30 systemd 252 / XFS incident lost exactly 32 MiB of
the 2-GiB external image after ext4 creation.  This tests a newly-created
regular file on CI's real host filesystem and the permanent fail-closed
inspection contract. No post-mount or recovery reallocation is permitted.
"""
import inspect
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_quota_volume as quota
from zog.host_deploy.gateway import fresh_native_owner as owner


def _safely_emulate_root_inode_metadata(monkeypatch):
    """Only the UID readback is fake; file allocation and inode are genuine."""
    native_fstat = os.fstat

    def owned_fstat(fd):
        actual = native_fstat(fd)
        return SimpleNamespace(
            st_mode=actual.st_mode, st_uid=0, st_nlink=actual.st_nlink,
            st_dev=actual.st_dev, st_ino=actual.st_ino, st_size=actual.st_size,
            st_blocks=actual.st_blocks,
        )

    monkeypatch.setattr(quota.os, "geteuid", lambda: 0)
    monkeypatch.setattr(quota, "_private", lambda path, *, file=False: Path(path))
    monkeypatch.setattr(quota.os, "fstat", owned_fstat)


def test_new_pre_mount_completion_fills_real_sparse_holes_without_writing_data(
        tmp_path, monkeypatch):
    image = tmp_path / "new-ext4.img"
    size = 64 * 1024 * 1024
    with image.open("wb") as handle:
        handle.truncate(size)
    image.chmod(0o600)
    # Metadata is representative of already formatted ext4 bytes.
    with image.open("r+b") as handle:
        handle.seek(1024)
        handle.write(b"EXT4-SUPERBLOCK-TEST-PRESERVE")
        handle.flush()
        os.fsync(handle.fileno())
    before = image.stat()
    assert before.st_blocks * 512 < size
    original = (before.st_dev, before.st_ino)
    with monkeypatch.context() as patch:
        _safely_emulate_root_inode_metadata(patch)
        quota._complete_new_ext4_reservation(
            image, size, original, tmp_path / "unmounted")
    after = image.stat()
    assert (after.st_dev, after.st_ino) == original
    assert after.st_size == size
    assert after.st_blocks * 512 >= size
    with image.open("rb") as handle:
        handle.seek(1024)
        assert handle.read(len(b"EXT4-SUPERBLOCK-TEST-PRESERVE")) == (
            b"EXT4-SUPERBLOCK-TEST-PRESERVE")


def test_never_reallocate_a_mounted_or_substituted_image(tmp_path, monkeypatch):
    image = tmp_path / "new-ext4.img"
    image.write_bytes(b"x" * 8192)
    image.chmod(0o600)
    st = image.stat()
    original = (st.st_dev, st.st_ino)
    with monkeypatch.context() as patch:
        _safely_emulate_root_inode_metadata(patch)
        patch.setattr(quota.os.path, "ismount", lambda p: True)
        with pytest.raises(RuntimeError, match="after ext4 is mounted"):
            quota._complete_new_ext4_reservation(
                image, 8192, original, tmp_path / "mount")
    with monkeypatch.context() as patch:
        _safely_emulate_root_inode_metadata(patch)
        with pytest.raises(RuntimeError, match="identity changed"):
            quota._complete_new_ext4_reservation(
                image, 8192, (st.st_dev, st.st_ino + 1),
                tmp_path / "unmounted")
    assert image.read_bytes() == b"x" * 8192


def test_incomplete_new_allocation_is_still_hard_failure(tmp_path, monkeypatch):
    image = tmp_path / "sparse.img"
    size = 8 * 1024 * 1024
    with image.open("wb") as handle:
        handle.truncate(size)
    image.chmod(0o600)
    st = image.stat()
    with monkeypatch.context() as patch:
        _safely_emulate_root_inode_metadata(patch)
        patch.setattr(quota.os, "posix_fallocate", lambda fd, start, length: None)
        with pytest.raises(RuntimeError, match="incompletely reserved"):
            quota._complete_new_ext4_reservation(
                image, size, (st.st_dev, st.st_ino), tmp_path / "unmounted")
    assert image.stat().st_blocks * 512 < size


def test_eager_mke2fs_is_real_and_does_not_require_privileged_loop(tmp_path):
    mkfs = shutil.which("mkfs.ext4")
    if not mkfs:
        pytest.skip("e2fsprogs not installed in source environment")
    image = tmp_path / "small-eager-ext4.img"
    with image.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    subprocess.run([
        mkfs, "-F", "-m", "0", "-E",
        "nodiscard,lazy_itable_init=0,lazy_journal_init=0", str(image),
    ], check=True, capture_output=True, text=True, timeout=30)
    with image.open("rb") as handle:
        handle.seek(1024 + 0x38)
        assert handle.read(2) == bytes.fromhex("53ef")
    # Formatting alone is not reservation evidence: no omitted readback.


def test_creation_only_and_no_recovery_or_later_implicit_repair():
    new_build = inspect.getsource(quota.provision)
    new_external = inspect.getsource(aggregate.provision_external)
    for source in (new_build, new_external):
        assert '"nodiscard,lazy_itable_init=0,lazy_journal_init=0"' in source
        assert "_complete_new_ext4_reservation(" in source
        assert source.index("_complete_new_ext4_reservation(") < (
            source.index('"/usr/sbin/losetup"'))
        assert '"nosuid,nodev,nodiscard"' in source
        assert "_flush_new_ext4_metadata(" in source
    for source in (
        inspect.getsource(quota.reattach_after_boot),
        inspect.getsource(quota.inspect),
        inspect.getsource(aggregate.reattach_external_after_boot),
        inspect.getsource(aggregate.inspect_external_pool_native),
        inspect.getsource(owner.prepare_work),
    ):
        assert "_complete_new_ext4_reservation(" not in source
        assert "posix_fallocate" not in source
    for source in (
        inspect.getsource(quota.inspect),
        inspect.getsource(aggregate.inspect_external_pool_native),
    ):
        assert "st_blocks * 512 <" in source


def test_mismatched_creator_identity_and_mode_fail_closed(tmp_path, monkeypatch):
    image = tmp_path / "another-image"
    image.write_bytes(b"xx")
    image.chmod(0o600)
    st = image.stat()
    with pytest.raises(PermissionError, match="protected creator"):
        quota._complete_new_ext4_reservation(
            image, 2, (st.st_dev, st.st_ino), tmp_path / "mount")
    with monkeypatch.context() as patch:
        _safely_emulate_root_inode_metadata(patch)
        image.chmod(0o666)
        with pytest.raises(RuntimeError, match="identity changed"):
            quota._complete_new_ext4_reservation(
                image, 2, (st.st_dev, st.st_ino), tmp_path / "mount")


def test_later_32mib_hole_still_blocks_pool_readback(tmp_path, monkeypatch):
    """Native incident-shaped negative: later loss is NOT automatically fixed."""
    punch = shutil.which("fallocate")
    if not punch:
        pytest.skip("util-linux fallocate unavailable")
    image = tmp_path / "already-installed.img"
    size = 64 * 1024 * 1024
    fd = os.open(image, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        os.posix_fallocate(fd, 0, size)
        os.fsync(fd)
    finally:
        os.close(fd)
    assert image.stat().st_blocks * 512 >= size
    try:
        subprocess.run([punch, "--punch-hole", "--offset", "1048576",
                        "--length", str(32 * 1024 * 1024), str(image)],
                       check=True, capture_output=True, text=True, timeout=15)
    except subprocess.CalledProcessError:
        pytest.skip("runner host filesystem does not support punch-hole")
    assert image.stat().st_size == size
    assert image.stat().st_blocks * 512 < size
    monkeypatch.setattr(quota, "IMAGE", image)
    monkeypatch.setattr(quota, "BUILD_BYTES", size)
    monkeypatch.setattr(quota, "_private",
                        lambda path, *, file=False: Path(path))
    with pytest.raises(RuntimeError, match="sparse or not fully reserved"):
        quota.inspect()
    # No call to _complete_new_ext4_reservation during any pool inspection.
    assert image.stat().st_blocks * 512 < size
