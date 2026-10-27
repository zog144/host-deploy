"""Budget-directory preparation regression from #5 (source-only, no host writes).

The protected 2-GiB external pool creates owner-state/budget as an EMPTY,
0700, root-owned directory. The installer must consume exactly that directory
rather than trying to create it twice, and may not repair prior attempts.
"""
from pathlib import Path
from types import SimpleNamespace
import inspect
import stat

import pytest

from zog.host_deploy.gateway import fresh_native_owner as owner
from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate


def prepared(tmp_path, monkeypatch):
    pool = tmp_path / "accounting"
    state = pool / "owner-state"
    budget = state / "budget"
    budget.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(aggregate, "EXTERNAL_MOUNT", str(pool))
    monkeypatch.setattr(owner, "STATE", state)
    monkeypatch.setattr(owner, "BUDGET_DIR", budget)
    monkeypatch.setattr(owner.budget, "_protected_root", lambda p: Path(p))
    # CI runs as a nonroot actor. Substitute only the budget directory's
    # UID/GID readback; keep real filesystem inodes and directory contents.
    original_lstat = Path.lstat
    def protected_lstat(p):
        original = original_lstat(p)
        if p == budget:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_uid=0, st_gid=0, st_dev=original.st_dev,
                st_ino=original.st_ino)
        return original
    monkeypatch.setattr(Path, "lstat", protected_lstat)
    return pool, state, budget


def test_existing_prepared_budget_directory_is_consumed_not_created(
        tmp_path, monkeypatch):
    _, _, budget = prepared(tmp_path, monkeypatch)
    inode_before = budget.stat().st_ino
    assert owner._budget_directory_prepared(require_empty=True) == budget
    assert budget.stat().st_ino == inode_before
    assert list(budget.iterdir()) == []


def test_nonempty_budget_directory_requires_review_no_cleanup(
        tmp_path, monkeypatch):
    _, _, budget = prepared(tmp_path, monkeypatch)
    pending = budget / ("f" * 32 + ".json")
    pending.write_text('{"status":"uncertain"}')
    with pytest.raises(RuntimeError, match="existing/uncertain"):
        owner._budget_directory_prepared(require_empty=True)
    assert pending.read_text() == '{"status":"uncertain"}'
    assert owner._budget_directory_prepared(require_empty=False) == budget
    # Watch/recovery may inspect existing records; installer cannot replay.


def test_missing_budget_directory_does_not_autocreate(tmp_path, monkeypatch):
    _, _, budget = prepared(tmp_path, monkeypatch)
    budget.rmdir()
    with pytest.raises(FileNotFoundError):
        owner._budget_directory_prepared(require_empty=True)
    assert not budget.exists()


def test_foreign_dev_or_mode_are_not_trusted(tmp_path, monkeypatch):
    _, _, budget = prepared(tmp_path, monkeypatch)
    original = Path.lstat
    def wrong_device(p):
        value = original(p)
        if p == budget:
            return SimpleNamespace(**{
                **vars(value), "st_dev": value.st_dev + 1,
            })
        return value
    monkeypatch.setattr(Path, "lstat", wrong_device)
    with pytest.raises(PermissionError, match="not the bounded"):
        owner._budget_directory_prepared(require_empty=True)


def test_no_duplicate_mkdir_and_preflight_precedes_30gib_allocation():
    provision = inspect.getsource(aggregate.provision_external)
    prepare = inspect.getsource(owner.prepare_work)
    install = inspect.getsource(owner.install_approved)
    arm = inspect.getsource(owner.arm_approved)
    assert '"owner-state/budget"' in provision
    assert "_budget_directory_prepared(require_empty=True)" in prepare
    assert prepare.index("_budget_directory_prepared(require_empty=True)") < (
        prepare.index("quota.provision("))
    assert "_budget_directory_prepared(require_empty=True)" in install
    assert "_budget_directory_prepared(require_empty=True)" in arm
    assert "BUDGET_DIR.mkdir" not in prepare + install + arm
