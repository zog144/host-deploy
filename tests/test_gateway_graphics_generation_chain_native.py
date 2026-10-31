"""Ephemeral root-only chain publication. Never uses a real accepted generation.

All authenticated producer and Host decisions here are TEST DOUBLES.
This does not exercise native admission, real compiler, SSM or AWS.
"""
import json
import os
import fcntl
from contextlib import contextmanager
from pathlib import Path
import shutil
import stat
import tempfile

import pytest

from zog.host_deploy.gateway import graphics_generation_chain as chain
from zog.host_deploy.gateway import graphics_catalogue_owner as first
from zog.host_deploy.gateway import task_catalogue
from test_gateway_graphics_generation_chain import scenario, evidence, FONTS, XCB


@pytest.fixture
def protected_chain(monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root-only ephemeral filesystem test")
    root = Path(tempfile.mkdtemp(prefix="zog-graphical-test-", dir="/root"))
    root.chmod(0o700)
    store = root / "owner-state"
    store.mkdir(mode=0o700)
    old = (first.CATALOGUE, first.RECEIPT)
    files = {
        chain.TASKS[1]: (store / "xcb-catalogue", store / "xcb-receipt"),
        chain.TASKS[2]: (store / "x11-catalogue", store / "x11-receipt"),
    }
    monkeypatch.setattr(chain, "STORE", store)
    monkeypatch.setattr(chain, "POLICY", store / "policy")
    monkeypatch.setattr(chain, "FILES", files)
    monkeypatch.setattr(first, "CATALOGUE", store / "fonts-catalogue")
    monkeypatch.setattr(first, "RECEIPT", store / "fonts-receipt")
    monkeypatch.setattr(chain, "first", first)
    # Ephemeral /root-only owner-fencing fixture, never installed native state.
    from zog.host_deploy.gateway import fresh_canary_owner, fresh_native_owner
    monkeypatch.setattr(fresh_native_owner, "_boot", lambda: "fixture-boot")
    @contextmanager
    def same_worker_claim_lock(_owner):
        lock = os.open(store / "native-admission.lock",
                       os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
    monkeypatch.setattr(fresh_canary_owner, "locked", same_worker_claim_lock)
    from zog.host_deploy.gateway import fresh_quota_volume, fresh_aggregate_disk
    monkeypatch.setattr(fresh_quota_volume, "inspect",
                        lambda: {"capacity_bytes": 30*1024**3 - 4096})
    monkeypatch.setattr(fresh_aggregate_disk, "inspect_external_pool_native",
                        lambda: {"limit_bytes": 2*1024**3 - 4096,
                                 "mount_verified": True,
                                 "allocation_verified": True,
                                 "budget_scope": fresh_aggregate_disk.BUDGET_SCOPE})
    policy, catalogue, receipt = scenario()
    for path, item in (
            (chain.POLICY, policy), (first.CATALOGUE, catalogue),
            (first.RECEIPT, receipt)):
        path.write_bytes(chain._canonical(item))
        path.chmod(0o600)
    try:
        yield policy, catalogue, receipt, files, store
    finally:
        # Do not retain any tested fake Host/generation as native evidence.
        shutil.rmtree(root)


@pytest.mark.skipif(os.geteuid() != 0, reason="privileged disposable-only test")
def test_fixed_policy_promotes_one_generation_per_stage(protected_chain):
    policy, fonts, fonts_receipt, files, store = protected_chain
    digest = chain._hash(policy)
    initially, init_digest = chain.load_installed_step(
        chain.TASKS[0], policy_sha256=digest)
    assert initially == fonts and init_digest == chain._hash(fonts)
    seen = []

    def owner(actual):
        assert actual == policy
        seen.append("native-owner")
        return True

    def previous(task, cat_sha, selected):
        seen.append((task, cat_sha, selected))
        previous_cat = task_catalogue.load(
            first.CATALOGUE if task == chain.TASKS[0] else files[task][0],
            require_root_owned=True)[0]
        return evidence(policy, task, previous_cat,
                        FONTS if task == chain.TASKS[0] else XCB,
                        request_id=("1" if task == chain.TASKS[0] else "6")*32)

    first_step = chain.install_next_native(
        previous_task=chain.TASKS[0],
        attest_native_owner=owner,
        attest_accepted_predecessor=previous)
    assert first_step["task"] == chain.TASKS[1]
    assert first_step["selection_generation_id"] == policy["first_base_generation_id"]
    assert first_step["graphical_predecessor_generation_id"] == FONTS
    snapshot, verified_digest = chain.load_installed_step(
        chain.TASKS[1], policy_sha256=digest)
    assert verified_digest == first_step["catalogue_sha256"]
    assert snapshot["tasks"][chain.TASKS[1]]["arguments"]["selection"] == policy["first_base_generation_id"]
    assert snapshot["tasks"][chain.TASKS[1]]["arguments"]["graphical_predecessor"] == FONTS
    with pytest.raises(chain.ChainBlocked):
        chain.install_next_native(
            previous_task=chain.TASKS[0],
            attest_native_owner=owner,
            attest_accepted_predecessor=previous)

    second_step = chain.install_next_native(
        previous_task=chain.TASKS[1],
        attest_native_owner=owner,
        attest_accepted_predecessor=previous)
    assert second_step["task"] == chain.TASKS[2]
    assert second_step["selection_generation_id"] == policy["first_base_generation_id"]
    assert second_step["graphical_predecessor_generation_id"] == XCB
    final, final_digest = chain.load_installed_step(
        chain.TASKS[2], policy_sha256=digest)
    assert final_digest == second_step["catalogue_sha256"]
    assert set(final["tasks"]) == {chain.TASKS[2]}
    for p in [*files[chain.TASKS[1]], *files[chain.TASKS[2]]]:
        st = p.lstat()
        assert st.st_uid == 0 and st.st_nlink == 1
        assert stat.S_IMODE(st.st_mode) == 0o600
    assert seen[0] == "native-owner"


@pytest.mark.skipif(os.geteuid() != 0, reason="privileged disposable-only test")
def test_partial_next_file_is_not_retried_or_replaced(protected_chain):
    p, fonts, receipt, files, store = protected_chain
    dest = files[chain.TASKS[1]][0]
    dest.write_bytes(b"interrupted-original")
    dest.chmod(0o600)
    original = dest.read_bytes()
    visited = []
    with pytest.raises(chain.ChainBlocked):
        chain.install_next_native(
            previous_task=chain.TASKS[0],
            attest_native_owner=lambda _: visited.append("owner") or True,
            attest_accepted_predecessor=lambda *args: pytest.fail(
                "unexpected second accepted-generation attestation"))
    assert dest.read_bytes() == original
    assert not files[chain.TASKS[1]][1].exists()
    assert visited == ["owner"]


@pytest.mark.skipif(os.geteuid() != 0, reason="privileged disposable-only test")
def test_wrong_policy_hash_denied_before_stage_read(protected_chain):
    with pytest.raises(chain.ChainBlocked):
        chain.load_installed_step(chain.TASKS[0],
                                  policy_sha256="sha256:"+"0"*64)
