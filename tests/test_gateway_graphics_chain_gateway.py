"""Isolated, non-AWS gateway tests for once-pinned graphical chain routing."""
import pytest

from zog.host_deploy.gateway import consumer
from zog.host_deploy.gateway import graphics_generation_chain as chain
from test_gateway_graphics_generation_chain import (
    scenario, evidence, FONTS, LANE,
)

REQ = "1" * 32
OTHER = "2" * 32
APPROVAL_DIGEST = "sha256:" + "e" * 64


def runner(tmp_path, monkeypatch, *, task=chain.TASKS[1], duplicate=False,
           dispatch=None):
    policy, base, receipt = scenario()
    xcb = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[0],
        previous_catalogue=base, previous_receipt=receipt,
        accepted_generation=evidence(policy, chain.TASKS[0], base, FONTS))
    cat = xcb["catalogue"]
    digest = xcb["catalogue_sha256"]
    root = tmp_path / "requests"
    (root / REQ).mkdir(parents=True)
    if duplicate:
        (root / OTHER).mkdir()
    def record(key):
        return {
            "request": {"operation": "build.submit",
                        "parameters": {"task": task, "lane": LANE}},
            "states": {"admission": "admitted"},
        }
    monkeypatch.setattr(consumer, "load_request", lambda _root, key: record(key))
    monkeypatch.setattr(consumer, "load_dispatch",
                        lambda _root, key: dispatch if key == REQ else None)
    monkeypatch.setattr(consumer, "_reserve_reviewed_advance",
                        lambda *_: True)
    monkeypatch.setattr(
        chain, "load_installed_step",
        lambda selected, *, policy_sha256: (
            (cat, digest) if selected == chain.TASKS[1] else
            (base, chain._hash(base))))
    prepared = []
    monkeypatch.setattr(
        consumer, "prepare_image_build_dispatch",
        lambda *args, **kwargs: prepared.append((args, kwargs)))
    invoked = []
    monkeypatch.setattr(consumer, "advance_generic",
                        lambda *args, **kwargs: invoked.append(args))
    monkeypatch.setattr(consumer, "generic_status",
                        lambda *args: {"phase": "active"})
    obj = consumer.GatewayConsumer.__new__(consumer.GatewayConsumer)
    obj.state_directory = tmp_path
    obj.approved_generic_catalogue = base
    obj.approved_catalogue_identity = chain._hash(base)
    obj.approved_catalogue_path = None
    obj.approved_graphical_chain_policy_sha256 = APPROVAL_DIGEST
    return obj, xcb, prepared, invoked


def test_supervisor_picks_installed_successor_and_freezes_its_digest(
        tmp_path, monkeypatch):
    obj, xcb, prepared, invoked = runner(tmp_path, monkeypatch)
    result = obj._advance_one_reviewed()
    assert result == {"request_id": REQ, "action": "prepared"}
    assert len(prepared) == 1
    args, kw = prepared[0]
    assert args == (tmp_path, REQ)
    assert kw["task_catalogue"] == xcb["catalogue"]
    assert kw["task_catalogue_identity"] == xcb["catalogue_sha256"]
    assert not invoked


def test_original_frozen_successor_binding_advances_without_repin(
        tmp_path, monkeypatch):
    state = {"phase": "prepared", "binding": {
        "task_catalogue_identity": "dummy"}}
    obj, xcb, prepared, invoked = runner(
        tmp_path, monkeypatch, dispatch=state)
    state["binding"]["task_catalogue_identity"] = xcb["catalogue_sha256"]
    result = obj._advance_one_reviewed()
    assert result == {"request_id": REQ, "action": "advanced"}
    assert invoked == [(tmp_path, REQ)]
    assert prepared == []


def test_changed_successor_binding_never_advances(tmp_path, monkeypatch):
    state = {"phase": "prepared", "binding": {
        "task_catalogue_identity": "sha256:" + "0"*64}}
    obj, xcb, prepared, invoked = runner(
        tmp_path, monkeypatch, dispatch=state)
    with pytest.raises(RuntimeError, match="changed since dispatch"):
        obj._advance_one_reviewed()
    assert not invoked and not prepared


def test_duplicate_same_step_blocks_new_dispatch(tmp_path, monkeypatch):
    obj, xcb, prepared, invoked = runner(
        tmp_path, monkeypatch, duplicate=True)
    with pytest.raises(RuntimeError, match="already admitted"):
        obj._advance_one_reviewed()
    assert not prepared and not invoked


def test_missing_verified_successor_blocks_before_preparation(
        tmp_path, monkeypatch):
    obj, xcb, prepared, invoked = runner(tmp_path, monkeypatch)
    def missing(*args, **kwargs):
        raise chain.ChainBlocked("no native accepted predecessor")
    monkeypatch.setattr(chain, "load_installed_step", missing)
    with pytest.raises(chain.ChainBlocked):
        obj._advance_one_reviewed()
    assert not prepared and not invoked


def test_nonchain_default_catalogue_stays_unchanged(tmp_path, monkeypatch):
    obj, xcb, prepared, invoked = runner(
        tmp_path, monkeypatch, task=chain.TASKS[0])
    obj.approved_graphical_chain_policy_sha256 = None
    result = obj._advance_one_reviewed()
    assert result["action"] == "prepared"
    assert prepared[0][1]["task_catalogue"] == obj.approved_generic_catalogue
    assert prepared[0][1]["task_catalogue_identity"] == obj.approved_catalogue_identity
