"""Protected gateway stage-once ledger; no SQS/SSM or native compilation."""
import json
import os
from pathlib import Path

import pytest

from zog.host_deploy.gateway import graphics_stage_once as once
from zog.host_deploy.gateway import graphics_generation_chain as chain


def test_distinct_request_cannot_replay_graphical_stage(tmp_path, monkeypatch):
    current = {"request": "1" * 32}
    def request(_root, request_id):
        return {
            "request": {"operation": "build.submit",
                        "parameters": {"task": chain.TASKS[1], "lane": "graphics"}},
            "states": {"admission": "admitted"},
        }
    monkeypatch.setattr(once, "load_request", request)
    binding = {
        "lane": "graphics", "task": {"lane": "graphics"},
        "task_catalogue_identity": "sha256:" + "a" * 64,
    }
    original = "1" * 32
    once.reserve(tmp_path, original, binding)
    path = tmp_path / "graphical-stage-once" / ("graphics--" + chain.TASKS[1] + ".json")
    assert path.exists()
    assert json.loads(path.read_text())["request_id"] == original
    once.reserve(tmp_path, original, binding)  # same original reconciliation
    with pytest.raises(once.StageReplayBlocked):
        once.reserve(tmp_path, "2" * 32, binding)
    with pytest.raises(once.StageReplayBlocked):
        once.reserve(tmp_path, original, {**binding,
            "task_catalogue_identity": "sha256:" + "b" * 64})
    assert json.loads(path.read_text())["request_id"] == original


def test_corrupt_partial_or_symlink_never_replayed(tmp_path, monkeypatch):
    monkeypatch.setattr(once, "load_request", lambda _root, request_id: {
        "request": {"operation": "build.submit",
                    "parameters": {"task": chain.TASKS[0], "lane": "graphics"}},
        "states": {"admission": "admitted"},
    })
    b = {
        "lane": "graphics", "task": {"lane": "graphics"},
        "task_catalogue_identity": "sha256:" + "c" * 64,
    }
    root = tmp_path / "graphical-stage-once"
    root.mkdir(mode=0o700)
    path = root / ("graphics--" + chain.TASKS[0] + ".json")
    path.write_bytes(b"partial")
    path.chmod(0o600)
    with pytest.raises(once.StageReplayBlocked):
        once.reserve(tmp_path, "3" * 32, b)
    assert path.read_bytes() == b"partial"
    path.unlink()
    path.symlink_to(tmp_path / "somewhere")
    with pytest.raises(once.StageReplayBlocked):
        once.reserve(tmp_path, "3" * 32, b)


def test_other_generic_task_unaffected(tmp_path, monkeypatch):
    monkeypatch.setattr(once, "load_request", lambda _root, request_id: {
        "request": {"operation": "build.submit",
                    "parameters": {"task": "xcb-support-image-v1", "lane": "graphics"}},
        "states": {"admission": "admitted"},
    })
    once.reserve(tmp_path, "4"*32, {"task": {}, "lane": "graphics"})
    assert not (tmp_path / "graphical-stage-once").exists()
