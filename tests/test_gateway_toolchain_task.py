"""Fail-closed protected typed-toolchain admission and provenance tests."""
import copy
import json

import pytest

from zog.host_deploy.gateway import toolchain_task
from zog.host_deploy.gateway.protocol import validate_request, RequestProtocolError


def definition():
    return {
        "contract": toolchain_task.CONTRACT,
        "task": {
            "name": toolchain_task.TASK_NAME,
            "source_repository": "zog144/image-build",
            "source_revision": toolchain_task.PRODUCER_REVISION,
            "lane": "compiler",
            "lane_owner": "compiler",
            "seed_generation": "a" * 64,
            "monthly_pin_repository_path": "project/pins/2026-10-01/commit-pin.py",
            "monthly_pin_identity": "sha256:" + "b" * 64,
            "pin_date": "2026-10-01",
            "specification_identity": "sha256:" + "c" * 64,
        },
    }


def test_exact_protected_toolchain_task_and_digest(tmp_path):
    value = definition()
    assert toolchain_task.validate(value) == value
    p = tmp_path / "approved.json"
    p.write_text(json.dumps(value))
    loaded, digest = toolchain_task.load(p)
    assert loaded == value and len(digest) == 71
    assert toolchain_task.select(
        value, name=toolchain_task.TASK_NAME,
        repository="zog144/image-build",
        revision=toolchain_task.PRODUCER_REVISION,
        lane="compiler", lane_owner="compiler",
        monthly_pin_repository_path=value["task"]["monthly_pin_repository_path"],
        monthly_pin_identity=value["task"]["monthly_pin_identity"],
    ) == value["task"]
    with pytest.raises(toolchain_task.ToolchainTaskError):
        toolchain_task.select(
            value, name=toolchain_task.TASK_NAME,
            repository="zog144/image-build",
            revision=toolchain_task.PRODUCER_REVISION,
            lane="wrong", lane_owner="compiler",
            monthly_pin_repository_path=value["task"]["monthly_pin_repository_path"],
            monthly_pin_identity=value["task"]["monthly_pin_identity"],
        )


@pytest.mark.parametrize("key,change", [
    ("source_revision", "d" * 40),
    ("seed_generation", "../seed"),
    ("lane_owner", "other"),
    ("specification_identity", "not-a-sha"),
    ("monthly_pin_identity", "sha256:" + "0" * 63),
])
def test_invalid_task_rejected(key, change):
    value = definition()
    value["task"][key] = change
    with pytest.raises(toolchain_task.ToolchainTaskError):
        toolchain_task.validate(value)


def test_duplicate_and_symlink_rejected(tmp_path):
    with pytest.raises(toolchain_task.ToolchainTaskError):
        toolchain_task.loads('{"contract":"x","contract":"x","task":{}}')
    target = tmp_path / "task.json"
    target.write_text(json.dumps(definition()))
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(toolchain_task.ToolchainTaskError):
        toolchain_task.load(alias)


def test_protocol_only_accepts_reviewed_typed_selector():
    req = {
        "schema": 1, "request_id": "a" * 32,
        "workspace_id": "b" * 32, "operation": "toolchain.submit",
        "origin": {"repository": "zog144/host-deploy",
                   "issue_number": 123, "trigger_actor": "operator"},
        "parameters": {"lane": "compiler", "task": toolchain_task.TASK_NAME},
        "source": {"repository": "zog144/image-build",
                   "commit": toolchain_task.PRODUCER_REVISION},
    }
    assert validate_request(req) == req
    bad = copy.deepcopy(req)
    bad["parameters"]["seed_generation"] = "0" * 64
    with pytest.raises(RequestProtocolError):
        validate_request(bad)
    bad = copy.deepcopy(req)
    bad["parameters"]["task"] = "arbitrary-compiler"
    with pytest.raises(RequestProtocolError):
        validate_request(bad)
    bad = copy.deepcopy(req)
    bad["operation"] = "toolchain.inspect"
    bad.pop("source")
    bad["parameters"] = {"lane": "compiler", "operation_id": "c" * 32}
    assert validate_request(bad) == bad
    bad["operation"] = "toolchain.resume"
    assert validate_request(bad) == bad
