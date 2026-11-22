"""Exact source-only SSM -> Project-current -> image-build -> box-control identity audit.

These are immutable companion source checkouts in the focused CI job. No
request is sent or resumed; the historical schema-3 UID-selected lane is not
the normal Project-current path being audited.
"""
import ast
import copy
import json
import math
from pathlib import Path, PurePosixPath
import types

import pytest

from zog.host_deploy import fonts_lane_runtime


REPO = Path(__file__).resolve().parents[1]
PROJECT_SOURCE = REPO / "companions/host-deploy-project-current/src/zog/host_deploy/gateway/project_current.py"
PRODUCER_SOURCE = REPO / "companions/image-build-project-current/src/zog/image_build/box_control_adapter.py"
BOX_PROTOCOL = REPO / "companions/box-control/box-control/src/zog/box_control/build_protocol.py"
ROOT_PROTOCOL = REPO / "companions/root-control/src/zog/root_control/build.py"

IDENTITY_FIELDS = {
    "execution_identity", "execution_user_id", "execution_group_id",
    "build_uid", "build_gid", "uid", "gid", "user", "group",
    "User", "Group", "run_as", "owner_uid", "owner_gid",
}


def _source(path):
    if not path.is_file():
        pytest.skip("exact companion source checkout not provided outside GitHub CI")
    return ast.parse(path.read_text())


def _function(tree, name):
    result = [node for node in tree.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name == name]
    assert len(result) == 1, name
    return result[0]


def _executable_functions(path, names, *, globals_dict):
    tree = _source(path)
    nodes = [_function(tree, n) for n in names]
    namespace = dict(globals_dict)
    exec(compile(ast.fix_missing_locations(
        ast.Module(body=nodes, type_ignores=[])), str(path), "exec"), namespace)
    return namespace


def _dict_call_keywords(assignment):
    assert isinstance(assignment, ast.Call)
    assert isinstance(assignment.func, ast.Name) and assignment.func.id == "dict"
    return {item.arg for item in assignment.keywords if item.arg is not None}


def _local_assignment(method, name):
    matches = [
        node.value for node in ast.walk(method)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    assert len(matches) == 1, name
    return matches[0]


def test_normal_ssm_project_current_request_has_no_identity_selector():
    scope = _executable_functions(
        PROJECT_SOURCE, ["_template"],
        globals_dict={
            "REMOTE_SCHEMA": "image-build-remote-operation-v1",
            "REVIEWED_IMAGE_TASKS": {
                "fonts": {"targets": ("libpng-final", "freetype-final", "fontconfig-final")}
            }, "TASK": "fonts",
        })
    request = scope["_template"]("a" * 32)
    assert request == {
        "schema": "image-build-remote-operation-v1",
        "operation_id": "a" * 32, "operation": "pipeline.submit",
        "source": {"repository": "zog144/image-build"},
        "arguments": {
            "mode": "image",
            "targets": ["libpng-final", "freetype-final", "fontconfig-final"],
        },
    }
    assert not IDENTITY_FIELDS.intersection(request)
    assert not IDENTITY_FIELDS.intersection(request["arguments"])
    # The Project-current producer invocation is not a UID/GID-selecting
    # wrapper. The selected Project chooses its source, not another identity.
    project_tree = _source(PROJECT_SOURCE)
    method = _function(project_tree, "remote_script")
    assert "execution_identity" not in ast.unparse(method)
    assert "execution_user_id" not in ast.unparse(method)
    assert "execution_group_id" not in ast.unparse(method)


def test_producer_box_control_registration_and_build_wire_are_identity_free():
    tree = _source(PRODUCER_SOURCE)
    adapter = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef)
                   and node.name == "BoxControlExecutionAdapter")
    method = next(node for node in adapter.body
                  if isinstance(node, ast.FunctionDef)
                  and node.name == "execute_for_attempt")
    registration = _dict_call_keywords(_local_assignment(method, "registration"))
    assert registration == {
        "prepared_root", "source_directory", "output_directory", "input_manifest_id",
    }
    arguments = _dict_call_keywords(_local_assignment(method, "arguments"))
    assert arguments == {
        "build_root_id", "source_workspace_id", "output_workspace_id",
        "command", "environment", "working_directory",
        "read_only_root", "network_access", "execution_timeout_seconds",
    }
    assert not (registration | arguments) & IDENTITY_FIELDS
    config = _dict_call_keywords(_local_assignment(method, "config"))
    assert config == {
        "startup_timeout_seconds", "termination_grace_seconds",
        "resource_limits", "input_manifest_id",
    }
    assert not config & IDENTITY_FIELDS
    assert "submit_build_job" in ast.unparse(method)
    assert "canonical_request(arguments)" in ast.unparse(method)


def test_actual_box_and_root_control_wire_validators_reject_override_fields():
    class Rejected(Exception):
        pass

    box = _executable_functions(BOX_PROTOCOL,
        ["identity", "_positive", "canonical_request", "canonical_registration"],
        globals_dict={
            "json": json, "math": math, "PurePosixPath": PurePosixPath,
            "RuntimeOperationError": Rejected,
        })
    root = _executable_functions(ROOT_PROTOCOL,
        ["identity", "positive", "canonical_request", "authenticated_build_peer"],
        globals_dict={
            "json": json, "math": math, "PurePosixPath": PurePosixPath,
            "SystemdBackendError": Rejected,
        })
    assert root["authenticated_build_peer"]((0, 0)) == (0, 0)
    with pytest.raises(Rejected):
        root["authenticated_build_peer"]((0, 123))
    rid = "a" * 32
    request = {
        "build_root_id": rid, "source_workspace_id": rid + "-source",
        "output_workspace_id": rid + "-output",
        "command": ["/usr/bin/true"], "environment": {},
        "working_directory": "/", "startup_timeout_seconds": 5,
        "execution_timeout_seconds": 20, "termination_grace_seconds": 2,
        "resource_limits": {
            "thread-count-maximum": 10, "memory-maximum-bytes": 10485760,
        },
        "read_only_root": True, "network_access": False,
    }
    assert box["canonical_request"](request) == request
    assert root["canonical_request"](request) == request
    registration = {
        "prepared_root": "/project/state/image-build/attempts/root",
        "source_directory": "/project/state/image-build/attempts/source",
        "output_directory": "/project/state/image-build/attempts/output",
        "input_manifest_id": "sha256:accepted",
    }
    assert box["canonical_registration"](registration) == registration
    for key in ("execution_user_id", "execution_group_id", "User", "Group", "uid", "gid"):
        modified = {**request, key: 0}
        with pytest.raises(Rejected):
            box["canonical_request"](modified)
        with pytest.raises(Rejected):
            root["canonical_request"](modified)
        with pytest.raises(Rejected):
            box["canonical_registration"]({**registration, key: 0})


def test_read_only_lane_controller_inspection_reports_exact_root_pair(monkeypatch):
    spec = {
        "project_root": "/project/certbot-seed",
        "python_executable": "/usr/bin/python3.12",
        "controller": {"socket_path": "/run/zog/root-control.sock"},
    }
    monkeypatch.setattr(fonts_lane_runtime, "expected_controller_sha256",
                        lambda _spec: "f" * 64)
    monkeypatch.setattr(fonts_lane_runtime, "script",
                        lambda _spec: "read-only-inspect")
    result = {
        "status": "complete",
        "project_root": spec["project_root"],
        "socket_path": spec["controller"]["socket_path"],
        "python_executable": spec["python_executable"],
        "controller_sha256": "f" * 64,
        "effective_uid": 0, "effective_gid": 0,
    }
    class ReadOnlyHost:
        def command(self, command):
            assert command == "read-only-inspect"
            return json.dumps(result)
    host = ReadOnlyHost()
    assert fonts_lane_runtime.inspect(host, spec) == result
    result["effective_gid"] = 200
    with pytest.raises(RuntimeError, match="differs"):
        fonts_lane_runtime.inspect(host, spec)
