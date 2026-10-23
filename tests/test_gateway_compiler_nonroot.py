"""Protected compiler owner identity, drift and fixed execution tests.

Pure source tests do not claim native controller SO_PEERCRED acceptance; Work
must verify the actual root-control socket and selected nonroot processes.
"""
from copy import deepcopy
import re

import pytest

from zog.host_deploy.gateway import compiler_execution_identity as execution
from zog.host_deploy.gateway import image_build_execution


PROJECT = "/home/zog-compiler/build-project"
SOURCE = "31e6121cdf9fd05336286529666e2c35cdbe0831"
RECORD = "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
CONTROLLER = "644170fc441863307092f329bf7e23cb64eb33e2"
TASK = "sha256:" + "e" * 64
PYTHON = "/usr/bin/python3"


def identity():
    return {
        "schema": execution.SCHEMA,
        "controller_uid": 15401,
        "controller_gid": 15402,
        "controller_home": "/home/zog-compiler",
        "project_root": PROJECT,
        "build_uid": 15501,
        "build_gid": 15502,
        "socket_path": "/run/zog/root-control.sock",
        "source_revision": SOURCE,
        "build_record_revision": RECORD,
        "box_control_revision": CONTROLLER,
        "python_executable": PYTHON,
        "task_catalogue_identity": TASK,
        "root_control_revision": execution.ROOT_CONTROL_REVISION,
    }


def verify(value):
    return execution.validate(
        value, project_root=PROJECT, python_executable=PYTHON,
        source_revision=SOURCE, build_record_revision=RECORD,
        box_control_revision=CONTROLLER, task_identity=TASK,
    )


def test_protected_numeric_controller_and_separate_build_identity():
    assert verify(identity()) == identity()
    assert execution.FIELDS == set(identity())
    for key, other in (
        ("controller_uid", 0), ("controller_gid", 0),
        ("controller_uid", 15501), ("controller_gid", 15502),
        ("build_uid", 15401), ("build_gid", 15402),
        ("build_uid", -2), ("build_gid", True),
        ("controller_uid", "15401"), ("controller_gid", 2**31),
    ):
        data = identity()
        data[key] = other
        with pytest.raises(ValueError):
            verify(data)


def test_no_home_spoof_or_implicit_controller_socket():
    for key, other in (
        ("controller_home", "/root"),
        ("controller_home", "/tmp"),
        ("controller_home", "/home/zog-compiler/build-project"),
        ("controller_home", "/home/zog-compiler/../zog-compiler"),
        ("project_root", "/tmp/build-project"),
        ("project_root", PROJECT + "/../different"),
        ("socket_path", "/run/zog/other.sock"),
        ("socket_path", "/tmp/root-control.sock"),
        ("socket_path", "/run/zog/../zog/root-control.sock"),
        ("python_executable", "python3"),
    ):
        data = identity()
        data[key] = other
        with pytest.raises(ValueError):
            verify(data)


@pytest.mark.parametrize("key,other", [
    ("source_revision", "f" * 40),
    ("build_record_revision", "a" * 40),
    ("box_control_revision", "b" * 40),
    ("task_catalogue_identity", "sha256:" + "f" * 64),
    ("root_control_revision", "62dca363d27a043a4b573e5b687f68ab5a16adeb"),
    ("root_control_revision", execution.ROOT_CONTROL_REVIEW_HEAD),
])
def test_execution_identity_cannot_repin_component_or_task(key, other):
    data = identity()
    data[key] = other
    with pytest.raises(ValueError):
        verify(data)


def test_unknown_claims_and_manifest_mutation_rejected():
    data = identity()
    data["gateway_actor"] = "request-from-issue"
    with pytest.raises(ValueError):
        verify(data)
    data.pop("gateway_actor")
    with pytest.raises(ValueError):
        execution.validate(
            data, project_root=PROJECT, python_executable=PYTHON,
            source_revision=SOURCE, build_record_revision=RECORD,
            box_control_revision=CONTROLLER,
            task_identity="sha256:" + "b" * 64,
        )


def test_embedded_fixed_launcher_checks_actual_passwd_socket_and_groups():
    source = execution.IDENTITY_RUNTIME
    assert "pwd.getpwuid(owner_uid)" in source
    assert 'account.pw_dir != value["controller_home"]' in source
    assert "stat.S_ISSOCK" in source
    assert "os.geteuid() != 0" in source
    assert 'user=value["controller_uid"]' in source
    assert 'group=value["controller_gid"]' in source
    assert "extra_groups=()" in source
    assert '"HOME": account.pw_dir' in source
    assert '"PYTHONPATH": runtime_path' in source
    assert 'env=environment' in source
    assert "cwd=account.pw_dir" in source
    assert "shell=True" not in source
    assert "setpriv" not in source
    assert "runuser" not in source
    # This is a static guard test; native kernel credential change and
    # socket SO_PEERCRED are independent Work acceptance gates.


def test_exact_frozen_request_uses_sealed_fd_in_nonroot_wrapper():
    source = image_build_execution._WRAPPER
    assert 'os.memfd_create("zog-compiler-request", os.MFD_ALLOW_SEALING)' in source
    assert "fcntl.F_SEAL_WRITE" in source
    assert "fcntl.F_SEAL_SHRINK" in source
    assert "fcntl.F_SEAL_GROW" in source
    assert "fcntl.F_SEAL_SEAL" in source
    assert "request_fd=descriptor" in source
    assert "os.close(descriptor)" in source
    assert 'atomic(request_path, payload)' in source
    assert 'atomic(result_path, result_bytes)' in source
    assert "subprocess.run(\n        argv," not in source


def test_historical_v1_is_readable_only_with_explicit_history_permission():
    frozen = identity()
    frozen["schema"] = execution.LEGACY_SCHEMA
    del frozen["root_control_revision"]
    with pytest.raises(ValueError, match="schema"):
        verify(frozen)
    assert execution.validate(
        frozen, project_root=PROJECT, python_executable=PYTHON,
        source_revision=SOURCE, build_record_revision=RECORD,
        box_control_revision=CONTROLLER, task_identity=TASK,
        allow_historical=True) == frozen
    assert execution.ROOT_CONTROL_REVISION != execution.ROOT_CONTROL_REVIEW_HEAD
