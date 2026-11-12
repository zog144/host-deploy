"""Exact first-Fonts build-record binding and status preflight (source only).

This exercises the real host-deploy preflight command constructor and its
frozen-result validator using a fake Host. It never checks out software,
uses AWS/SSM, installs a service, or submits a Fonts operation.
"""
import copy
import json

import pytest

from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy.gateway.image_build_execution import producer_runtime_preflight

PROJECT = "/srv/zog/compiler-lanes/fonts"
SOURCE = PROJECT + "/source"
BUILD_RECORD = PROJECT + "/companions/build-record"
PIN = "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
PRODUCER = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"


def companion():
    return {
        "schema": lanes.RUNTIME_COMPANION_SCHEMA,
        "repository": "zog144/build-record",
        "revision": PIN,
        "source_root": BUILD_RECORD,
        "producer_revision": PRODUCER,
    }


def selected_binding():
    return {
        "schema": 3,
        "runtime_companion": companion(),
        "runtime_profile": {
            "schema": 1,
            "operation": "pipeline.inspect",
            "provenance": False,
            "controller": False,
            "external_observed_state": True,
            "controller_revision": None,
            "controller_source_root": None,
        },
        "source_root": SOURCE,
        "python_executable": "/usr/bin/python3",
        "source": {"repository": "zog144/image-build", "revision": PRODUCER},
    }


def ready_report():
    return {
        "contract": "image-build-runtime-preflight-v1",
        "ready": True,
        "mutation": False,
        "python": {"executable": "/usr/bin/python3"},
        "image_build": {"repository_root": SOURCE},
        "requirements": {
            "operation": "pipeline.inspect",
            "bindings": {
                "provenance": False,
                "controller": False,
                "external_observed_state": True,
            },
            "components": [{
                "component": "build-record",
                "repository": "zog144/build-record",
                "validated_revision": PIN,
                "version": "0.8.2",
                "source_subdir": "src",
            }],
        },
        "checks": [{
            "component": "build-record",
            "status": "ready",
            "validated_revision": PIN,
            "source": BUILD_RECORD + "/src/zog/build_record/__init__.py",
        }],
    }


class HostStub:
    def __init__(self, report):
        self.report = report
        self.commands = []

    def command(self, script, seconds):
        self.commands.append((script, seconds))
        return json.dumps(self.report)


def test_first_fonts_producer_pins_real_build_record_082():
    assert lanes.FIRST_FONTS_PRODUCER_REVISION == PRODUCER
    assert lanes.expected_build_record_revision(PRODUCER) == PIN
    assert lanes.FIRST_FONTS_BUILD_RECORD_COMPATIBILITY == PIN
    assert lanes.validate_runtime_companion(
        companion(), project_root=PROJECT
    ) == companion()
    # Older historical compatibility is not globally repointed.
    assert lanes.BUILD_RECORD_COMPATIBILITY != PIN


@pytest.mark.parametrize("change", ["revision", "source_root", "repository"])
def test_wrong_first_fonts_companion_never_binds(change):
    entry = companion()
    entry[change] = {
        "revision": "771af9429e83da40fd503625a6b4ba8329acee35",
        "source_root": PROJECT + "/companions/other-build-record",
        "repository": "unreviewed/build-record",
        "producer_revision": "f" * 40,
    }[change]
    with pytest.raises(ValueError):
        lanes.validate_runtime_companion(entry, project_root=PROJECT)


def test_status_rejects_companion_bound_to_another_producer_before_host_execution():
    binding = selected_binding()
    binding["runtime_companion"]["producer_revision"] = "f" * 40
    host = HostStub(ready_report())
    with pytest.raises(RuntimeError, match="source-bound build-record"):
        producer_runtime_preflight(host, binding)
    assert host.commands == []


def test_first_fonts_status_preflight_checks_git_and_python_source_without_provenance_flag():
    binding = selected_binding()
    host = HostStub(ready_report())
    result = producer_runtime_preflight(host, binding)
    assert result["ready"] is True
    assert len(host.commands) == 1
    script, timeout = host.commands[0]
    assert timeout == 120
    assert "--operation pipeline.inspect" in script
    assert "--component-root build-record=" + BUILD_RECORD in script
    assert "PYTHONPATH=" + SOURCE + "/src:" + BUILD_RECORD + "/src" in script
    assert PIN in script
    assert "rev-parse --verify HEAD" in script
    assert "status --porcelain=v1 --untracked-files=all" in script
    assert "--provenance" not in script
    assert "send-command" not in script.lower()


@pytest.mark.parametrize("damage", ["missing_requirement", "wrong_version", "wrong_revision", "missing_check", "wrong_source", "not_ready"])
def test_first_fonts_status_fails_before_submission_when_build_record_invalid(damage):
    report = copy.deepcopy(ready_report())
    if damage == "missing_requirement":
        report["requirements"]["components"] = []
    elif damage == "wrong_version":
        report["requirements"]["components"][0]["version"] = "0.1.0"
    elif damage == "wrong_revision":
        report["requirements"]["components"][0]["validated_revision"] = "f" * 40
    elif damage == "missing_check":
        report["checks"] = []
    elif damage == "wrong_source":
        report["checks"][0]["source"] = "/tmp/untrusted/zog/build_record/__init__.py"
    else:
        report["ready"] = False
    host = HostStub(report)
    with pytest.raises(RuntimeError, match="preflight|readiness"):
        producer_runtime_preflight(host, selected_binding())
    assert len(host.commands) == 1
