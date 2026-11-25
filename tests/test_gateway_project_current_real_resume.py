"""Actual image-build pipeline.resume -> trusted Project-current observation.

This disposable source integration uses the exact reviewed image-build checkout,
never a real controller/Host, and never a second pipeline.submit. It proves the
original pending remote result can remain stale while image-build's OWN pipeline
and attempts finish through the same retained pipeline identity.
"""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from zog.host_deploy.gateway.project_current_observation import (
    observe_selected_project,
)

IMAGE_BUILD = Path(__file__).resolve().parents[1] / "companions/image-build"

# This is deliberately a separate, isolated source process. The Project
# image-build namespace must not be shadowed by site-installed zog modules.
_REAL_IMAGE_BUILD_WORKER = r"""
import json, sys, shutil
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[2]]
project = Path(sys.argv[3])
phase = sys.argv[4]
operation_id = sys.argv[5]
pipeline_id = sys.argv[6] if len(sys.argv) > 6 else None
from zog.image_build import ImageBuild
from zog.image_build.runner import BoxControlRunner, BuildExecutionResult

targets = ["libpng-final", "freetype-final", "fontconfig-final"]

if phase == "submit":
    from test_remote_operations import setup_repo, recipe, request, adapter
    repository, packages, builder, toolchain = setup_repo(project)
    # The production Fonts route intentionally requires separately
    # reviewed executable stage metadata. This disposable test exercises
    # the *generic* default Project pipeline, with identical Fonts targets,
    # through actual image-build prepare/resume. It is not source approval
    # of the real fonts catalogue or a compilation on any Host.
    packages = repository / "project" / "synthetic-package"
    shutil.copytree(builder.package_dir, packages)
    builder.package_dir = packages
    recipe(packages, "libpng-final")
    recipe(packages, "freetype-final", build=("libpng-final",))
    recipe(packages, "fontconfig-final", build=("freetype-final",))
    active = builder.state / "image-build" / "active"
    if not active.is_symlink():
        active.symlink_to("generations/" + toolchain.generation)
    def pending(_):
        raise KeyboardInterrupt("disconnected after durable pipeline preparation")
    builder.runner = BoxControlRunner(execute=pending)
    remote = adapter(repository, builder, "a" * 40)
    original = request(operation_id, "pipeline.submit",
                       {"mode": "image", "targets": targets},
                       revision="a" * 40)
    result = remote.execute(original)
    assert result["status"] == "pending", result
    assert result["pipeline_id"] is not None, result
    requested = project / "gateway-requests" / operation_id
    requested.mkdir(parents=True, exist_ok=True)
    (requested / "request.json").write_text(json.dumps(original))
    print(json.dumps({
        "pipeline_id": result["pipeline_id"],
        "submit_status": result["status"],
    }))
elif phase == "resume":
    def completed(request):
        if request.command[0] == "install":
            target = request.output / "usr/share" / request.command[1]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(request.command[1])
        return BuildExecutionResult("fixture-runtime", "fixture-invocation",
                                    0, True, "journal:disposable-fixture")
    builder = ImageBuild(
        package_dir=project / "repository/project/synthetic-package",
        state_dir=project / "state",
        runner=BoxControlRunner(execute=completed),
    )
    generation = builder.resume(pipeline_id)
    pipeline = builder.inspect_pipeline(pipeline_id)
    assert pipeline["status"] == "complete"
    print(json.dumps({
        "pipeline_id": pipeline_id,
        "generation": generation.generation,
        "status": pipeline["status"],
        "attempts": pipeline["attempts"],
    }))
else:
    raise AssertionError("unsupported disposable image-build phase")
"""


def _image_build_phase(project, operation_id, phase, pipeline_id=None):
    cmd = [
        sys.executable, "-I", "-B", "-c", _REAL_IMAGE_BUILD_WORKER,
        str(IMAGE_BUILD / "src"), str(IMAGE_BUILD / "tests"),
        str(project), phase, operation_id,
    ]
    if pipeline_id is not None:
        cmd.append(pipeline_id)
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(not (IMAGE_BUILD / "src/zog/image_build/pipeline.py").is_file(),
                    reason="requires exact image-build companion checkout")
def test_real_pipeline_resume_completes_same_owned_operation_with_pending_original_result(
        tmp_path):
    project = tmp_path / "actual-image-build-project"
    project.mkdir()
    operation_id = "8" * 32
    submitted = _image_build_phase(project, operation_id, "submit")
    pipeline_id = submitted["pipeline_id"]
    original_path = (
        project / "state/image-build/remote-operations" /
        operation_id / "result.json"
    )
    original_result = original_path.read_bytes()
    pipeline_directory = project / "state/image-build/pipelines"
    pipelines_before_resume = {item.name for item in pipeline_directory.iterdir()}
    assert pipeline_id in pipelines_before_resume
    assert json.loads(original_result)["status"] == "pending"
    pending = observe_selected_project(str(project), operation_id,
                                       pipeline_id=pipeline_id)
    assert pending["terminal_confirmed"] is False
    assert pending["pipeline_id"] == pipeline_id
    assert pending["evidence_source"] == "local-selected-project"

    # Actual source-supported image-build PipelineMixin.resume now updates
    # original attempt/status.json and pipeline.json, not the stale original
    # operation result. This is a RESUME, never another pipeline.submit.
    resumed = _image_build_phase(project, operation_id, "resume", pipeline_id)
    assert resumed["pipeline_id"] == pipeline_id
    assert resumed["status"] == "complete"
    assert resumed["attempts"]
    finished = observe_selected_project(str(project), operation_id,
                                        pipeline_id=pipeline_id)
    assert finished["terminal_confirmed"] is True
    assert finished["producer_status"] == "completed"
    assert finished["terminal_outcome"] == "success"
    assert finished["pipeline_status"] == "complete"
    assert finished["attempt_ids"] == sorted(resumed["attempts"].values())
    assert len(finished["evidence"]["attempt_statuses"]) == len(
        finished["attempt_ids"])
    assert original_path.read_bytes() == original_result
    assert {item.name for item in pipeline_directory.iterdir()} == (
        pipelines_before_resume), "resume must not allocate another pipeline"
    assert finished["request_id"] == pending["request_id"] == operation_id
    assert finished["pipeline_id"] == pending["pipeline_id"] == pipeline_id
    assert not (project / "state/image-build/remote-operations" /
                ("9" * 32)).exists(), "no second pipeline.submit was created"
