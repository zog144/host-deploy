"""Selected-Project/controller routing; run a synthetic producer, never a build."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy.gateway import project_current


def git(path, *arguments):
    return subprocess.run(["git", "-C", str(path), *arguments],
                          text=True, capture_output=True, check=True).stdout.strip()


def project(tmp_path):
    root = tmp_path / "existing-project"
    source = root / "source"
    package = source / "project/package"
    package.mkdir(parents=True)
    (root / "state").mkdir()
    controller = root / "controller-gateway-first-fonts-runtime-inherited-v1.json"
    controller.write_text('{"controller":"unchanged"}')
    module = source / "src/zog/image_build/remote_operations.py"
    module.parent.mkdir(parents=True)
    (module.parent / "__init__.py").write_text("")
    (module.parent.parent / "__init__.py").write_text("")
    (package / "pins.txt").write_text("first-pin")
    module.write_text(
        "import json,sys\nfrom pathlib import Path\n"
        "request=json.loads(Path(sys.argv[-1]).read_text())\n"
        "pin=(Path(__file__).resolve().parents[3]/'project/package/pins.txt').read_text()\n"
        "print(json.dumps({'schema':'image-build-remote-result-v1',"
        "'operation_id':request['operation_id'],"
        "'operation_type':request['operation'],"
        "'source_revision':request['source']['revision'],"
        "'status':'pending','pipeline_id':'a'*32,'recipe_identity':pin}))\n"
    )
    git(source, "init", "-q")
    git(source, "config", "user.email", "test@example.invalid")
    git(source, "config", "user.name", "Test")
    git(source, "add", ".")
    git(source, "commit", "-qm", "initial selected Project checkout")
    return root, source, controller


def selected(root, controller, *, historic=True):
    extra = ({
        "source_repository": "zog144/image-build",
        "source_revision": "b" * 40,
        "monthly_pin_repository_path": "project/pins/obsolete.py",
        "monthly_pin_identity": "sha256:" + "c" * 64,
    } if historic else {})
    spec = lanes.specification(
        "gateway-first-fonts-runtime",
        existing_project=True,
        project_root=str(root),
        python_executable=sys.executable,
        memory_maximum_bytes=1024**3,
        thread_count_maximum=4,
        cpu_weight=100,
        disk_reservation_bytes=1,
        **extra,
    )
    record = {
        "schema": lanes.INHERITED_SCHEMA,
        "lane": spec["lane"],
        "state": "active",
        "specification": spec,
        "source_root": str(root / "source"),
        "package_dir": str(root / "source/project/package"),
        "state_dir": str(root / "state"),
        "controller_config": str(controller),
    }
    return spec, record


def intent(request_id):
    return {
        "schema": 1,
        "request_id": request_id,
        "workspace_id": "1" * 32,
        "operation": "build.submit",
        "parameters": {
            "lane": "gateway-first-fonts-runtime",
            "task": "graphics-fonts-image-v1",
        },
    }


def target():
    return {
        "region": "us-east-1",
        "instance_id": "i-0123456789abcdef0",
        "account_id": "123456789012",
        "workspace_id": "1" * 32,
    }


def test_minimal_lane_has_only_project_controller_runtime_inputs(tmp_path):
    root = tmp_path / "gateway-first-fonts-runtime"
    spec = lanes.specification(
        "gateway-first-fonts-runtime", project_root=str(root),
        existing_project=True, python_executable=sys.executable,
        memory_maximum_bytes=1024**3, thread_count_maximum=4,
        cpu_weight=100, disk_reservation_bytes=1,
    )
    for historical in ("source_revision", "monthly_pin_repository_path",
                       "monthly_pin_identity", "provenance_host_id",
                       "provenance_project_id"):
        assert historical not in spec
    assert lanes.validate(spec) == spec


@pytest.mark.parametrize("historic", [True, False])
def test_next_build_uses_current_checkout_and_pin_not_lane_metadata(tmp_path, historic):
    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller, historic=historic)
    first = project_current.binding(intent("1" * 32), record, spec, target())
    first_revision = git(source, "rev-parse", "HEAD")
    assert "source_revision" not in first
    assert "monthly_pin_identity" not in first
    assert "source_revision" not in first["remote_request"]
    assert "revision" not in first["remote_request"]["source"]
    command = project_current.remote_script(first)
    output = subprocess.run(command, shell=True, text=True, capture_output=True,
                            check=True, timeout=20)
    receipt = json.loads(output.stdout.strip().splitlines()[-1])
    assert receipt["request_id"] == "1" * 32
    assert receipt["remote_request_sha256"] == first["remote_request_sha256"]
    assert receipt["result"]["source_revision"] == first_revision
    assert receipt["result"]["recipe_identity"] == "first-pin"
    assert receipt["result"]["status"] == "pending"
    assert receipt["result"]["pipeline_id"] == "a" * 32

    # Change both Project checkout and package pins. Do not edit the lane,
    # recreate the Project, touch the controller, or copy retained state.
    (source / "project/package/pins.txt").write_text("second-pin")
    git(source, "add", ".")
    git(source, "commit", "-qm", "current package pin selection")
    revision = git(source, "rev-parse", "HEAD")
    assert revision != first_revision
    second = project_current.binding(intent("2" * 32), record, spec, target())
    output = subprocess.run(project_current.remote_script(second), shell=True,
                            text=True, capture_output=True, check=True, timeout=20)
    receipt = json.loads(output.stdout.strip().splitlines()[-1])
    assert receipt["result"]["source_revision"] == revision
    assert receipt["result"]["recipe_identity"] == "second-pin"
    assert controller.read_text() == '{"controller":"unchanged"}'
    assert record["specification"] == spec


def test_project_controller_changes_are_not_allowed(tmp_path):
    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller)
    wrong = dict(record, controller_config=str(tmp_path / "another.json"))
    with pytest.raises(RuntimeError, match="Project/controller"):
        project_current.binding(intent("3" * 32), wrong, spec, target())
    bad = dict(record, source_root=str(tmp_path / "other-source"))
    with pytest.raises(RuntimeError, match="Project/controller"):
        project_current.binding(intent("4" * 32), bad, spec, target())


def test_frozen_project_binding_cannot_change_task_or_ssm_target(tmp_path):
    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller)
    binding = project_current.binding(intent("5" * 32), record, spec, target())
    bad = json.loads(json.dumps(binding))
    bad["remote_request"]["arguments"]["targets"].append("unexpected")
    with pytest.raises(RuntimeError, match="operation"):
        project_current.validate(bad)
    bad = json.loads(json.dumps(binding))
    bad["target"]["instance_id"] = "bad"
    with pytest.raises(RuntimeError, match="target"):
        project_current.validate(bad)
