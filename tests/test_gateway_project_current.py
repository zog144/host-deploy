"""Selected-Project/controller routing; run a synthetic producer, never a build."""
import json
import os
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
        "def main():\n"
        "    request=json.loads(Path(sys.argv[-1]).read_text())\n"
        "    pin=(Path(__file__).resolve().parents[3]/'project/package/pins.txt').read_text()\n"
        "    print(json.dumps({'schema':'image-build-remote-result-v1',"
        "'operation_id':request['operation_id'],"
        "'operation_type':request['operation'],"
        "'source_revision':request['source']['revision'],"
        "'status':'pending','pipeline_id':'a'*32,'recipe_identity':pin}))\n"
        "if __name__ == '__main__': main()\n"
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
    with pytest.raises(RuntimeError, match="target|host identity"):
        project_current.validate(bad)


def test_gateway_uses_project_controller_only_across_saved_revision_pin_change(
        tmp_path, monkeypatch):
    from contextlib import nullcontext
    from test_gateway_simple_forward import approved, admit
    from zog.host_deploy.gateway import image_build_dispatch, simple_forward
    from zog.host_deploy.gateway.ledger import load_dispatch

    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller, historic=True)
    gateway = tmp_path / "gateway"
    request = approved()
    admit(gateway, request)
    host = target()
    monkeypatch.setattr(image_build_dispatch, "owned_workspace",
                        lambda directory, workspace: "owned-workspace")
    monkeypatch.setattr(image_build_dispatch, "locked_workspace",
                        lambda directory: nullcontext(directory))
    monkeypatch.setattr(image_build_dispatch, "configuration",
                        lambda directory: ({}, host))
    monkeypatch.setattr(image_build_dispatch, "_load_lane_locked",
                        lambda directory, lane: (record, spec))
    result = simple_forward.advance(gateway, request["request_id"])
    assert result["phase"] == "prepared"
    frozen = load_dispatch(gateway, request["request_id"])["binding"]
    assert frozen["schema"] == 4
    assert "source" not in frozen
    assert "monthly_pin_identity" not in frozen
    assert frozen["project_root"] == str(root)

    # The retained specification fields can change without becoming new
    # request authorization or blocking the already selected controller.
    spec["source_revision"] = "f" * 40
    spec["monthly_pin_identity"] = "sha256:" + "d" * 64
    (source / "project/package/pins.txt").write_text("current-pin")
    git(source, "add", ".")
    git(source, "commit", "-qm", "new current package pin")
    assert image_build_dispatch.verify_current_target(gateway, frozen) == host

    sent = []
    class FakeHost:
        def __init__(self, configuration):
            assert configuration == host
        def submit_command(self, script, seconds):
            sent.append(script)
            return "command-project-current"
        def inspect_command(self, identifier):
            return None
    submitted = simple_forward.advance(
        gateway, request["request_id"], host_factory=FakeHost)
    assert submitted["command_id"] == "command-project-current"
    assert len(sent) == 1
    assert "zog.image_build.remote_operations" in sent[0]
    assert simple_forward.advance(
        gateway, request["request_id"], host_factory=FakeHost)["phase"] == "submitted"
    assert len(sent) == 1


def test_new_project_dispatch_lost_ack_does_not_send_twice(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from test_gateway_simple_forward import approved, admit
    from zog.host_deploy.gateway import image_build_dispatch, simple_forward
    from zog.host_deploy.gateway.ledger import load_dispatch

    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller, historic=False)
    gateway = tmp_path / "gateway"
    request = approved()
    admit(gateway, request)
    host = target()
    monkeypatch.setattr(image_build_dispatch, "owned_workspace",
                        lambda directory, workspace: "owned")
    monkeypatch.setattr(image_build_dispatch, "locked_workspace",
                        lambda directory: nullcontext(directory))
    monkeypatch.setattr(image_build_dispatch, "configuration",
                        lambda directory: ({}, host))
    monkeypatch.setattr(image_build_dispatch, "_load_lane_locked",
                        lambda directory, lane: (record, spec))
    simple_forward.advance(gateway, request["request_id"])
    sent = []
    class Lost:
        def __init__(self, config):
            assert config == host
        def submit_command(self, script, seconds):
            sent.append(script)
            raise TimeoutError("lost SSM command acknowledgement")
    with pytest.raises(TimeoutError, match="lost SSM"):
        simple_forward.advance(gateway, request["request_id"], host_factory=Lost)
    assert len(sent) == 1
    assert load_dispatch(gateway, request["request_id"])["phase"] == "submission_uncertain"
    assert simple_forward.advance(
        gateway, request["request_id"], host_factory=Lost)["phase"] == "submission_uncertain"
    assert len(sent) == 1


@pytest.fixture
def project_with_installed_zog_shadow(tmp_path):
    """Actual site-packages regular zog would win over a PYTHONPATH namespace."""
    root, source, controller = project(tmp_path)
    environment = tmp_path / "isolated-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(environment)],
        check=True, capture_output=True, text=True,
    )
    interpreter = environment / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python"
    )
    site = subprocess.check_output(
        [str(interpreter), "-I", "-c",
         "import site; print(site.getsitepackages()[0])"],
        text=True,
    ).strip()
    installed_zog = Path(site) / "zog"
    installed_image_build = installed_zog / "image_build"
    installed_image_build.mkdir(parents=True)
    sentinel = tmp_path / "installed-zog-was-imported"
    (installed_zog / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('wrong-installed-zog')\n"
        "raise RuntimeError('installed zog shadows the selected Project')\n"
    )
    (installed_image_build / "__init__.py").write_text("")
    (installed_image_build / "remote_operations.py").write_text(
        "raise RuntimeError('wrong installed image-build executable')\n"
    )
    discovered = subprocess.check_output(
        [str(interpreter), "-I", "-c",
         "import importlib.util; print(importlib.util.find_spec('zog').origin)"],
        text=True,
    ).strip()
    assert Path(discovered).resolve() == (installed_zog / "__init__.py").resolve()
    # Negative control: the old PYTHONPATH + "-m" invocation really does
    # import the globally installed regular package, not this Project's
    # implicit src/zog namespace. Remove the sentinel before the new test.
    legacy = subprocess.run(
        [str(interpreter), "-m", "zog.image_build.remote_operations"],
        cwd=source, env={**os.environ, "PYTHONPATH": str(source / "src")},
        text=True, capture_output=True, timeout=15,
    )
    assert legacy.returncode != 0
    assert "installed zog shadows the selected Project" in legacy.stderr
    assert sentinel.read_text() == "wrong-installed-zog"
    sentinel.unlink()
    return root, source, controller, interpreter, sentinel


def test_project_current_imports_selected_source_even_when_regular_zog_is_installed(
        project_with_installed_zog_shadow):
    root, source, controller, interpreter, sentinel = project_with_installed_zog_shadow
    spec, record = selected(root, controller, historic=True)
    spec["python_executable"] = str(interpreter)
    for operation_id, expected_pin in (("7" * 32, "first-pin"),
                                       ("8" * 32, "updated-pin")):
        if expected_pin == "updated-pin":
            (source / "project/package/pins.txt").write_text(expected_pin)
            git(source, "add", ".")
            git(source, "commit", "-qm", "selected Project version update")
        prepared = project_current.binding(
            intent(operation_id), record, spec, target(),
        )
        script = project_current.remote_script(prepared)
        output = subprocess.run(
            script, shell=True, text=True, capture_output=True, timeout=30,
        )
        assert output.returncode == 0, output.stderr
        receipt = json.loads(output.stdout.strip().splitlines()[-1])
        assert receipt["result"]["source_revision"] == git(source, "rev-parse", "HEAD")
        assert receipt["result"]["recipe_identity"] == expected_pin
        assert not sentinel.exists(), "the installed zog package was imported"


def test_project_current_fails_closed_if_selected_module_missing_despite_installed_zog(
        project_with_installed_zog_shadow):
    root, source, controller, interpreter, sentinel = project_with_installed_zog_shadow
    spec, record = selected(root, controller, historic=False)
    spec["python_executable"] = str(interpreter)
    # A global zog package must not silently replace the absent Project module.
    (source / "src/zog/image_build/remote_operations.py").unlink()
    script = project_current.remote_script(
        project_current.binding(intent("9" * 32), record, spec, target()),
    )
    output = subprocess.run(
        script, shell=True, text=True, capture_output=True, timeout=30,
    )
    assert output.returncode != 0
    assert "selected Project image-build module is missing" in output.stderr
    assert not sentinel.exists()
