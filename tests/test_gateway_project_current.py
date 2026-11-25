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
    # The real image-build checkout is a PEP 420 namespace: src/zog has
    # NO __init__.py. A regular installed zog package can otherwise win.
    assert not (module.parent.parent / "__init__.py").exists()
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


class _FakeProtectedJournal:
    """Simulate root-control's exact owner API without root/AWS in source CI."""
    def inspect(self, operation_id):
        assert len(operation_id) == 32
        return (None, None, None)

    def submit_once(self, *, operation_id, request_sha256, script, target,
                    seconds, sender):
        assert len(operation_id) == 32
        assert len(request_sha256) == 64
        assert target["instance_id"] == sender.instance
        return sender.submit_command(script, seconds=seconds)

    def close(self):
        pass


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
    # The isolated Project fixture has no real archived first-Fonts lane.
    # Production provenance is tested separately against its source owner.
    monkeypatch.setattr(project_current, "verify_approved_lane",
                        lambda *_: {"execution_authorized": False})
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
            self.instance = configuration["instance_id"]
        def submit_command(self, script, seconds):
            sent.append(script)
            return "command-project-current"
        def inspect_command(self, identifier):
            return None
    submitted = simple_forward.advance(
        gateway, request["request_id"], host_factory=FakeHost,
        owner_factory=_FakeProtectedJournal)
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
    # The isolated Project fixture has no real archived first-Fonts lane.
    # Production provenance is tested separately against its source owner.
    monkeypatch.setattr(project_current, "verify_approved_lane",
                        lambda *_: {"execution_authorized": False})
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
            self.instance = config["instance_id"]
        def submit_command(self, script, seconds):
            sent.append(script)
            raise TimeoutError("lost SSM command acknowledgement")
    with pytest.raises(TimeoutError, match="lost SSM"):
        simple_forward.advance(
            gateway, request["request_id"], host_factory=Lost,
            owner_factory=_FakeProtectedJournal)
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
        cwd=source,
        # Python's -I flag and ordinary venv startup can expose different
        # site paths on older interpreters. Include the fixture's *actual*
        # installed site directory explicitly, after the selected checkout.
        env={**os.environ, "PYTHONPATH":
             os.pathsep.join((str(source / "src"), site))},
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


def test_read_only_normal_import_uses_selected_project_companions_and_installed_deps(
        project_with_installed_zog_shadow):
    root, source, controller, interpreter, sentinel = project_with_installed_zog_shadow
    site = Path(subprocess.check_output(
        [str(interpreter), "-I", "-c",
         "import site; print(site.getsitepackages()[0])"],
        text=True,
    ).strip())
    # An unrelated third-party distribution remains installed and importable
    # even while the globally installed regular 'zog' cannot shadow the
    # Project's namespace.
    (site / "ordinary_dependency.py").write_text("READY = True\n")
    for role, prefix, marker in (
        ("build_record", root / "companions/build-record/src", "project-build-record"),
        ("box_control", root / "companions/box-control/box-control/src", "project-box-control"),
    ):
        package = prefix / "zog" / role
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("ORIGIN = " + repr(marker) + "\n")
        installed = site / "zog" / role
        installed.mkdir()
        (installed / "__init__.py").write_text(
            "raise RuntimeError('installed companion incorrectly selected')\n"
        )
    executable = source / "src/zog/image_build/remote_operations.py"
    original = executable.read_text()
    executable.write_text(
        "import ordinary_dependency\n"
        "from zog import build_record, box_control\n"
        "assert ordinary_dependency.READY is True\n"
        "assert build_record.ORIGIN == 'project-build-record'\n"
        "assert box_control.ORIGIN == 'project-box-control'\n"
        + original
    )
    git(source, "add", ".")
    git(source, "commit", "-qm", "Project-current source with local companions")

    readiness = project_current.read_only_import_script(str(root), str(interpreter))
    assert "-I" in readiness and "-B" in readiness
    before = controller.read_bytes()
    response = subprocess.run(
        readiness, shell=True, text=True, capture_output=True, timeout=30,
    )
    assert response.returncode == 0, response.stderr
    evidence = json.loads(response.stdout.strip().splitlines()[-1])
    assert evidence["schema"] == "host-deploy-project-current-import-readiness-v1"
    assert evidence["source_root"] == str(source)
    assert evidence["python_executable"] == str(interpreter)
    assert evidence["remote_operations"] == str(executable)
    assert evidence["image_build_package"] == str(executable.parent / "__init__.py")
    assert evidence["companions"]["build-record"]["origin"] == str(
        root / "companions/build-record/src/zog/build_record/__init__.py"
    )
    assert evidence["companions"]["box-control"]["origin"] == str(
        root / "companions/box-control/box-control/src/zog/box_control/__init__.py"
    )
    assert evidence["mutation"] is False
    assert evidence["execution_authorized"] is False
    assert not (root / "gateway-requests").exists()
    assert controller.read_bytes() == before
    assert not sentinel.exists()
    assert not list(source.rglob("__pycache__"))

    # The true Project-current dispatch uses this exact same bootstrap; this
    # synthetic execution is local-only, not a live Host request or SSM send.
    spec, record = selected(root, controller)
    spec["python_executable"] = str(interpreter)
    prepared = project_current.binding(
        intent("a" * 32), record, spec, target(),
    )
    actual = subprocess.run(
        project_current.remote_script(prepared), shell=True,
        text=True, capture_output=True, timeout=30,
    )
    assert actual.returncode == 0, actual.stderr
    receipt = json.loads(actual.stdout.strip().splitlines()[-1])
    assert receipt["result"]["source_revision"] == git(source, "rev-parse", "HEAD")
    assert receipt["result"]["recipe_identity"] == "first-pin"
    assert not sentinel.exists()


def test_import_readiness_holds_without_selected_project_module_before_request(
        project_with_installed_zog_shadow):
    root, source, _, interpreter, sentinel = project_with_installed_zog_shadow
    (source / "src/zog/image_build/remote_operations.py").unlink()
    result = subprocess.run(
        project_current.read_only_import_script(str(root), str(interpreter)),
        shell=True, text=True, capture_output=True, timeout=30,
    )
    assert result.returncode != 0
    assert "selected Project image-build module is missing or redirected" in result.stderr
    assert not (root / "gateway-requests").exists()
    assert not sentinel.exists()


def test_import_readiness_rejects_broken_selected_companion_not_installed_fallback(
        project_with_installed_zog_shadow):
    root, source, _, interpreter, sentinel = project_with_installed_zog_shadow
    broken = root / "companions/box-control/box-control/src/zog/box_control"
    broken.mkdir(parents=True)
    response = subprocess.run(
        project_current.read_only_import_script(str(root), str(interpreter)),
        shell=True, text=True, capture_output=True, timeout=30,
    )
    assert response.returncode != 0
    assert "selected Project box_control companion is incomplete" in response.stderr
    assert not (root / "gateway-requests").exists()
    assert not sentinel.exists()


def test_import_readiness_rejects_unspecified_project_or_python():
    with pytest.raises((RuntimeError, ValueError)):
        project_current.read_only_import_script("../other-project", "/usr/bin/python3.12")
    with pytest.raises((RuntimeError, ValueError)):
        project_current.read_only_import_script("/srv/zog/certbot-seed", "python3")


def test_unexpected_import_arguments_never_invoke_project_producer(
        project_with_installed_zog_shadow):
    root, source, _, interpreter, sentinel = project_with_installed_zog_shadow
    # Even if someone appends an accidental argument to a readiness check,
    # it must not fall through into remote_operations.main().
    for args in (["--inspect-only", "--unexpected"], ["--wrong-operation"]):
        result = subprocess.run(
            [str(interpreter), "-I", "-B", "-c",
             project_current._PROJECT_IMPORT_BOOTSTRAP, str(source),
             str(root), *args],
            text=True, capture_output=True, timeout=30,
        )
        assert result.returncode != 0
        assert "unsupported Project-current import invocation" in result.stderr
        assert not (root / "gateway-requests").exists()
        assert not sentinel.exists()


def _slow_durable_producer(root, source, *, create_pipeline=True):
    """Disposable image-build-shaped producer: durable owner before long wait."""
    module = source / "src/zog/image_build/remote_operations.py"
    worker = """
import json, sys, time
from pathlib import Path
def main():
    request_path = Path(sys.argv[-1])
    request = json.loads(request_path.read_text())
    operation = request["operation_id"]
    project = request_path.parents[2]
    state = project / "state/image-build"
    operation_dir = state / "remote-operations" / operation
    operation_dir.mkdir(parents=True, exist_ok=True)
    (operation_dir / "request.json").write_text(json.dumps(request))
    if CREATE_PIPELINE:
        pipeline_id = "d" * 32
        record = {
            "schema": 1, "pipeline_id": pipeline_id, "status": "running",
            "operation": "image",
            "arguments": {
                "targets": ["libpng-final", "freetype-final", "fontconfig-final"],
            },
            "owner": {
                "contract": request["schema"],
                "operation_id": operation,
                "source_repository": request["source"]["repository"],
                "source_revision": request["source"]["revision"],
            },
            "attempts": {"fontconfig-final": "image-63dcd6a137f040bc9224dce166a916ed"},
        }
        dest = state / "pipelines" / pipeline_id
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "pipeline.json").write_text(json.dumps(record))
        (operation_dir / "binding.json").write_text(json.dumps({"pipeline_id": pipeline_id}))
    # Simulate long generation verification after the pipeline/attempt exist.
    time.sleep(3)
""".replace("CREATE_PIPELINE", "True" if create_pipeline else "False")
    module.write_text(worker)
    git(source, "add", ".")
    git(source, "commit", "-qm", "durable first-fonts producer with slow verification")


def test_project_current_producer_timeout_keeps_original_pipeline_and_attempt(
        tmp_path, monkeypatch):
    root, source, controller = project(tmp_path)
    _slow_durable_producer(root, source)
    spec, record = selected(root, controller)
    request_id = "e" * 32
    binding = project_current.binding(intent(request_id), record, spec, target())
    # Shrink the *test* timeout only; real policy remains controller=14400s.
    monkeypatch.setattr(project_current, "_RUN",
                        project_current._RUN.replace("timeout=14400", "timeout=0.75"))
    submitted = subprocess.run(project_current.remote_script(binding),
                               shell=True, capture_output=True, text=True, timeout=12)
    assert submitted.returncode == 0, submitted.stderr
    receipt = json.loads(submitted.stdout.strip().splitlines()[-1])
    assert receipt["request_id"] == request_id
    assert receipt["remote_request_sha256"] == binding["remote_request_sha256"]
    result = receipt["result"]
    assert result["status"] == "pending"
    assert result["uncertainty"] is True
    assert result["terminal_outcome"] is None
    assert result["pipeline_id"] == "d" * 32
    assert result["attempt_ids"] == ["image-63dcd6a137f040bc9224dce166a916ed"]
    assert result["reconciliation_required"] is True
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script, PRODUCER_TIMEOUT_SECONDS,
        CONTROL_TIMEOUT_SECONDS,
    )
    assert PRODUCER_TIMEOUT_SECONDS == 14400
    assert CONTROL_TIMEOUT_SECONDS > PRODUCER_TIMEOUT_SECONDS
    first = subprocess.run(
        read_only_observation_script(str(root), sys.executable, request_id,
                                     pipeline_id="d" * 32),
        shell=True, capture_output=True, text=True, timeout=8)
    assert first.returncode == 0, first.stderr
    observed = json.loads(first.stdout.strip())
    assert observed["operation_id"] == request_id
    assert observed["pipeline_id"] == "d" * 32
    assert observed["pipeline_status"] == "running"
    assert observed["terminal_confirmed"] is False
    assert observed["mutation"] is False
    assert observed["execution_authorized"] is False
    before = (root / "state/image-build/remote-operations" / request_id /
              "binding.json").read_bytes()
    assert before == json.dumps({"pipeline_id": "d" * 32}).encode()
    assert (root / "gateway-requests" / request_id / "request.json").is_file()
    assert not (root / "state/image-build/remote-operations" / request_id /
                "result.json").exists(), "timeout must not invent a terminal producer result"
    # Simulate later verified producer completion in *the same operation*.
    pipeline_file = (root / "state/image-build/pipelines" /
                     ("d" * 32) / "pipeline.json")
    pipeline_record = json.loads(pipeline_file.read_text())
    generation = "9" * 64
    attempt = "image-63dcd6a137f040bc9224dce166a916ed"
    attempt_file = (root / "state/image-build/attempts" / attempt / "status.json")
    attempt_file.parent.mkdir(parents=True)
    attempt_file.write_text(json.dumps(
        {"status": "complete", "generation": generation}))
    pipeline_record.update({"status": "complete", "generation": generation})
    pipeline_file.write_text(json.dumps(pipeline_record))
    # No result.json is written here. This is exactly the production case:
    # image-build's durable pipeline/attempt reaches completion after
    # submit had already timed out (or left a stale pending result).
    assert not (root / "state/image-build/remote-operations" / request_id /
                "result.json").exists()
    second = subprocess.run(
        read_only_observation_script(str(root), sys.executable, request_id,
                                     pipeline_id="d" * 32),
        shell=True, capture_output=True, text=True, timeout=8)
    assert second.returncode == 0, second.stderr
    complete = json.loads(second.stdout.strip())
    assert complete["terminal_confirmed"] is True
    assert complete["producer_status"] == "completed"
    assert complete["terminal_outcome"] == "success"
    assert complete["evidence"]["pipeline_sha256"]
    assert complete["evidence"]["attempt_statuses"][attempt]
    assert complete["pipeline_id"] == observed["pipeline_id"]
    assert (root / "state/image-build/remote-operations" / request_id /
            "binding.json").read_bytes() == before


def test_project_current_timeout_without_pipeline_is_uncertain_not_failed(
        tmp_path, monkeypatch):
    root, source, controller = project(tmp_path)
    _slow_durable_producer(root, source, create_pipeline=False)
    spec, record = selected(root, controller)
    request = project_current.binding(intent("f" * 32), record, spec, target())
    monkeypatch.setattr(project_current, "_RUN",
                        project_current._RUN.replace("timeout=14400", "timeout=0.75"))
    result = subprocess.run(project_current.remote_script(request),
                            shell=True, text=True, capture_output=True, timeout=12)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout.strip().splitlines()[-1])
    assert receipt["result"]["pipeline_id"] is None
    assert receipt["result"]["status"] == "pending"
    assert receipt["result"]["uncertainty"] is True


def test_observation_rejects_foreign_pipeline_and_does_not_create_request(tmp_path):
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    root, source, controller = project(tmp_path)
    with pytest.raises((RuntimeError, ValueError)):
        read_only_observation_script(str(root), sys.executable, "not-an-operation")
    absent = subprocess.run(
        read_only_observation_script(str(root), sys.executable, "e" * 32),
        shell=True, capture_output=True, text=True, timeout=8)
    assert absent.returncode != 0
    assert not (root / "gateway-requests").exists()


def test_read_only_observation_fails_closed_on_foreign_pipeline_owner(
        tmp_path, monkeypatch):
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    root, source, controller = project(tmp_path)
    _slow_durable_producer(root, source)
    spec, record = selected(root, controller)
    req = project_current.binding(intent("b" * 32), record, spec, target())
    monkeypatch.setattr(project_current, "_RUN",
                        project_current._RUN.replace("timeout=14400", "timeout=0.75"))
    created = subprocess.run(project_current.remote_script(req),
                             shell=True, capture_output=True, text=True, timeout=12)
    assert created.returncode == 0, created.stderr
    pipeline = root / "state/image-build/pipelines" / ("d" * 32) / "pipeline.json"
    selected_record = json.loads(pipeline.read_text())
    readback = read_only_observation_script(
        str(root), sys.executable, "b" * 32, pipeline_id="d" * 32)
    for owner_key, invalid in (("operation_id", "f" * 32),
                               ("source_revision", "f" * 40)):
        changed = json.loads(json.dumps(selected_record))
        changed["owner"][owner_key] = invalid
        pipeline.write_text(json.dumps(changed))
        response = subprocess.run(readback, shell=True,
                                  capture_output=True, text=True, timeout=8)
        assert response.returncode != 0
        assert "pipeline owner differs" in response.stderr
    pipeline.write_text(json.dumps(selected_record))
    response = subprocess.run(
        read_only_observation_script(
            str(root), sys.executable, "b" * 32, pipeline_id="f" * 32),
        shell=True, capture_output=True, text=True, timeout=8)
    assert response.returncode != 0
    assert "expected pipeline" in response.stderr or "differs" in response.stderr


def test_producer_completion_not_terminal_if_pipeline_still_running(
        tmp_path, monkeypatch):
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    root, source, controller = project(tmp_path)
    _slow_durable_producer(root, source)
    spec, record = selected(root, controller)
    req = project_current.binding(intent("c" * 32), record, spec, target())
    monkeypatch.setattr(project_current, "_RUN",
                        project_current._RUN.replace("timeout=14400", "timeout=0.75"))
    created = subprocess.run(project_current.remote_script(req),
                             shell=True, capture_output=True, text=True, timeout=12)
    assert created.returncode == 0, created.stderr
    directory = root / "state/image-build/remote-operations" / ("c" * 32)
    (directory / "result.json").write_text(json.dumps({
        "schema": "image-build-remote-result-v1", "operation_id": "c" * 32,
        "operation_type": "pipeline.submit",
        "source_repository": "zog144/image-build",
        "source_revision": git(source, "rev-parse", "HEAD"),
        "pipeline_id": "d" * 32,
        "status": "completed", "terminal_outcome": "success",
        "uncertainty": False,
    }))
    observed = subprocess.run(
        read_only_observation_script(
            str(root), sys.executable, "c" * 32, pipeline_id="d" * 32),
        shell=True, capture_output=True, text=True, timeout=8)
    assert observed.returncode == 0, observed.stderr
    evidence = json.loads(observed.stdout.strip())
    assert evidence["pipeline_status"] == "running"
    assert evidence["terminal_confirmed"] is False
    assert evidence["uncertainty"] is True


def test_owned_completed_pipeline_without_attempt_completion_is_not_terminal(
        tmp_path, monkeypatch):
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    root, source, controller = project(tmp_path)
    _slow_durable_producer(root, source)
    spec, record = selected(root, controller)
    request_id = "4" * 32
    binding = project_current.binding(intent(request_id), record, spec, target())
    monkeypatch.setattr(project_current, "_RUN",
                        project_current._RUN.replace("timeout=14400", "timeout=0.75"))
    run = subprocess.run(project_current.remote_script(binding), shell=True,
                         capture_output=True, text=True, timeout=12)
    assert run.returncode == 0, run.stderr
    pipeline = root / "state/image-build/pipelines" / ("d" * 32) / "pipeline.json"
    payload = json.loads(pipeline.read_text())
    payload.update({"status": "complete", "generation": "a" * 64})
    pipeline.write_text(json.dumps(payload))
    inspect = read_only_observation_script(str(root), sys.executable, request_id,
                                           pipeline_id="d" * 32)
    refused = subprocess.run(inspect, shell=True, capture_output=True,
                             text=True, timeout=8)
    assert refused.returncode != 0
    assert "attempt evidence missing" in refused.stderr
    # Even a counterfeit terminal producer result cannot replace the
    # actual attempt and pipeline generation readback.
    (root / "state/image-build/remote-operations" / request_id /
     "result.json").write_text(json.dumps({
         "schema": "image-build-remote-result-v1",
         "operation_id": request_id, "operation_type": "pipeline.submit",
         "source_repository": "zog144/image-build",
         "source_revision": git(source, "rev-parse", "HEAD"),
         "pipeline_id": "d" * 32,
         "status": "completed", "uncertainty": False,
         "terminal_outcome": "success",
    }))
    refused_again = subprocess.run(inspect, shell=True, capture_output=True,
                                   text=True, timeout=8)
    assert refused_again.returncode != 0
    assert "attempt evidence missing" in refused_again.stderr


def test_selected_project_observer_rejects_unprotected_or_symlinked_evidence(
        tmp_path, monkeypatch):
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    root, source, controller = project(tmp_path)
    _slow_durable_producer(root, source)
    spec, record = selected(root, controller)
    request_id = "5" * 32
    binding = project_current.binding(intent(request_id), record, spec, target())
    monkeypatch.setattr(project_current, "_RUN",
                        project_current._RUN.replace("timeout=14400", "timeout=0.75"))
    run = subprocess.run(project_current.remote_script(binding), shell=True,
                         capture_output=True, text=True, timeout=12)
    assert run.returncode == 0, run.stderr
    command = read_only_observation_script(
        str(root), sys.executable, request_id, pipeline_id="d" * 32)
    pipeline = root / "state/image-build/pipelines" / ("d" * 32) / "pipeline.json"
    original = pipeline.read_bytes()
    pipeline.chmod(0o666)
    unprotected = subprocess.run(command, shell=True, capture_output=True,
                                 text=True, timeout=8)
    assert unprotected.returncode != 0
    assert "unsafe selected Project evidence custody" in unprotected.stderr
    pipeline.chmod(0o644)
    pipeline.unlink()
    other = tmp_path / "unselected-pipeline.json"
    other.write_bytes(original)
    pipeline.symlink_to(other)
    redirected = subprocess.run(command, shell=True, capture_output=True,
                                text=True, timeout=8)
    assert redirected.returncode != 0
    assert "unsafe selected Project evidence custody" in redirected.stderr



def test_selected_project_rejects_symlinked_absolute_ancestor(tmp_path):
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    root, source, controller = project(tmp_path)
    alias = tmp_path / "redirected-parent"
    alias.symlink_to(root.parent, target_is_directory=True)
    redirected = alias / root.name
    assert redirected.is_dir() and not redirected.is_symlink()
    result = subprocess.run(
        read_only_observation_script(
            str(redirected), sys.executable, "e" * 32),
        shell=True, capture_output=True, text=True, timeout=8)
    assert result.returncode != 0
    assert not (root / "gateway-requests").exists()



@pytest.mark.parametrize("replace", ["file", "parent"])
def test_project_observer_no_follow_descriptor_rejects_inode_swap(
        tmp_path, monkeypatch, replace):
    """Simulate a name swap precisely between lstat and openat."""
    from zog.host_deploy.gateway.project_current_observation import _OBSERVER
    selected_root = tmp_path / "compiler-project"
    request_id = "a" * 32
    parent = selected_root / "gateway-requests"
    child = parent / request_id
    child.mkdir(parents=True)
    request_file = child / "request.json"
    request_file.write_text(json.dumps({
        "schema": "image-build-remote-operation-v1",
        "operation_id": request_id,
        "operation": "pipeline.submit",
        "arguments": {
            "mode": "image",
            "targets": ["libpng-final", "freetype-final", "fontconfig-final"]},
        "source": {"repository": "zog144/image-build",
                   "revision": "b" * 40},
    }))
    namespace = {"__builtins__": __builtins__}
    exec(_OBSERVER, namespace)
    original_open = os.open
    swapped = False

    def racing_open(name, flags, *args, **kwargs):
        nonlocal swapped
        trigger = ("request.json" if replace == "file" else "gateway-requests")
        if not swapped and name == trigger and kwargs.get("dir_fd") is not None:
            swapped = True
            if replace == "file":
                original = request_file.read_bytes()
                request_file.rename(child / "retained-original.json")
                request_file.write_bytes(original)
            else:
                parent.rename(selected_root / "retained-original-parent")
                # A newly created parent must not be treated as the lstat'ed
                # directory even if it contains identically named evidence.
                parent.mkdir()
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    with pytest.raises(ValueError, match="inode changed|ancestor changed"):
        namespace["observe"](str(selected_root), request_id)
    assert swapped is True
