"""Dispatch the currently selected Project and controller, not a pinned checkout.

The lane selects the Project and controller. At execution on that Host, the
producer uses that Project's *current* image-build checkout and package pins.
Existing pinned dispatch records remain immutable and readable.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex

from .. import image_build_lanes
from .github_dispatch import FIRST_FONTS_TASK
from .image_build_dispatch import REMOTE_SCHEMA, _canonical, _target
from .task_catalogue import REVIEWED_IMAGE_TASKS

SCHEMA = 4
REVISION = re.compile(r"[0-9a-f]{40}")
IDENTITY = re.compile(r"[0-9a-f]{32}")
TASK = FIRST_FONTS_TASK


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or str(PurePosixPath(value)) != value
            or any(part in {"", ".", ".."} for part in value.split("/")[1:])
            or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)):
        raise RuntimeError("Project/controller path is not normalized")
    return Path(value)


def _template(request_id):
    return {
        "schema": REMOTE_SCHEMA,
        "operation_id": request_id,
        "operation": "pipeline.submit",
        # Current source revision is resolved on the selected Project Host.
        "source": {"repository": "zog144/image-build"},
        "arguments": {
            "mode": "image",
            "targets": list(REVIEWED_IMAGE_TASKS[TASK]["targets"]),
        },
    }


def binding(request, record, spec, host):
    if (record.get("state") != "active"
            or spec["schema"] != image_build_lanes.INHERITED_SCHEMA
            or spec["mode"] != "managed"
            or request.get("operation") != "build.submit"
            or request.get("parameters") != {
                "lane": "gateway-first-fonts-runtime", "task": TASK
            }
            or not IDENTITY.fullmatch(request["request_id"])):
        raise RuntimeError("unsupported Project-current Fonts request")
    project = _path(spec["project_root"])
    controller = _path(record["controller_config"])
    if (controller.parent != project
            or record.get("source_root") != str(project / "source")
            or record.get("state_dir") != str(project / "state")
            or record.get("package_dir") != str(project / "source/project/package")):
        raise RuntimeError("lane does not select the stated Project/controller")
    template = _template(request["request_id"])
    value = {
        "schema": SCHEMA,
        "kind": REMOTE_SCHEMA,
        "direct_forward": True,
        "request_id": request["request_id"],
        "workspace_id": request["workspace_id"],
        "lane": request["parameters"]["lane"],
        "project_root": str(project),
        "controller_config": str(controller),
        "python_executable": spec["python_executable"],
        "target": _target(host),
        "remote_request": template,
        "remote_request_sha256": hashlib.sha256(_canonical(template)).hexdigest(),
    }
    return validate(value)


def validate(value):
    expected = {
        "schema", "kind", "direct_forward", "request_id", "workspace_id",
        "lane", "project_root", "controller_config", "python_executable",
        "target", "remote_request", "remote_request_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise RuntimeError("Project-current dispatch fields are invalid")
    if (value["schema"] != SCHEMA or value["kind"] != REMOTE_SCHEMA
            or value["direct_forward"] is not True
            or value["lane"] != "gateway-first-fonts-runtime"
            or not isinstance(value["request_id"], str)
            or not IDENTITY.fullmatch(value["request_id"])
            or not isinstance(value["workspace_id"], str)
            or not IDENTITY.fullmatch(value["workspace_id"])):
        raise RuntimeError("Project-current identity is invalid")
    project = _path(value["project_root"])
    controller = _path(value["controller_config"])
    if (controller.parent != project
            or controller.name not in ("controller.json",
                "controller-" + value["lane"] + "-inherited-v1.json")):
        raise RuntimeError("Project-current controller is not selected by lane")
    image_build_lanes.validate_python_executable(value["python_executable"])
    target = value["target"]
    if (_target({**target, "workspace_id": value["workspace_id"]}) != target):
        raise RuntimeError("Project-current SSM target is invalid")
    template = _template(value["request_id"])
    if (value["remote_request"] != template
            or value["remote_request_sha256"] !=
            hashlib.sha256(_canonical(template)).hexdigest()):
        raise RuntimeError("Project-current operation differs from supported Fonts task")
    return value


# Deliberately no source SHA or pin value here. They are read on the Project
# Host when the one durable SSM attempt executes. No cross-Project search.
_RUN = r'''
import hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path

project = Path(sys.argv[1])
controller = Path(sys.argv[2])
python = sys.argv[3]
operation_id = sys.argv[4]
template_digest = sys.argv[5]
source = project / "source"
state = project / "state"
request_path = project / "gateway-requests" / operation_id / "request.json"
try:
    command = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--verify", "HEAD"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    revision = command.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("Project has no usable current checkout")
    request = {
        "schema": "image-build-remote-operation-v1",
        "operation_id": operation_id,
        "operation": "pipeline.submit",
        "source": {"repository": "zog144/image-build", "revision": revision},
        "arguments": {"mode": "image",
                      "targets": ["libpng-final", "freetype-final", "fontconfig-final"]},
    }
    encoded = (json.dumps(request, sort_keys=True, separators=(",", ":"))
               + "\n").encode("ascii")
    request_path.parent.mkdir(parents=True, exist_ok=True)
    if request_path.exists() or request_path.is_symlink():
        if request_path.is_symlink() or request_path.read_bytes() != encoded:
            raise ValueError("existing producer operation belongs to another checkout")
    else:
        descriptor, temporary = tempfile.mkstemp(dir=request_path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, request_path)
            directory = os.open(request_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    env = dict(os.environ)
    env["PYTHONPATH"] = ":".join((
        str(source / "src"),
        str(project / "companions/build-record/src"),
        str(project / "companions/box-control/box-control/src"),
    ))
    result = subprocess.run(
        [python, "-m", "zog.image_build.remote_operations",
         "--repository-root", str(source),
         "--source-repository", "zog144/image-build",
         "--source-revision", revision,
         "--package-dir", str(source / "project/package"),
         "--state-dir", str(state),
         "--controller-config", str(controller), str(request_path)],
        env=env, cwd=str(source), capture_output=True, text=True, timeout=240,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("configured Project producer could not execute: " +
                           result.stderr[-1000:])
    output = result.stdout.strip().splitlines()
    if not output:
        raise RuntimeError("configured Project producer returned no result")
    produced = json.loads(output[-1])
    if (produced.get("schema") != "image-build-remote-result-v1"
            or produced.get("operation_id") != operation_id
            or produced.get("operation_type") != "pipeline.submit"
            or produced.get("source_revision") != revision):
        raise RuntimeError("Project producer result identity differs")
    summary = {k: produced.get(k) for k in (
        "status", "pipeline_id", "source_revision",
        "recipe_identity", "selected_generation", "terminal_outcome",
        "failure", "allowed_next_operations",
    )}
    raw = json.dumps(produced, sort_keys=True, separators=(",", ":")).encode()
    print(json.dumps({
        "schema": "host-deploy-image-build-receipt-v1",
        "request_id": operation_id,
        "remote_request_sha256": template_digest,
        "result_sha256": hashlib.sha256(raw).hexdigest(),
        "result_bytes": len(raw),
        "result": summary,
    }, sort_keys=True, separators=(",", ":")))
except Exception as error:
    raise SystemExit("configured Project build operation failed: " + str(error)) from error
'''


def remote_script(value):
    value = validate(value)
    return " ".join(shlex.quote(item) for item in (
        value["python_executable"], "-c", _RUN,
        value["project_root"], value["controller_config"],
        value["python_executable"], value["request_id"],
        value["remote_request_sha256"],
    ))
