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
from .project_current_observation import (
    _OBSERVER, PRODUCER_TIMEOUT_SECONDS, CONTROL_TIMEOUT_SECONDS,
    read_only_observation_script,
)

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


def verify_approved_lane(root, workspace, host, record, spec):
    """Verify CURRENT selected schema-5 existing Project, not Nov14 migration.

    The current verified lane/Project/controller is the authority. Historical
    schema-4 manifests, archived lanes, pending migration intents and old
    pipelines are evidence only, never admission prerequisites. This local
    validation does NOT claim to read the remote compiler: the exact expected
    installed controller digest is frozen into each NEW dispatch, and the
    protected one-use SSM operation verifies it before any producer writes.
    """
    from .. import existing_project_runtime as existing
    from .. import image_build_lanes as lanes
    expected_root = "/home/certbot-build-owner/certbot-seed"
    if (record.get("lane") != "gateway-first-fonts-runtime"
            or spec.get("lane") != "gateway-first-fonts-runtime"
            or record.get("schema") != lanes.INHERITED_SCHEMA
            or spec.get("schema") != lanes.INHERITED_SCHEMA
            or record.get("state") != "active"
            or record.get("specification") != spec
            or spec.get("mode") != "managed"
            or spec.get("project_selection") != "existing"
            or spec.get("project_root") != expected_root):
        raise RuntimeError("first Fonts current schema-5 existing Project selection differs")
    expected_controller = expected_root + "/" + existing.controller_file(spec)
    if (record.get("controller_config") != expected_controller
            or record.get("source_root") != expected_root + "/source"
            or record.get("package_dir") != expected_root + "/source/project/package"
            or record.get("state_dir") != expected_root + "/state"):
        raise RuntimeError("current certbot-seed Project/controller paths differ")
    # The prior source revision and package pin do not select the current
    # installed controller. Preserve optional historic fields, never use
    # them to require a matching November 14 checkout.
    if (type(workspace) is not dict or type(host) is not dict
            or host.get("workspace_id") != workspace.get("workspace_id")
            or host.get("region") != workspace.get("region")):
        raise RuntimeError("current Fonts workspace/compiler binding differs")
    from .image_build_dispatch import _target
    _target(host)  # validated account, region, instance (not legacy intent)
    return {
        "selection": "current-schema-5-existing-project",
        "project_root": expected_root,
        "controller_config": expected_controller,
        "controller_sha256": hashlib.sha256(existing.expected_bytes(spec)).hexdigest(),
        "execution_authorized": False,
        "historical_migration_required": False,
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
    from .. import existing_project_runtime as existing
    value = {
        "schema": SCHEMA,
        "controller_sha256": hashlib.sha256(existing.expected_bytes(spec)).hexdigest(),
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
    # Historical frozen schema-4 dispatches have no controller digest.
    # They remain readable and recoverable with their ORIGINAL script bytes.
    # New bindings freeze a digest from the actual selected schema-5 spec.
    if not isinstance(value, dict) or set(value) not in (
            expected, expected | {"controller_sha256"}):
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
    if "controller_sha256" in value and (
            type(value["controller_sha256"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", value["controller_sha256"])
            or controller.name != (
                "controller-" + value["lane"] + "-inherited-v1.json")):
        raise RuntimeError("current installed controller digest or filename differs")
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
_PROJECT_IMPORT_BOOTSTRAP = r'''
import importlib
import importlib.machinery
import sys
import types
from pathlib import Path

source = Path(sys.argv[1]).resolve(strict=True)
project = Path(sys.argv[2]).resolve(strict=True)
expected_root = (source / "src").resolve(strict=True)
expected_package = expected_root / "zog/image_build"
expected_init = expected_package / "__init__.py"
expected_module = expected_package / "remote_operations.py"
if (not expected_init.is_file() or not expected_module.is_file()
        or not expected_init.resolve(strict=True).is_relative_to(expected_root)
        or not expected_module.resolve(strict=True).is_relative_to(expected_root)):
    raise SystemExit("selected Project image-build module is missing or redirected")

# Preserve access to globally installed *other* zog components, but never
# allow their package initializer to choose the image-build implementation.
installed = importlib.machinery.PathFinder.find_spec("zog", sys.path)
fallback = list(installed.submodule_search_locations or ()) if installed else []
# Restore the selected Project's source-root import semantics for other
# Project-local top-level modules too; -I otherwise ignores PYTHONPATH.
source_roots = [
    source / "src",
    project / "companions/build-record/src",
    project / "companions/box-control/box-control/src",
]
sys.path[:0] = [str(path) for path in source_roots if path.is_dir()]
locations = [path / "zog" for path in source_roots]
namespace = types.ModuleType("zog")
namespace.__package__ = "zog"
namespace.__path__ = [str(p) for p in locations if p.is_dir()] + fallback
namespace.__spec__ = importlib.machinery.ModuleSpec(
    "zog", loader=None, is_package=True,
)
sys.modules["zog"] = namespace

# Check the resolution before executing any image-build code, not merely
# after an incorrect globally installed module might have run.
selected = importlib.machinery.PathFinder.find_spec(
    "zog.image_build", namespace.__path__,
)
if (selected is None or selected.origin is None
        or Path(selected.origin).resolve(strict=True) !=
        expected_init.resolve(strict=True)):
    raise SystemExit("image-build package does not resolve to selected Project")
selected_module = importlib.machinery.PathFinder.find_spec(
    "zog.image_build.remote_operations", [str(expected_package)],
)
if (selected_module is None or selected_module.origin is None
        or Path(selected_module.origin).resolve(strict=True) !=
        expected_module.resolve(strict=True)):
    raise SystemExit("image-build executable does not resolve to selected Project")
# Validate any Project-local companion before module import. A regular
# installed zog package may supply missing components, but it must never
# replace one explicitly selected from the Project's companions directory.
def companion(name, root):
    package = root / "zog" / name
    if not package.is_dir():
        return {"present": False}
    expected = package / "__init__.py"
    if not expected.is_file() or expected.is_symlink():
        raise SystemExit("selected Project " + name + " companion is incomplete")
    found = importlib.machinery.PathFinder.find_spec(
        "zog." + name, namespace.__path__,
    )
    if (found is None or found.origin is None
            or Path(found.origin).resolve(strict=True) !=
               expected.resolve(strict=True)):
        raise SystemExit("selected Project " + name + " companion was shadowed")
    return {"present": True, "origin": str(expected)}

companions = {
    "build-record": companion("build_record", source_roots[1]),
    "box-control": companion("box_control", source_roots[2]),
}
module = importlib.import_module("zog.image_build.remote_operations")
if (Path(module.__file__).resolve(strict=True) !=
        expected_module.resolve(strict=True)):
    raise SystemExit("imported image-build executable differs from selected Project")
# Import-only readiness takes the *identical* namespace and module-origin
# path used for a real Project-current submission. It is deliberately
# nonmutating: no request creation, producer main(), pipeline or controller job.
if sys.argv[3:] == ["--inspect-only"]:
    import json
    report = {
        "schema": "host-deploy-project-current-import-readiness-v1",
        "source_root": str(source),
        "project_root": str(project),
        "python_executable": sys.executable,
        "image_build_package": str(expected_init),
        "remote_operations": str(expected_module),
        "companions": companions,
        "mutation": False,
        "execution_authorized": False,
    }
    print(json.dumps(report, sort_keys=True))
elif (len(sys.argv[3:]) == 13
      and [sys.argv[i] for i in (3, 5, 7, 9, 11, 13)] == [
          "--repository-root", "--source-repository", "--source-revision",
          "--package-dir", "--state-dir", "--controller-config",
      ]):
    sys.argv = [str(expected_module), *sys.argv[3:]]
    module.main()
else:
    raise SystemExit("unsupported Project-current import invocation")'''


_RUN = r'''
import hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path

# The observation helper is standard-library-only and reads the original
# durable image-build request/binding/owner. It never submits a pipeline.
exec(__ZOG_OBSERVER_BOOTSTRAP__)

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
    # A site-installed regular 'zog' can eclipse the selected Project's
    # implicit 'src/zog' namespace even if PYTHONPATH starts with source/src.
    # Run an isolated child with an explicit namespace and verify the module's
    # actual file before invoking the producer. Keep other installed zog
    # components available after the selected Project and its companions.
    bootstrap = __ZOG_PROJECT_IMPORT_BOOTSTRAP__
    try:
        completed = subprocess.run(
            [python, "-I", "-B", "-c", bootstrap, str(source), str(project),
             "--repository-root", str(source),
             "--source-repository", "zog144/image-build",
             "--source-revision", revision,
             "--package-dir", str(source / "project/package"),
             "--state-dir", str(state),
             "--controller-config", str(controller), str(request_path)],
            cwd=str(source), capture_output=True, text=True,
            timeout=__ZOG_PRODUCER_TIMEOUT__, check=False,
        )
    except subprocess.TimeoutExpired:
        # The producer may have prepared an immutable pipeline and started
        # a durable root-control job before its control wait expired. A
        # Python subprocess timeout is NOT a pipeline terminal outcome.
        observed = observe(project, operation_id)
        produced = {
            "schema": "image-build-remote-result-v1",
            "operation_id": operation_id,
            "operation_type": "pipeline.submit",
            "source_revision": revision,
            "source_repository": "zog144/image-build",
            "status": "pending", "pipeline_id": observed["pipeline_id"],
            "terminal_outcome": None, "uncertainty": True,
            "attempt_ids": observed["attempt_ids"],
            "reconciliation_required": True,
            "failure": {"type": "producer-timeout",
                        "reason": "bounded producer wait expired; observe original operation"},
            "allowed_next_operations": ["pipeline.inspect"],
        }
    else:
        if completed.returncode != 0:
            # A failed transport/subprocess is also not proof that a
            # durable pipeline failed. Only independent owned-state evidence
            # may support this uncertain recovery receipt.
            observed = observe(project, operation_id)
            if (observed["pipeline_id"] is None
                    and observed["producer_status"] == "unreconciled"):
                raise RuntimeError(
                    "configured Project producer failed before durable pipeline: "
                    + completed.stderr[-1000:])
            produced = {
                "schema": "image-build-remote-result-v1",
                "operation_id": operation_id,
                "operation_type": "pipeline.submit",
                "source_revision": revision,
                "source_repository": "zog144/image-build",
                "status": "pending", "pipeline_id": observed["pipeline_id"],
                "terminal_outcome": None, "uncertainty": True,
                "attempt_ids": observed["attempt_ids"],
                "reconciliation_required": True,
                "failure": {"type": "producer-exit",
                            "reason": "producer exited; durable pipeline requires reconciliation"},
                "allowed_next_operations": ["pipeline.inspect"],
            }
        else:
            output = completed.stdout.strip().splitlines()
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
        "failure", "allowed_next_operations", "uncertainty",
        "attempt_ids", "reconciliation_required",
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
_RUN = (_RUN.replace("__ZOG_PROJECT_IMPORT_BOOTSTRAP__", repr(_PROJECT_IMPORT_BOOTSTRAP))
           .replace("__ZOG_OBSERVER_BOOTSTRAP__", repr(_OBSERVER))
           .replace("__ZOG_PRODUCER_TIMEOUT__", str(PRODUCER_TIMEOUT_SECONDS)))



def read_only_import_script(project_root, python_executable):
    """Use the actual Project-current import bootstrap without writing a request.

    The selected Project source comes before local companions, which come
    before installed third-party packages and remaining Zog components.
    This command is safe for Work's normal readiness inspection; it does not
    call remote_operations.main() or submit anything to box/root-control.
    """
    project = _path(project_root)
    python = image_build_lanes.validate_python_executable(python_executable)
    return " ".join(shlex.quote(item) for item in (
        python, "-I", "-B", "-c", _PROJECT_IMPORT_BOOTSTRAP,
        str(project / "source"), str(project), "--inspect-only",
    ))



# The following is injected ONLY into newly frozen current-schema-5
# dispatches. The original _RUN string and its argv remain byte-for-byte
# stable for saved historical schema-4 dispatch / journal readback.
_CURRENT_CONTROLLER_PREFLIGHT = r'''
    # Actual selected-Host verification runs in the protected, once-only
    # build invocation, BEFORE request_path.parent.mkdir or any pipeline call.
    # The current installed controller must equal the exact selected lane
    # specification, not an archived November 14 controller.
    expected_controller_sha256 = sys.argv[6]
    if not re.fullmatch(r"[0-9a-f]{64}", expected_controller_sha256):
        raise RuntimeError("unreviewed current controller digest")
    if (not project.is_absolute() or not controller.is_absolute()
            or controller.parent != project
            or controller.name !=
                "controller-gateway-first-fonts-runtime-inherited-v1.json"):
        raise RuntimeError("selected current Project/controller path differs")
    def verified_directory(parent_fd, part):
        info = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
        if not __import__('stat').S_ISDIR(info.st_mode):
            raise RuntimeError("selected Project ancestor is not a directory")
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        opened = os.fstat(fd)
        if ((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
                != (opened.st_dev, opened.st_ino, opened.st_uid,
                    opened.st_gid, opened.st_mode)):
            os.close(fd)
            raise RuntimeError("selected Project ancestry changed during open")
        sticky_root = (opened.st_uid == 0 and
                       __import__('stat').S_IMODE(opened.st_mode) == 0o1777)
        if opened.st_mode & 0o022 and not sticky_root:
            os.close(fd)
            raise RuntimeError("selected Project ancestor is writable")
        return fd, opened
    project_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    project_ancestors = []
    try:
        for name in project.parts[1:]:
            next_fd, info = verified_directory(project_fd, name)
            os.close(project_fd)
            project_fd = next_fd
            project_ancestors.append(info)
        project_info = project_ancestors[-1]
        if (not all(x.st_uid in (0, project_info.st_uid)
                    for x in project_ancestors)
                or __import__('stat').S_IMODE(project_info.st_mode) & 0o077):
            raise RuntimeError("selected Project ownership or private mode differs")
        config_info = os.stat(controller.name, dir_fd=project_fd,
                              follow_symlinks=False)
        if (not __import__('stat').S_ISREG(config_info.st_mode)
                or config_info.st_nlink != 1
                or config_info.st_uid not in (0, project_info.st_uid)
                or config_info.st_mode & 0o022
                or not 0 < config_info.st_size <= 65536):
            raise RuntimeError("installed current controller file is unsafe")
        config_fd = os.open(controller.name, os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=project_fd)
        try:
            before = os.fstat(config_fd)
            if ((before.st_dev, before.st_ino, before.st_mode,
                 before.st_uid, before.st_gid, before.st_nlink,
                 before.st_size) !=
                (config_info.st_dev, config_info.st_ino, config_info.st_mode,
                 config_info.st_uid, config_info.st_gid, config_info.st_nlink,
                 config_info.st_size)):
                raise RuntimeError("selected current controller inode changed")
            installed = os.read(config_fd, 65537)
            after = os.fstat(config_fd)
            still = os.stat(controller.name, dir_fd=project_fd,
                            follow_symlinks=False)
            if (len(installed) != before.st_size or
                    (before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns) or
                    (still.st_dev, still.st_ino, still.st_mode,
                     still.st_uid) !=
                    (before.st_dev, before.st_ino, before.st_mode,
                     before.st_uid)):
                raise RuntimeError("installed current controller changed during readback")
            if hashlib.sha256(installed).hexdigest() != expected_controller_sha256:
                raise RuntimeError("installed current controller differs from schema-5 selection")
        finally:
            os.close(config_fd)
        # Use the *opened* selected source and cleared Git environment, not
        # any inherited GIT_DIR/GIT_WORK_TREE/GIT_CONFIG_COUNT override.
        source_fd, _ = verified_directory(project_fd, "source")
        try:
            git_dir, _ = verified_directory(source_fd, ".git")
            os.close(git_dir)
            git_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                       "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0",
                       "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": "/dev/null"}
            command = subprocess.run(
                ["/usr/bin/git", "-C", "/proc/self/fd/" + str(source_fd),
                 "rev-parse", "--verify", "HEAD"],
                pass_fds=(source_fd,), env=git_env,
                capture_output=True, text=True, timeout=30, check=True)
            revision = command.stdout.strip()
            if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                raise RuntimeError("selected Project has no current Git checkout")
        finally:
            os.close(source_fd)
        # Existing controller and Project path must remain the same immediately
        # before any producer-owned file changes occur.
        if (os.fstat(project_fd).st_dev, os.fstat(project_fd).st_ino) != (
                project_info.st_dev, project_info.st_ino):
            raise RuntimeError("selected Project changed before producer")
    finally:
        os.close(project_fd)
'''
# Keep the original _RUN unchanged for immutable historical bindings.
_CURRENT_RUN_MARKER = '''    command = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--verify", "HEAD"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    revision = command.stdout.strip()'''
if _RUN.count(_CURRENT_RUN_MARKER) != 1:
    raise RuntimeError("Project-current preflight source insertion point differs")
_RUN_CURRENT = _RUN.replace(_CURRENT_RUN_MARKER, _CURRENT_CONTROLLER_PREFLIGHT)


def remote_script(value):
    value = validate(value)
    newer = "controller_sha256" in value
    script = _RUN_CURRENT if newer else _RUN
    arguments = (
        value["python_executable"], "-c", script,
        value["project_root"], value["controller_config"],
        value["python_executable"], value["request_id"],
        value["remote_request_sha256"],
    )
    if newer:
        arguments += (value["controller_sha256"],)
    return " ".join(shlex.quote(item) for item in arguments)
