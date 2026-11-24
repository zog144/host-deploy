"""Read-only Project-current producer/pipeline observation contract.

This is deliberately separate from the protected first/subsequent submission.
The same source runs inside the original bounded SSM invocation after a
producer timeout and in an explicit read-only Host inspection. It NEVER
calls image-build.RemoteOperations.execute(), pipeline.submit or resume.
"""
import json
import re
import shlex

OBSERVATION_SCHEMA = "host-deploy-project-current-observation-v1"
PRODUCER_TIMEOUT_SECONDS = 14400
CONTROL_TIMEOUT_SECONDS = 14700

# Standard-library-only. Runs against existing Project state, not its
# possibly newer installed/checked-out image-build source. No writes.
_OBSERVER = r"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

OP = re.compile(r"[0-9a-f]{32}")
REV = re.compile(r"[0-9a-f]{40}")
RESULT_SCHEMA = "image-build-remote-result-v1"
OBSERVATION_SCHEMA = "host-deploy-project-current-observation-v1"
FIXED_TARGETS = ["libpng-final", "freetype-final", "fontconfig-final"]

def read_json(path, maximum=1048576):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size > maximum
                or before.st_size <= 0):
            raise ValueError("unusable Project-current evidence file")
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns)):
            raise ValueError("Project-current evidence changed during readback")
        value = json.loads(raw)
        if type(value) is not dict:
            raise ValueError("Project-current evidence must be an object")
        return value
    finally:
        os.close(fd)

def observe(project, operation_id, expected_pipeline_id=None):
    project = Path(project)
    if (not project.is_absolute() or project.is_symlink()
            or not project.is_dir() or not OP.fullmatch(operation_id)
            or (expected_pipeline_id is not None
                and (type(expected_pipeline_id) is not str
                     or not OP.fullmatch(expected_pipeline_id)))):
        raise ValueError("invalid selected Project or operation identity")
    request = read_json(project / "gateway-requests" / operation_id / "request.json")
    if (request is None or request.get("schema") != "image-build-remote-operation-v1"
            or request.get("operation_id") != operation_id
            or request.get("operation") != "pipeline.submit"
            or request.get("arguments") !=
               {"mode": "image", "targets": FIXED_TARGETS}
            or type(request.get("source")) is not dict
            or request["source"].get("repository") != "zog144/image-build"
            or not isinstance(request["source"].get("revision"), str)
            or not REV.fullmatch(request["source"]["revision"])):
        raise ValueError("retained Project-current original request differs")
    revision = request["source"]["revision"]
    op_dir = project / "state/image-build/remote-operations" / operation_id
    producer_request = read_json(op_dir / "request.json")
    if producer_request is not None and producer_request != request:
        raise ValueError("producer request differs from retained operation")
    binding = read_json(op_dir / "binding.json")
    pipeline_id = None
    if binding is not None:
        pipeline_id = binding.get("pipeline_id")
        if (type(pipeline_id) is not str or not OP.fullmatch(pipeline_id)
                or set(binding) - {"pipeline_id", "recipe_snapshot"}):
            raise ValueError("invalid retained producer pipeline binding")
    if expected_pipeline_id is not None and pipeline_id is not None:
        if expected_pipeline_id != pipeline_id:
            raise ValueError("observed pipeline differs from approved observation")

    pipelines = project / "state/image-build/pipelines"
    if pipeline_id is None and pipelines.is_dir():
        # Recover a crash between durable pipeline preparation and binding.
        # A finite scan cannot accidentally become an unbounded lookup.
        matches = []
        count = 0
        for path in sorted(pipelines.glob("*/pipeline.json")):
            count += 1
            if count > 4096:
                raise ValueError("Project pipeline observation scan exceeds limit")
            record = read_json(path)
            owner = record.get("owner") if record is not None else None
            if (type(owner) is dict
                    and owner.get("contract") == request["schema"]
                    and owner.get("operation_id") == operation_id):
                if (owner.get("source_repository") != "zog144/image-build"
                        or owner.get("source_revision") != revision
                        or record.get("pipeline_id") != path.parent.name):
                    raise ValueError("owned pipeline record differs from original request")
                matches.append(path.parent.name)
        if len(matches) > 1:
            raise ValueError("one operation owns multiple pipelines")
        if matches:
            pipeline_id = matches[0]
    if expected_pipeline_id is not None and pipeline_id != expected_pipeline_id:
        raise ValueError("original operation does not own expected pipeline")
    pipeline = (read_json(pipelines / pipeline_id / "pipeline.json")
                if pipeline_id is not None else None)
    if pipeline_id is not None:
        if pipeline is None:
            raise ValueError("retained bound pipeline record is unavailable")
        owner = pipeline.get("owner")
        if (pipeline.get("pipeline_id") != pipeline_id
                or type(owner) is not dict
                or owner.get("contract") != request["schema"]
                or owner.get("operation_id") != operation_id
                or owner.get("source_repository") != "zog144/image-build"
                or owner.get("source_revision") != revision):
            raise ValueError("pipeline owner differs from immutable operation")
    result = read_json(op_dir / "result.json", 131072)
    if result is not None:
        if (result.get("schema") != RESULT_SCHEMA
                or result.get("operation_id") != operation_id
                or result.get("operation_type") != "pipeline.submit"
                or result.get("source_revision") != revision
                or result.get("source_repository") != "zog144/image-build"
                or result.get("pipeline_id") != pipeline_id):
            raise ValueError("producer result differs from original pipeline")
    status = result.get("status") if result is not None else "unreconciled"
    terminal = bool(
        result is not None and result.get("uncertainty") is False
        and ((status == "completed" and result.get("terminal_outcome") == "success"
              and pipeline is not None and pipeline.get("status") == "complete")
             or (status == "failed" and result.get("terminal_outcome") is not None))
    )
    attempts = (pipeline.get("attempts") if pipeline is not None else None)
    attempt_ids = sorted(attempts.values())[:24] if type(attempts) is dict else []
    if any(type(x) is not str or len(x) > 128 for x in attempt_ids):
        raise ValueError("invalid retained pipeline attempt identity")
    return {
        "schema": OBSERVATION_SCHEMA,
        "project_root": str(project),
        "request_id": operation_id,
        "operation_id": operation_id,
        "source_revision": revision,
        "pipeline_id": pipeline_id,
        "pipeline_status": pipeline.get("status") if pipeline is not None else None,
        "attempt_ids": attempt_ids,
        "producer_status": status,
        "terminal_outcome": result.get("terminal_outcome") if terminal else None,
        "terminal_confirmed": terminal,
        "uncertainty": not terminal,
        "mutation": False,
        "execution_authorized": False,
    }
"""


def read_only_observation_script(project_root, python_executable, request_id,
                                 *, pipeline_id=None):
    """Generate an explicit operator-controlled Host readback, never a submit."""
    from .project_current import _path, IDENTITY
    from .. import image_build_lanes

    project = _path(project_root)
    python = image_build_lanes.validate_python_executable(python_executable)
    if type(request_id) is not str or not IDENTITY.fullmatch(request_id):
        raise ValueError("invalid original Gateway request ID")
    if (pipeline_id is not None and
            (type(pipeline_id) is not str or not IDENTITY.fullmatch(pipeline_id))):
        raise ValueError("invalid retained pipeline ID")
    code = (_OBSERVER +
            '\nimport sys\n'
            'print(json.dumps(observe(sys.argv[1], sys.argv[2], '
            'sys.argv[3] if sys.argv[3] != "-" else None), '
            'sort_keys=True, separators=(",", ":")))\n')
    return " ".join(shlex.quote(x) for x in (
        python, "-I", "-B", "-c", code, str(project), request_id,
        pipeline_id if pipeline_id is not None else "-",
    ))
