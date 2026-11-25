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
GENERATION = re.compile(r"[0-9a-f]{64}")
ATTEMPT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")

def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")).hexdigest()


def _checked_directory(parent_fd, name):
    '''Open one named directory, binding no-follow lstat to the opened inode.'''
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("selected Project ancestor is not a directory")
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    opened = os.fstat(fd)
    if ((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            != (opened.st_dev, opened.st_ino, opened.st_mode,
                opened.st_uid, opened.st_gid)):
        os.close(fd)
        raise ValueError("selected Project ancestor changed during open")
    return fd, opened


def _opened_project(project):
    '''Anchor the complete absolute ancestry at the filesystem root.'''
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC)
    ancestors = [os.fstat(fd)]
    try:
        for component in project.parts[1:]:
            next_fd, metadata = _checked_directory(fd, component)
            os.close(fd)
            fd = next_fd
            ancestors.append(metadata)
        project_stat = ancestors[-1]
        uid = project_stat.st_uid
        if os.geteuid() not in (0, uid):
            raise ValueError("observer identity differs from selected Project")
        # /tmp's root-owned sticky traversal is permitted in disposable
        # source tests; on a native Host, all other ancestors must be
        # non-writable by group and other. No symlink is permitted anywhere.
        for metadata in ancestors:
            sticky_root = (metadata.st_uid == 0
                           and stat.S_IMODE(metadata.st_mode) == 0o1777)
            if (metadata.st_uid not in (0, uid)
                    or (metadata.st_mode & 0o022 and not sticky_root)):
                raise ValueError("selected Project ancestor custody is unsafe")
        return fd, project_stat
    except BaseException:
        os.close(fd)
        raise


def observe(project, operation_id, expected_pipeline_id=None):
    project = Path(project)
    if (not project.is_absolute() or not OP.fullmatch(operation_id)
            or (expected_pipeline_id is not None
                and (type(expected_pipeline_id) is not str
                     or not OP.fullmatch(expected_pipeline_id)))):
        raise ValueError("invalid selected Project or operation identity")
    project_fd, root_metadata = _opened_project(project)
    project_owner_uid = root_metadata.st_uid
    observer_uid = os.geteuid()
    allowed_evidence_uids = {project_owner_uid}
    if observer_uid == 0:
        allowed_evidence_uids.add(0)

    def read(path, maximum=1048576):
        try:
            relative = path.relative_to(project)
        except ValueError as error:
            raise ValueError("observation escaped selected Project") from error
        if not relative.parts:
            raise ValueError("observation requires an evidence file")
        current_fd = os.dup(project_fd)
        try:
            for part in relative.parts[:-1]:
                try:
                    next_fd, info = _checked_directory(current_fd, part)
                except FileNotFoundError:
                    return None
                if info.st_uid not in allowed_evidence_uids or info.st_mode & 0o022:
                    os.close(next_fd)
                    raise ValueError("unsafe selected Project evidence directory")
                os.close(current_fd)
                current_fd = next_fd
            name = relative.parts[-1]
            try:
                expected = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if (not stat.S_ISREG(expected.st_mode)
                    or expected.st_uid not in allowed_evidence_uids
                    or expected.st_mode & 0o022 or expected.st_nlink != 1
                    or not 0 < expected.st_size <= maximum):
                raise ValueError("unsafe selected Project evidence file")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=current_fd)
            try:
                before = os.fstat(fd)
                if ((before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                     before.st_mode, before.st_nlink, before.st_size)
                        != (expected.st_dev, expected.st_ino, expected.st_uid,
                            expected.st_gid, expected.st_mode,
                            expected.st_nlink, expected.st_size)):
                    raise ValueError("selected Project evidence inode changed")
                raw = os.read(fd, maximum + 1)
                after = os.fstat(fd)
                named = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                if (len(raw) != before.st_size
                        or (before.st_dev, before.st_ino, before.st_size,
                            before.st_mtime_ns) !=
                           (after.st_dev, after.st_ino, after.st_size,
                            after.st_mtime_ns)
                        or (named.st_dev, named.st_ino, named.st_mode,
                            named.st_uid, named.st_gid) !=
                           (before.st_dev, before.st_ino, before.st_mode,
                            before.st_uid, before.st_gid)):
                    raise ValueError("Project-current evidence changed during readback")
                value = json.loads(raw)
                if type(value) is not dict:
                    raise ValueError("Project-current evidence must be an object")
                return value
            finally:
                os.close(fd)
        finally:
            os.close(current_fd)

    try:
        request = read(project / "gateway-requests" / operation_id / "request.json")
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
        producer_request = read(op_dir / "request.json")
        if producer_request is not None and producer_request != request:
            raise ValueError("producer request differs from retained operation")
        binding = read(op_dir / "binding.json")
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
        if pipeline_id is None:
            # Enumerate only through verified directory descriptors; glob() would
            # follow pathname ancestry not bound to any opened Project descriptor.
            scan_fd = os.dup(project_fd)
            try:
                missing = False
                for part in ("state", "image-build", "pipelines"):
                    try:
                        next_fd, info = _checked_directory(scan_fd, part)
                    except FileNotFoundError:
                        missing = True
                        break
                    if info.st_uid not in allowed_evidence_uids or info.st_mode & 0o022:
                        os.close(next_fd)
                        raise ValueError("unsafe pipeline inventory directory")
                    os.close(scan_fd)
                    scan_fd = next_fd
                matches = []
                if not missing:
                    names = sorted(os.listdir(scan_fd))
                    if len(names) > 4096:
                        raise ValueError("Project pipeline observation scan exceeds limit")
                    for name in names:
                        if not OP.fullmatch(name):
                            raise ValueError("foreign pipeline directory identity")
                        record = read(pipelines / name / "pipeline.json")
                        owner = record.get("owner") if record is not None else None
                        if (type(owner) is dict
                                and owner.get("contract") == request["schema"]
                                and owner.get("operation_id") == operation_id):
                            if (owner.get("source_repository") != "zog144/image-build"
                                    or owner.get("source_revision") != revision
                                    or record.get("pipeline_id") != name):
                                raise ValueError("owned pipeline record differs from original request")
                            matches.append(name)
                if len(matches) > 1:
                    raise ValueError("one operation owns multiple pipelines")
                if matches:
                    pipeline_id = matches[0]
            finally:
                os.close(scan_fd)
        if expected_pipeline_id is not None and pipeline_id != expected_pipeline_id:
            raise ValueError("original operation does not own expected pipeline")
        pipeline = (read(pipelines / pipeline_id / "pipeline.json")
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
        result = read(op_dir / "result.json", 131072)
        if result is not None:
            if (result.get("schema") != RESULT_SCHEMA
                    or result.get("operation_id") != operation_id
                    or result.get("operation_type") != "pipeline.submit"
                    or result.get("source_revision") != revision
                    or result.get("source_repository") != "zog144/image-build"
                    or result.get("pipeline_id") != pipeline_id):
                raise ValueError("producer result differs from original pipeline")
        # image-build's only source-supported terminal success publication
        # is its owned pipeline.json status=complete *after* all attempt status
        # files are durably written complete for the same generation. Its
        # original remote-operations/result.json may be absent or stale
        # "pending" after an interrupted/timeout submit, so it is NOT a
        # required success precondition and must never override pipeline state.
        attempts = pipeline.get("attempts") if pipeline is not None else None
        if pipeline is not None:
            if (pipeline.get("schema") != 1
                    or pipeline.get("operation") != "image"
                    or pipeline.get("arguments", {}).get("targets") != FIXED_TARGETS
                    or type(attempts) is not dict or len(attempts) > 128):
                raise ValueError("owned Fonts pipeline structure differs")
        attempt_ids = sorted(attempts.values()) if type(attempts) is dict else []
        if any(type(x) is not str or not ATTEMPT.fullmatch(x) for x in attempt_ids):
            raise ValueError("invalid retained pipeline attempt identity")
        evidence = {
            "request_sha256": digest(request),
            "producer_request_sha256": digest(producer_request)
                if producer_request is not None else None,
            "binding_sha256": digest(binding) if binding is not None else None,
            "pipeline_sha256": digest(pipeline) if pipeline is not None else None,
            "result_sha256": digest(result) if result is not None else None,
            "attempt_statuses": {},
        }
        complete = False
        if pipeline is not None and pipeline.get("status") == "complete":
            generation = pipeline.get("generation")
            if (type(generation) is not str or not GENERATION.fullmatch(generation)
                    or not attempt_ids or len(set(attempt_ids)) != len(attempt_ids)):
                raise ValueError("completed pipeline lacks unique bounded generation/attempts")
            for attempt_id in attempt_ids:
                observed = read(project / "state/image-build/attempts" / attempt_id
                                / "status.json", 131072)
                if (observed is None or observed.get("status") != "complete"
                        or observed.get("generation") != generation):
                    raise ValueError("completed pipeline attempt evidence missing or differs")
                evidence["attempt_statuses"][attempt_id] = digest(observed)
            complete = True
        # Bound cross-file observation: a resumed producer must not race this
        # readback by changing the pipeline or binding while attempt status
        # records are being inspected. Refuse the mixed snapshot rather than
        # claiming a terminal outcome from different moments in time.
        if pipeline_id is not None:
            refreshed = read(pipelines / pipeline_id / "pipeline.json")
            if refreshed != pipeline:
                raise ValueError("owned pipeline changed during observation")
        if read(op_dir / "binding.json") != binding:
            raise ValueError("original producer pipeline binding changed")

        # An image-build-owned terminal command failure is confirmed only when
        # its original producer result exists and the pipeline is *not running*.
        # Pending/unknown executions must not become terminal Gateway failure.
        failure = bool(
            result is not None and result.get("status") == "failed"
            and result.get("uncertainty") is False
            and type(result.get("terminal_outcome")) is str
            and bool(result["terminal_outcome"])
            and type(result.get("failure")) is dict
            and result["failure"].get("kind") == "command-exit"
            and pipeline is not None and pipeline.get("status") == "pending"
        )
        terminal = complete or failure
        status = ("completed" if complete else
                  "failed" if failure else
                  result.get("status") if result is not None else "unreconciled")
        if not terminal and status in ("completed", "failed"):
            status = "pending"
        outcome = ("success" if complete else
                   result["terminal_outcome"] if failure else None)
        evidence["evidence_sha256"] = digest(evidence)
        check_fd, check_stat = _opened_project(project)
        try:
            if (check_stat.st_dev, check_stat.st_ino, check_stat.st_uid,
                    check_stat.st_mode) != (
                    root_metadata.st_dev, root_metadata.st_ino,
                    root_metadata.st_uid, root_metadata.st_mode):
                raise ValueError("selected Project changed during observation")
        finally:
            os.close(check_fd)
        return {
            "schema": OBSERVATION_SCHEMA,
            "project_root": str(project),
            "project_owner_uid": project_owner_uid,
            "request_id": operation_id,
            "operation_id": operation_id,
            "source_revision": revision,
            "pipeline_id": pipeline_id,
            "pipeline_status": pipeline.get("status") if pipeline is not None else None,
            "attempt_ids": attempt_ids,
            "evidence": evidence,
            "evidence_source": "local-selected-project",
            "producer_status": status,
            "terminal_outcome": outcome,
            "terminal_confirmed": terminal,
            "uncertainty": not terminal,
            "mutation": False,
            "execution_authorized": False,
        }
    finally:
        os.close(project_fd)
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


def observe_selected_project(project_root, request_id, *, pipeline_id=None):
    """Read actual local selected-Host evidence; never accept supplied status.

    Invoke this only from the trusted Gateway administrator running on the
    selected Host. A different Host lacks the selected Project root and
    cannot satisfy the retained ownership/source/attempt checks. The
    embedded, reviewed standard-library observer executes *only* local
    read-only filesystem calls; no producer/module import, subprocess,
    SendCommand or controller action is made.
    """
    from .project_current import _path, IDENTITY
    project = _path(project_root)
    if (type(request_id) is not str or not IDENTITY.fullmatch(request_id)
            or (pipeline_id is not None and
                (type(pipeline_id) is not str or
                 not IDENTITY.fullmatch(pipeline_id)))):
        raise ValueError("invalid original Project-current observation identity")
    namespace = {"__builtins__": __builtins__}
    exec(_OBSERVER, namespace)
    return namespace["observe"](str(project), request_id, pipeline_id)
