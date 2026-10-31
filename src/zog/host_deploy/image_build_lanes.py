"""Durable image-build lane ownership for one shared development host.

A lane is one independent box-control Project plus one image-build state universe.
Lanes share the EC2 host and root-control socket, never mutable build state.
"""
import json
from pathlib import Path, PurePosixPath
import re
import shlex

from .provision import configuration
from .runner import Host
from .workspace import locked, save

SCHEMA = 4
EXTERNAL_STATE_SCHEMA = 3
MONTHLY_PIN_SCHEMA = 2
LEGACY_SCHEMA = 1
_RECORD_SCHEMAS = {LEGACY_SCHEMA, MONTHLY_PIN_SCHEMA, EXTERNAL_STATE_SCHEMA, SCHEMA}
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
_REVISION = re.compile(r"[0-9a-f]{40,64}")
DEFAULT_ROOT = Path("/var/lib/zog/image-build-lanes")


def _positive(value, name, maximum=2**63 - 1):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError("invalid lane " + name)
    return value


def _monthly_pin_path(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("invalid lane monthly_pin_repository_path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or not path.parts
        or path.parts[0] == ".git"
    ):
        raise ValueError("lane monthly pin path must be safe repository-relative source evidence")
    return path.as_posix()


def _observed_state_path(value, project_root):
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("invalid lane observed_state_dir")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("lane observed_state_dir must be absolute")
    if path == Path(project_root) / "state":
        raise ValueError("lane observed_state_dir must differ from control state")
    return str(path)


def validate_python_executable(value):
    """Validate a server-owned, normalized absolute interpreter path."""
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 512:
        raise ValueError("lane python_executable must be an absolute path")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError("lane python_executable contains control or whitespace")
    if any(part in {"", ".", ".."} for part in value.split("/")[1:]):
        raise ValueError("lane python_executable must be normalized")
    if str(PurePosixPath(value)) != value:
        raise ValueError("lane python_executable must be normalized")
    return value


def validate(spec):
    common = {
        "schema",
        "lane",
        "mode",
        "source_repository",
        "source_revision",
        "provenance_host_id",
        "provenance_project_id",
        "project_root",
        "resource_policy",
        "controller",
    }
    schema = spec.get("schema") if isinstance(spec, dict) else None
    if schema == LEGACY_SCHEMA:
        required = common | {"pin_identity"}
    elif schema == MONTHLY_PIN_SCHEMA:
        required = common | {
            "monthly_pin_repository_path",
            "monthly_pin_identity",
        }
    elif schema in {EXTERNAL_STATE_SCHEMA, SCHEMA}:
        required = common | {
            "monthly_pin_repository_path",
            "monthly_pin_identity",
            "observed_state_dir",
        }
        if schema == SCHEMA:
            required.add("python_executable")
    else:
        raise ValueError("unsupported image-build lane specification")
    if set(spec) != required:
        raise ValueError("unsupported image-build lane specification")
    lane = spec["lane"]
    if not isinstance(lane, str) or not _NAME.fullmatch(lane):
        raise ValueError("invalid image-build lane name")
    if spec["mode"] not in {"managed", "reservation"}:
        raise ValueError("image-build lane mode must be managed or reservation")
    if (
        not isinstance(spec["source_repository"], str)
        or not spec["source_repository"]
        or len(spec["source_repository"]) > 512
    ):
        raise ValueError("invalid lane source repository")
    if not isinstance(spec["source_revision"], str) or not _REVISION.fullmatch(
        spec["source_revision"]
    ):
        raise ValueError("lane source revision must be an immutable commit identity")
    if schema in {EXTERNAL_STATE_SCHEMA, SCHEMA}:
        _observed_state_path(spec["observed_state_dir"], spec["project_root"])
        if spec["observed_state_dir"] is not None and spec["mode"] != "managed":
            raise ValueError("external observed state requires a managed lane")
    if schema == SCHEMA:
        validate_python_executable(spec["python_executable"])
    if schema == LEGACY_SCHEMA:
        pin_identity = spec["pin_identity"]
        if (
            not isinstance(pin_identity, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin_identity)
        ):
            raise ValueError("lane pin_identity must be an exact SHA-256")
    else:
        _monthly_pin_path(spec["monthly_pin_repository_path"])
        monthly_pin_identity = spec["monthly_pin_identity"]
        if (
            not isinstance(monthly_pin_identity, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", monthly_pin_identity)
        ):
            raise ValueError("lane monthly_pin_identity must be the exact monthly pin SHA-256")
    for key in ("provenance_host_id", "provenance_project_id"):
        if (
            not isinstance(spec[key], str)
            or not spec[key]
            or len(spec[key]) > 512
            or any(ord(c) < 32 for c in spec[key])
        ):
            raise ValueError("invalid lane " + key)
    project_root = Path(spec["project_root"])
    if not project_root.is_absolute():
        raise ValueError("lane project_root must be absolute")
    if spec["mode"] == "managed" and project_root.name != lane:
        raise ValueError("managed lane project_root must end with the lane name")
    policy = spec["resource_policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "memory_maximum_bytes",
        "thread_count_maximum",
        "cpu_weight",
        "disk_reservation_bytes",
    }:
        raise ValueError("invalid lane resource policy")
    _positive(policy["memory_maximum_bytes"], "memory_maximum_bytes")
    _positive(policy["thread_count_maximum"], "thread_count_maximum", 2**31 - 1)
    _positive(policy["cpu_weight"], "cpu_weight", 10000)
    _positive(policy["disk_reservation_bytes"], "disk_reservation_bytes")
    controller = spec["controller"]
    required_controller = {
        "socket_path",
        "execution_user_id",
        "execution_group_id",
        "startup_timeout_seconds",
        "execution_timeout_seconds",
        "termination_grace_seconds",
        "wait_timeout_seconds",
        "transport_timeout_seconds",
    }
    if not isinstance(controller, dict) or set(controller) != required_controller:
        raise ValueError("invalid lane controller policy")
    socket_path = Path(controller["socket_path"])
    if not socket_path.is_absolute():
        raise ValueError("lane root-control socket must be absolute")
    for key in ("execution_user_id", "execution_group_id"):
        _positive(controller[key], key, 2**31 - 1)
    for key in (
        "startup_timeout_seconds",
        "execution_timeout_seconds",
        "termination_grace_seconds",
        "transport_timeout_seconds",
    ):
        _positive(controller[key], key, 604800)
    if (
        type(controller["wait_timeout_seconds"]) is not int
        or not 0 <= controller["wait_timeout_seconds"] <= 604800
    ):
        raise ValueError("invalid lane wait_timeout_seconds")
    return json.loads(json.dumps(spec))


def specification(
    lane,
    *,
    mode="managed",
    source_repository,
    source_revision,
    monthly_pin_repository_path,
    monthly_pin_identity,
    provenance_host_id,
    provenance_project_id,
    memory_maximum_bytes,
    thread_count_maximum,
    cpu_weight,
    disk_reservation_bytes,
    execution_user_id,
    execution_group_id,
    project_root=None,
    socket_path="/run/zog/root-control.sock",
    startup_timeout_seconds=30,
    execution_timeout_seconds=3600,
    termination_grace_seconds=10,
    wait_timeout_seconds=0,
    transport_timeout_seconds=45,
    observed_state_dir=None,
    python_executable=None,
):
    project_root = Path(project_root) if project_root else DEFAULT_ROOT / lane
    return validate(
        {
            "schema": SCHEMA if python_executable is not None else EXTERNAL_STATE_SCHEMA,
            **({"python_executable": python_executable} if python_executable is not None else {}),
            "lane": lane,
            "mode": mode,
            "source_repository": source_repository,
            "source_revision": source_revision,
            "monthly_pin_repository_path": monthly_pin_repository_path,
            "monthly_pin_identity": monthly_pin_identity,
            "observed_state_dir": (
                str(Path(observed_state_dir))
                if observed_state_dir is not None
                else None
            ),
            "provenance_host_id": provenance_host_id,
            "provenance_project_id": provenance_project_id,
            "project_root": str(project_root),
            "resource_policy": {
                "memory_maximum_bytes": memory_maximum_bytes,
                "thread_count_maximum": thread_count_maximum,
                "cpu_weight": cpu_weight,
                "disk_reservation_bytes": disk_reservation_bytes,
            },
            "controller": {
                "socket_path": socket_path,
                "execution_user_id": execution_user_id,
                "execution_group_id": execution_group_id,
                "startup_timeout_seconds": startup_timeout_seconds,
                "execution_timeout_seconds": execution_timeout_seconds,
                "termination_grace_seconds": termination_grace_seconds,
                "wait_timeout_seconds": wait_timeout_seconds,
                "transport_timeout_seconds": transport_timeout_seconds,
            },
        }
    )


def _path(root, lane):
    if not isinstance(lane, str) or not _NAME.fullmatch(lane):
        raise ValueError("invalid image-build lane name")
    return Path(root) / "image-build-lanes" / (lane + ".json")


def prepare(directory, spec):
    spec = validate(spec)
    with locked(directory) as root:
        path = _path(root, spec["lane"])
        others = []
        lane_dir = path.parent
        if lane_dir.exists():
            for candidate in lane_dir.glob("*.json"):
                if candidate == path:
                    continue
                try:
                    others.append(json.loads(candidate.read_text()))
                except (OSError, ValueError, TypeError):
                    raise RuntimeError("invalid retained image-build lane record")
        project_root = Path(spec["project_root"]).resolve()
        basename = project_root.name
        for item in others:
            if item.get("state") == "retired":
                continue
            other = item["specification"]
            other_root = Path(other["project_root"]).resolve()
            if other_root == project_root:
                raise ValueError("image-build project root is already owned by another lane")
            if (
                spec["mode"] == "managed"
                and other.get("mode", "managed") == "managed"
                and other_root.name == basename
            ):
                raise ValueError("managed image-build project basename must be host-unique")
        if path.exists():
            record = json.loads(path.read_text())
            if record.get("schema") not in _RECORD_SCHEMAS or record["specification"] != spec:
                raise ValueError("existing image-build lane is bound to different inputs")
            return record
        record = {
            "schema": spec["schema"],
            "lane": spec["lane"],
            "specification": spec,
            "state": "prepared",
        }
        save(path, record)
        return record


def specification_sha256(spec):
    """Canonical digest of the exact previously retained lane specification."""
    import hashlib

    valid = validate(spec)
    payload = json.dumps(
        valid, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def bind_python_runtime(
    directory, lane, python_executable, *, expected_specification_sha256
):
    """Explicitly bind a prepared managed schema-3 lane, with preserved evidence.

    This never activates the lane, alters an active lane, or changes a dispatch.
    The caller supplies the original specification digest to guard against stale
    workspace selection. Replaying the same binding is read-only and idempotent.
    """
    python_executable = validate_python_executable(python_executable)
    if (
        not isinstance(expected_specification_sha256, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_specification_sha256)
    ):
        raise ValueError("expected_specification_sha256 must be an exact SHA-256")
    with locked(directory) as root:
        path = _path(root, lane)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("image-build lane record must be a regular file")
        record = json.loads(path.read_text())
        spec = validate(record.get("specification"))
        if record.get("lane") != lane or spec["lane"] != lane:
            raise RuntimeError("lane identity differs from the requested lane")
        if spec["mode"] != "managed":
            raise RuntimeError("runtime binding requires a managed lane")
        if spec["schema"] == SCHEMA:
            previous = record.get("runtime_binding_upgrade")
            if (
                record.get("schema") != SCHEMA
                or not isinstance(previous, dict)
                or previous.get("schema") != 1
                or previous.get("previous_schema") != EXTERNAL_STATE_SCHEMA
                or previous.get("previous_specification_sha256")
                != expected_specification_sha256
                or previous.get("python_executable") != python_executable
                or spec["python_executable"] != python_executable
            ):
                raise ValueError("image-build lane Python runtime already bound differently")
            return record
        if (
            record.get("schema") != EXTERNAL_STATE_SCHEMA
            or spec["schema"] != EXTERNAL_STATE_SCHEMA
            or record.get("state") != "prepared"
            or set(record) != {"schema", "lane", "specification", "state"}
        ):
            raise RuntimeError(
                "runtime binding requires an unactivated prepared schema-3 lane"
            )
        current_digest = specification_sha256(spec)
        if current_digest != expected_specification_sha256:
            raise ValueError("prepared lane specification digest differs from expected")
        new_spec = validate({
            **spec, "schema": SCHEMA, "python_executable": python_executable
        })
        record["schema"] = SCHEMA
        record["specification"] = new_spec
        record["runtime_binding_upgrade"] = {
            "schema": 1,
            "previous_schema": EXTERNAL_STATE_SCHEMA,
            "previous_specification_sha256": current_digest,
            "python_executable": python_executable,
        }
        save(path, record)
        return record


RUNTIME_COMPANION_SCHEMA = 1
BUILD_RECORD_REPOSITORY = "zog144/build-record"
BUILD_RECORD_COMPATIBILITY = "771af9429e83da40fd503625a6b4ba8329acee35"
BOX_CONTROL_REPOSITORY = "zog144/box-control"
BOX_CONTROL_COMPATIBILITY = "c8e65abde37d6e2d9ce6fd3622e289826a253642"

# Source-bound acceptance checkpoint for the reviewed unattended toolchain
# producer. The historical constants above MUST NOT be silently repointed:
# already prepared dispatch bindings use those exact revisions.
TOOLCHAIN_PRODUCER_REVISION = "857bb454e64102afa51a93ce0b9f8cce5924b67c"
# A separate, restored-lock producer; no historical lane or compatibility
# record is rewritten. The producer's runtime requirements were byte-identical.
RESTORED_TOOLCHAIN_PRODUCER_REVISION = "31e6121cdf9fd05336286529666e2c35cdbe0831"
TOOLCHAIN_BUILD_RECORD_COMPATIBILITY = "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
TOOLCHAIN_BOX_CONTROL_COMPATIBILITY = "644170fc441863307092f329bf7e23cb64eb33e2"
# Separate fresh-only tuple. Historical source/companion bindings above remain
# valid for readback and recovery; no prior lane may be silently promoted.
FRESH_CROSS_BOOTSTRAP_PRODUCER_REVISION = "53ad8c2166e6b73dffbc722c2e47ccf3593612ec"
FRESH_CROSS_BOOTSTRAP_BOX_CONTROL_REVISION = "b7934882cfacd2fbfd60c7964713ed3dde7f9460"
# Reviewed image-build runtime_requirements.py at the exact producer revision
# still declares build-record a866... as its validated API checkpoint.
FRESH_CROSS_BOOTSTRAP_BUILD_RECORD_REVISION = "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
CONTROLLER_COMPANION_SCHEMA = 1


def expected_build_record_revision(producer_revision):
    if producer_revision == FRESH_CROSS_BOOTSTRAP_PRODUCER_REVISION:
        return FRESH_CROSS_BOOTSTRAP_BUILD_RECORD_REVISION
    if producer_revision in (
            TOOLCHAIN_PRODUCER_REVISION, RESTORED_TOOLCHAIN_PRODUCER_REVISION):
        return TOOLCHAIN_BUILD_RECORD_COMPATIBILITY
    return BUILD_RECORD_COMPATIBILITY


def expected_controller_revision(producer_revision):
    if producer_revision == FRESH_CROSS_BOOTSTRAP_PRODUCER_REVISION:
        return FRESH_CROSS_BOOTSTRAP_BOX_CONTROL_REVISION
    if producer_revision in (
            TOOLCHAIN_PRODUCER_REVISION, RESTORED_TOOLCHAIN_PRODUCER_REVISION):
        return TOOLCHAIN_BOX_CONTROL_COMPATIBILITY
    return BOX_CONTROL_COMPATIBILITY


def validate_controller_companion(value, *, project_root=None):
    """Exact producer-specific, lane-owned controller checkout binding."""
    if (not isinstance(value, dict) or set(value) != {
            "schema", "repository", "revision", "source_root",
            "producer_revision"} or value["schema"] != CONTROLLER_COMPANION_SCHEMA
            or value["repository"] != BOX_CONTROL_REPOSITORY
            or not isinstance(value["producer_revision"], str)
            or not _REVISION.fullmatch(value["producer_revision"])
            or not isinstance(value["revision"], str)
            or value["revision"] != expected_controller_revision(
                value["producer_revision"])):
        raise ValueError("unreviewed producer/controller companion compatibility")
    source_root = value["source_root"]
    if (not isinstance(source_root, str) or not source_root.startswith("/")
            or any(ord(char) < 33 or ord(char) == 127 for char in source_root)
            or any(part in {"", ".", ".."} for part in source_root.split("/")[1:])
            or str(PurePosixPath(source_root)) != source_root):
        raise ValueError("controller companion source root must be normalized absolute")
    if (project_root is not None
            and source_root != str(PurePosixPath(project_root) /
                                   "companions/box-control")):
        raise ValueError("controller companion must use owned lane controller checkout")
    return json.loads(json.dumps(value, sort_keys=True))


def bind_controller_companion(
    directory, lane, *, producer_revision, repository,
    revision, source_root, expected_specification_sha256,
):
    """One-time explicit controller binding; leave all prior lanes untouched."""
    expected = {
        "schema": CONTROLLER_COMPANION_SCHEMA,
        "repository": repository, "revision": revision,
        "source_root": source_root, "producer_revision": producer_revision,
    }
    with locked(directory) as root:
        path = _path(root, lane)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("controller companion requires regular lane record")
        record = json.loads(path.read_text())
        spec = validate(record.get("specification"))
        if (record.get("schema") != SCHEMA
                or record.get("lane") != lane or spec["lane"] != lane
                or record.get("state") != "active"
                or spec["schema"] != SCHEMA or spec["mode"] != "managed"):
            raise RuntimeError("controller companion requires active managed schema-4 lane")
        candidate = validate_controller_companion(
            expected, project_root=spec["project_root"])
        if (specification_sha256(spec) != expected_specification_sha256
                or spec["source_revision"] != producer_revision):
            raise ValueError("controller companion differs from frozen lane source")
        current = record.get("controller_companion")
        if current is not None:
            if validate_controller_companion(
                current, project_root=spec["project_root"]) != candidate:
                raise ValueError("controller companion already bound differently")
            return record
        record["controller_companion"] = candidate
        save(path, record)
        return record




def bind_compiler_execution_identity(
    directory, lane, *, identity, expected_specification_sha256,
):
    """One-time approved nonroot owner binding for a NEW typed compiler lane.

    No history rewrite, no UID inference, no defaults and no identity rotation.
    The actual host passwd/socket/source DAC is checked separately by the
    fixed, root-controlled SSM transition before each producer invocation.
    """
    from .gateway.compiler_execution_identity import validate as validate_identity
    with locked(directory) as root:
        path = _path(root, lane)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("nonroot compiler requires regular lane record")
        record = json.loads(path.read_text())
        spec = validate(record.get("specification"))
        companion = validate_runtime_companion(
            record.get("runtime_companion"), project_root=spec["project_root"])
        controller = validate_controller_companion(
            record.get("controller_companion"), project_root=spec["project_root"])
        if (record.get("schema") != SCHEMA or record.get("lane") != lane
                or record.get("state") != "active"
                or spec["schema"] != SCHEMA or spec["mode"] != "managed"
                or spec["source_revision"] not in (
                    RESTORED_TOOLCHAIN_PRODUCER_REVISION,
                    FRESH_CROSS_BOOTSTRAP_PRODUCER_REVISION,
                )
                or spec["observed_state_dir"] is not None
                or controller["producer_revision"] != spec["source_revision"]
                or companion["producer_revision"] != spec["source_revision"]
                or specification_sha256(spec) != expected_specification_sha256):
            raise RuntimeError("nonroot compiler requires reviewed separate managed lane")
        expected = validate_identity(
            identity, project_root=spec["project_root"],
            python_executable=spec["python_executable"],
            source_revision=spec["source_revision"],
            build_record_revision=companion["revision"],
            box_control_revision=controller["revision"],
            task_identity=identity["task_catalogue_identity"],
        )
        if spec["source_revision"] == FRESH_CROSS_BOOTSTRAP_PRODUCER_REVISION:
            selected_controller = spec["controller"]
            if (selected_controller["socket_path"] != expected["socket_path"]
                    or selected_controller["execution_user_id"] != expected["build_uid"]
                    or selected_controller["execution_group_id"] != expected["build_gid"]
                    or selected_controller["execution_timeout_seconds"] > 21600
                    or spec["resource_policy"]["disk_reservation_bytes"] > 32 * 1024**3):
                raise RuntimeError("fresh compiler owner/socket/resource bounds differ from lane")
        existing = record.get("compiler_execution_identity")
        if existing is not None:
            if existing != expected:
                raise RuntimeError("compiler execution identity already frozen differently")
            return record
        record["compiler_execution_identity"] = expected
        save(path, record)
        return record


def validate_runtime_companion(value, *, project_root=None):
    """Immutable lane-owned exact build-record source identity."""
    if not isinstance(value, dict) or set(value) != {
        "schema", "repository", "revision", "source_root", "producer_revision",
    } or value["schema"] != RUNTIME_COMPANION_SCHEMA:
        raise ValueError("invalid lane runtime companion contract")
    if value["repository"] != BUILD_RECORD_REPOSITORY:
        raise ValueError("unsupported runtime companion repository")
    if (not isinstance(value["revision"], str)
            or not _REVISION.fullmatch(value["revision"])):
        raise ValueError("runtime companion revision must be an exact commit")
    if (not isinstance(value["producer_revision"], str)
            or not _REVISION.fullmatch(value["producer_revision"])):
        raise ValueError("runtime companion producer revision must be an exact commit")
    root = value["source_root"]
    if (not isinstance(root, str) or not root.startswith("/")
            or any(ord(c) < 33 for c in root)
            or any(p in ("", ".", "..") for p in root.split("/")[1:])
            or str(PurePosixPath(root)) != root):
        raise ValueError("runtime companion source root must be normalized absolute")
    if project_root is not None and not (
        PurePosixPath(root).is_relative_to(PurePosixPath(project_root) / "companions")
    ):
        raise ValueError("runtime companion must be below the owned lane companions directory")
    return json.loads(json.dumps(value, sort_keys=True))


def bind_runtime_companion(
    directory, lane, *, producer_revision, repository,
    revision, source_root, expected_specification_sha256,
):
    """Explicit one-time active-lane companion binding, not an implicit migration."""
    expected = {
        "schema": RUNTIME_COMPANION_SCHEMA,
        "repository": repository, "revision": revision,
        "source_root": source_root, "producer_revision": producer_revision,
    }
    with locked(directory) as root:
        path = _path(root, lane)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("image-build lane record must be a regular file")
        record = json.loads(path.read_text())
        spec = validate(record.get("specification"))
        if (record.get("lane") != lane or spec["lane"] != lane
                or record.get("state") != "active"
                or spec["schema"] != SCHEMA or spec["mode"] != "managed"):
            raise RuntimeError("runtime companion binding requires an active managed schema-4 lane")
        candidate = validate_runtime_companion(expected, project_root=spec["project_root"])
        if (specification_sha256(spec) != expected_specification_sha256
                or spec["source_revision"] != producer_revision):
            raise ValueError("runtime companion differs from exact lane source specification")
        current = record.get("runtime_companion")
        if current is not None:
            if validate_runtime_companion(current, project_root=spec["project_root"]) != candidate:
                raise ValueError("lane runtime companion is already bound differently")
            return record
        record["runtime_companion"] = candidate
        save(path, record)
        return record


def inspect(directory, lane):
    with locked(directory) as root:
        record = json.loads(_path(root, lane).read_text())
        if record.get("schema") not in _RECORD_SCHEMAS:
            raise ValueError("invalid image-build lane record")
        validate(record["specification"])
        return record


def _controller(spec):
    policy = spec["resource_policy"]
    controller = spec["controller"]
    return {
        "project_root": spec["project_root"],
        "socket_path": controller["socket_path"],
        "execution_user_id": controller["execution_user_id"],
        "execution_group_id": controller["execution_group_id"],
        "startup_timeout_seconds": controller["startup_timeout_seconds"],
        "execution_timeout_seconds": controller["execution_timeout_seconds"],
        "termination_grace_seconds": controller["termination_grace_seconds"],
        "wait_timeout_seconds": controller["wait_timeout_seconds"],
        "transport_timeout_seconds": controller["transport_timeout_seconds"],
        "resource_limits": {
            "thread-count-maximum": policy["thread_count_maximum"],
            "memory-maximum-bytes": policy["memory_maximum_bytes"],
            "cpu-weight": policy["cpu_weight"],
        },
    }


def _active_records(root):
    directory = Path(root) / "image-build-lanes"
    if not directory.exists():
        return []
    result = []
    for path in sorted(directory.glob("*.json")):
        record = json.loads(path.read_text())
        if record.get("state") == "active":
            validate(record["specification"])
            result.append(record)
    return result


def _capacity(host, project_root):
    # Measure the filesystem that will contain the lane without requiring its
    # parent directory to exist yet.
    code = (
        "import json,os;"
        "from pathlib import Path;"
        "m=int(open('/proc/meminfo').read().split('MemTotal:')[1].split()[0])*1024;"
        f"p=Path({str(project_root.parent)!r});"
        "p=next((x for x in (p,*p.parents) if x.exists()),Path('/'));"
        "v=os.statvfs(p);"
        "print(json.dumps({'memory_bytes':m,'disk_free_bytes':v.f_bavail*v.f_frsize}))"
    )
    return json.loads(host.command("python3 -c " + shlex.quote(code)))


def activate(directory, lane):
    with locked(directory) as root:
        workspace, host_config = configuration(root)
        path = _path(root, lane)
        record = json.loads(path.read_text())
        spec = validate(record["specification"])
        host = Host(host_config)
        if spec["schema"] == SCHEMA:
            runtime_preflight(host, spec["python_executable"])
        capacity = _capacity(host, Path(spec["project_root"]))
        active = [
            item
            for item in _active_records(root)
            if item["lane"] != lane
        ]
        reserved_memory = sum(
            item["specification"]["resource_policy"]["memory_maximum_bytes"]
            for item in active
        )
        reserved_disk = sum(
            item["specification"]["resource_policy"]["disk_reservation_bytes"]
            for item in active
        )
        policy = spec["resource_policy"]
        if reserved_memory + policy["memory_maximum_bytes"] > capacity["memory_bytes"]:
            raise RuntimeError("image-build lane memory reservations exceed host capacity")
        if reserved_disk + policy["disk_reservation_bytes"] > capacity["disk_free_bytes"]:
            raise RuntimeError("image-build lane disk reservations exceed free capacity")
        project = Path(spec["project_root"])
        if spec["mode"] == "managed":
            command = "set -eu\n" + "\n".join(
                "install -d -m 0755 " + shlex.quote(str(project / name))
                for name in ("", "package", "application", "catalogue", "state", "source")
            )
            host.command(command)
            controller = _controller(spec)
            host.upload(
                (json.dumps(controller, sort_keys=True, indent=2) + "\n").encode(),
                str(project / "controller.json"),
            )
            record.update(
                controller_config=str(project / "controller.json"),
                source_root=str(project / "source"),
                package_dir=str(project / "source" / "project" / "package"),
                state_dir=str(project / "state"),
            )
        record.update(state="active", capacity=capacity)
        save(path, record)
        return record


def retire(directory, lane):
    """Stop admitting new work. Remote build state is deliberately retained."""
    with locked(directory) as root:
        path = _path(root, lane)
        record = json.loads(path.read_text())
        validate(record["specification"])
        record["state"] = "retired"
        save(path, record)
        return record


def runtime_preflight(
    host, python_executable, source_root=None, *, required_capabilities=()
):
    """Read-only operation-aware remote CLI dependency/capability probe.

    Capabilities are selected by the trusted operation argv, not request-supplied
    module names. This does not invoke CLI.main or write provenance/build state.
    """
    validate_python_executable(python_executable)
    capabilities = {
        "provenance": "zog.build_record",
        "controller": "zog.box_control",
        "host-identity": "zog.host_identify",
    }
    if (
        not isinstance(required_capabilities, (list, tuple))
        or len(set(required_capabilities)) != len(required_capabilities)
        or any(name not in capabilities for name in required_capabilities)
        or (required_capabilities and source_root is None)
    ):
        raise ValueError("unsupported remote CLI preflight capabilities")
    selected = sorted(required_capabilities)
    code = [
        "import importlib,json,os,pathlib,sys",
        "p=pathlib.Path(" + repr(python_executable) + ")",
        "assert p.is_file() and not p.is_symlink() and os.access(p,os.X_OK), 'unsafe Python executable'",
        "assert sys.version_info >= (3,11), 'Python >=3.11 required'",
        "assert os.path.realpath(sys.executable)==os.path.realpath(str(p)), 'Python executable mismatch'",
        "module=None",
        "companions={}",
    ]
    if source_root is not None:
        code.extend([
            "m=importlib.import_module('zog.image_build.remote_operations')",
            "module=os.path.realpath(m.__file__)",
            "assert os.path.commonpath([module,os.path.realpath("
            + repr(str(source_root)) + ")])==os.path.realpath("
            + repr(str(source_root)) + "), 'module outside source'",
        ])
    for name in selected:
        module = capabilities[name]
        code.extend([
            "c=importlib.import_module(" + repr(module) + ")",
            "companions[" + repr(name) + "]={'module':" + repr(module)
            + ",'path':os.path.realpath(c.__file__)}",
        ])
        if name == "provenance":
            code.extend([
                "model=importlib.import_module('zog.build_record.model')",
                "assert callable(getattr(c,'make_record',None)), 'build-record make_record unavailable'",
                "assert callable(getattr(c,'Store',None)), 'build-record Store unavailable'",
                "assert callable(getattr(model,'digest',None)), 'build-record digest unavailable'",
            ])
        elif name == "controller":
            code.extend([
                "runtime=importlib.import_module('zog.box_control.runtime.root_control')",
                "assert callable(getattr(c,'BoxControl',None)), 'box-control BoxControl unavailable'",
                "assert callable(getattr(c,'Project',None)), 'box-control Project unavailable'",
                "assert callable(getattr(runtime,'RootControlSystemdTransport',None)), 'box-control transport unavailable'",
            ])
    code.append(
        "print(json.dumps({'python_executable':str(p),"
        "'python_version':list(sys.version_info[:3]),"
        "'resolved_executable':os.path.realpath(sys.executable),"
        "'source_module':module,'capabilities':companions},sort_keys=True))"
    )
    command = (
        ("env PYTHONDONTWRITEBYTECODE=1 " + shlex.quote("PYTHONPATH=" + str(Path(source_root) / "src")) + " ")
        if source_root is not None else "env PYTHONDONTWRITEBYTECODE=1 "
    ) + shlex.quote(python_executable) + " -c " + shlex.quote("\n".join(code))
    report = json.loads(host.command(command, seconds=120))
    if (
        not isinstance(report, dict)
        or set(report) != {
            "python_executable", "python_version", "resolved_executable",
            "source_module", "capabilities",
        }
        or report["python_executable"] != python_executable
        or not isinstance(report["python_version"], list)
        or len(report["python_version"]) != 3
        or any(type(part) is not int for part in report["python_version"])
        or report["python_version"][:2] < [3, 11]
        or not isinstance(report["resolved_executable"], str)
        or not report["resolved_executable"].startswith("/")
        or (source_root is not None and not isinstance(report["source_module"], str))
        or not isinstance(report["capabilities"], dict)
        or set(report["capabilities"]) != set(selected)
        or any(
            not isinstance(item, dict)
            or item.get("module") != capabilities[name]
            or not isinstance(item.get("path"), str)
            or not item["path"].startswith("/")
            for name, item in report["capabilities"].items()
        )
    ):
        raise RuntimeError("image-build runtime preflight returned invalid evidence")
    return report


def remote_operation_argv(record, request_path):
    """Return argv for an already deployed exact source checkout."""
    if record.get("state") != "active":
        raise RuntimeError("image-build lane is not active")
    spec = validate(record["specification"])
    if spec["mode"] != "managed":
        raise RuntimeError("reservation-only lane does not execute remote operations")
    if spec["schema"] == LEGACY_SCHEMA:
        raise RuntimeError(
            "legacy image-build lane lacks explicit monthly provenance pin binding"
        )
    request_path = Path(request_path)
    if not request_path.is_absolute():
        raise ValueError("remote request path must be absolute")
    monthly_pin = Path(record["source_root"]).joinpath(
        *PurePosixPath(spec["monthly_pin_repository_path"]).parts
    )
    argv = [
        "env",
        "PYTHONPATH=" + str(Path(record["source_root"]) / "src"),
        (spec["python_executable"] if spec["schema"] == SCHEMA else "python3"),
        "-m",
        "zog.image_build.remote_operations",
        "--repository-root",
        record["source_root"],
        "--source-repository",
        spec["source_repository"],
        "--source-revision",
        spec["source_revision"],
        "--package-dir",
        record["package_dir"],
        "--state-dir",
        record["state_dir"],
    ]
    observed_state = (
        spec["observed_state_dir"]
        if spec["schema"] in {EXTERNAL_STATE_SCHEMA, SCHEMA}
        else None
    )
    if observed_state is None:
        argv.extend(["--controller-config", record["controller_config"]])
    else:
        argv.extend(["--observed-state-dir", observed_state])
    argv.extend(
        [
            "--provenance-host-id",
            spec["provenance_host_id"],
            "--provenance-project-id",
            spec["provenance_project_id"],
            "--provenance-pin",
            str(monthly_pin),
            "--expected-pin-digest",
            spec["monthly_pin_identity"],
            str(request_path),
        ]
    )
    return argv
