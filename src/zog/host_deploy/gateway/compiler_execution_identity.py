"""Approved nonroot image-build producer execution identity.

Only root-owned lane admission may install this schema. Root SSM is a
transport; its wrapper must drop to the controller owner for producer calls.
"""
import json
import re
from pathlib import PurePosixPath

LEGACY_SCHEMA = "host-deploy-compiler-execution-v1"
SCHEMA = "host-deploy-compiler-execution-v2"
FRESH_SCHEMA = "host-deploy-compiler-execution-v3"
FRESH_PRODUCER_REVISION = "53ad8c2166e6b73dffbc722c2e47ccf3593612ec"
FRESH_BOX_CONTROL_REVISION = "b7934882cfacd2fbfd60c7964713ed3dde7f9460"
FRESH_ROOT_CONTROL_REVISION = "5185a2ae6e7177feccda8cb34d99d7c5f0b5d040"
FRESH_BUILD_RECORD_REVISION = "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
FRESH_SCOPE = "host-deploy-fresh-cross-bootstrap-v1"
FRESH_DISK_BYTES = 32 * 1024**3
FRESH_MAX_SECONDS = 6 * 3600
ROOT_CONTROL_REVISION = "e4f25110c854c000bdde5ec564c8119370da9a52"
ROOT_CONTROL_REVIEW_HEAD = "8a9583924109ef324eb80071953151c8c7e20b33"
_SHA = re.compile(r"[a-f0-9]{40}\Z")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
FIELDS = {
    "schema", "controller_uid", "controller_gid", "controller_home",
    "project_root", "build_uid", "build_gid", "socket_path",
    "source_revision", "build_record_revision", "box_control_revision",
    "python_executable", "task_catalogue_identity",
    "root_control_revision",
}
LEGACY_FIELDS = FIELDS - {"root_control_revision"}
FRESH_FIELDS = FIELDS | {"fresh_scope"}
FRESH_SCOPE_FIELDS = {"schema", "phase", "execution_limit_seconds",
                      "additional_disk_bytes", "existing_host_only",
                      "automatic_later_phases"}


def _absolute(value):
    if type(value) is not str or not value.startswith("/") or len(value) > 1024:
        return False
    path = PurePosixPath(value)
    return (str(path) == value and
            all(part not in ("", ".", "..") for part in value.split("/")[1:]) and
            all(ord(char) >= 33 and ord(char) != 127 for char in value))


def validate(value, *, project_root, python_executable, source_revision,
             build_record_revision, box_control_revision, task_identity,
             allow_historical=False):
    if type(value) is not dict:
        raise ValueError("invalid nonroot compiler execution binding")
    historical = value.get("schema") == LEGACY_SCHEMA
    fresh = value.get("schema") == FRESH_SCHEMA
    if (set(value) != (LEGACY_FIELDS if historical else
                       FRESH_FIELDS if fresh else FIELDS)
            or (historical and not allow_historical)
            or (fresh and source_revision != FRESH_PRODUCER_REVISION)
            or (not fresh and source_revision == FRESH_PRODUCER_REVISION)
            or (value.get("schema") not in (LEGACY_SCHEMA, SCHEMA, FRESH_SCHEMA))):
        raise ValueError("unreviewed nonroot compiler execution schema")
    if fresh:
        if (value["root_control_revision"] != FRESH_ROOT_CONTROL_REVISION
                or value["source_revision"] != FRESH_PRODUCER_REVISION
                or value["box_control_revision"] != FRESH_BOX_CONTROL_REVISION
                or value["build_record_revision"] != FRESH_BUILD_RECORD_REVISION
                or not isinstance(value["fresh_scope"], dict)
                or set(value["fresh_scope"]) != FRESH_SCOPE_FIELDS
                or value["fresh_scope"] != {
                    "schema": FRESH_SCOPE, "phase": "cross-bootstrap",
                    "execution_limit_seconds": FRESH_MAX_SECONDS,
                    "additional_disk_bytes": FRESH_DISK_BYTES,
                    "existing_host_only": True,
                    "automatic_later_phases": False,
                }):
            raise ValueError("fresh compiler scope/source/controller differs from approval")
    elif (not historical and
          value["root_control_revision"] != ROOT_CONTROL_REVISION):
        raise ValueError("root-control revision differs from reviewed controller tuple")
    for key in ("controller_uid", "controller_gid", "build_uid", "build_gid"):
        if type(value[key]) is not int or value[key] <= 0 or value[key] >= 2**31:
            raise ValueError("compiler identity requires nonzero numeric UID/GID")
    if (value["controller_uid"] == value["build_uid"]
            or value["controller_gid"] == value["build_gid"]):
        raise ValueError("compiler controller and build identities must be separate")
    for key in ("controller_home", "project_root", "socket_path", "python_executable"):
        if not _absolute(value[key]):
            raise ValueError("compiler execution path is not normalized absolute")
    home = PurePosixPath(value["controller_home"])
    if home in (PurePosixPath("/"), PurePosixPath("/root")):
        raise ValueError("controller owner must have a dedicated nonroot home")
    project = PurePosixPath(project_root)
    if (value["project_root"] != project_root or project == home
            or home not in project.parents):
        raise ValueError("compiler project must be strictly inside controller home")
    if fresh:
        if (not re.fullmatch(r"/run/zog/root-control-[a-z0-9][a-z0-9-]{0,47}\.sock",
                             value["socket_path"])
                or value["socket_path"] == "/run/zog/root-control.sock"):
            raise ValueError("fresh compiler must use a dedicated reviewed controller socket")
    elif value["socket_path"] != "/run/zog/root-control.sock":
        raise ValueError("unreviewed privileged controller socket")
    for key, expected in (
        ("source_revision", source_revision),
        ("build_record_revision", build_record_revision),
        ("box_control_revision", box_control_revision),
        ("python_executable", python_executable),
        ("task_catalogue_identity", task_identity),
    ):
        if value[key] != expected:
            raise ValueError("compiler execution identity differs from protected task")
    if any(not _SHA.fullmatch(value[k]) for k in
           ("source_revision", "build_record_revision", "box_control_revision")):
        raise ValueError("invalid compiler source revision")
    if type(task_identity) is not str or not _DIGEST.fullmatch(task_identity):
        raise ValueError("invalid protected task digest")
    return json.loads(json.dumps(value, sort_keys=True))


# Executed only by the fixed, root-side SSM control wrapper. Not a client-
# supplied script. The target process gets a genuine kernel nonroot identity,
# the passwd database's own home, and NO supplemental groups or inherited env.
IDENTITY_RUNTIME = r'''
import os
import pwd
import stat
from pathlib import Path

# Exact root-control executable revision. The documentation-only receipt
# head is different and cannot substitute for executable provenance.
REVIEWED_ROOT_CONTROL_REVISION = "e4f25110c854c000bdde5ec564c8119370da9a52"
FRESH_ROOT_CONTROL_REVISION = "5185a2ae6e7177feccda8cb34d99d7c5f0b5d040"

def _trusted_identity(value, source, record_root, controller_root):
    if os.geteuid() != 0:
        raise RuntimeError("compiler identity transition requires root transport")
    if value.get("schema") == "host-deploy-compiler-execution-v3":
        if (value.get("root_control_revision") != FRESH_ROOT_CONTROL_REVISION
                or value.get("source_revision") != "53ad8c2166e6b73dffbc722c2e47ccf3593612ec"
                or value.get("box_control_revision") != "b7934882cfacd2fbfd60c7964713ed3dde7f9460"
                or value.get("fresh_scope") != {
                    "schema": "host-deploy-fresh-cross-bootstrap-v1",
                    "phase": "cross-bootstrap",
                    "execution_limit_seconds": 21600,
                    "additional_disk_bytes": 34359738368,
                    "existing_host_only": True, "automatic_later_phases": False,
                }
                or not __import__("re").fullmatch(
                    r"/run/zog/root-control-[a-z0-9][a-z0-9-]{0,47}\.sock",
                    value.get("socket_path", ""))):
            raise RuntimeError("fresh compiler has unreviewed root-control or scope")
    elif value.get("schema") != "host-deploy-compiler-execution-v2" or (
            value.get("root_control_revision") != REVIEWED_ROOT_CONTROL_REVISION):
        raise RuntimeError("nonroot compiler missing corrected root-control pin")
    owner_uid = value["controller_uid"]
    owner_gid = value["controller_gid"]
    account = pwd.getpwuid(owner_uid)
    if account.pw_gid != owner_gid or account.pw_dir != value["controller_home"]:
        raise RuntimeError("controller passwd home/gid differs from frozen identity")
    if value["controller_uid"] == value["build_uid"] or value["controller_gid"] == value["build_gid"]:
        raise RuntimeError("controller/build identities alias")
    project = Path(value["project_root"])
    home = Path(value["controller_home"])
    if home not in project.parents or str(project) != value["project_root"]:
        raise RuntimeError("compiler project not inside verified owner home")
    # Check *every* owner-controlled component from the real home to the
    # Project, matching root-control's canonical primary-group policy.
    if not home.is_absolute() or not project.is_absolute() or home not in project.parents:
        raise RuntimeError("compiler project outside verified passwd home")
    for path in (home, *reversed(project.parents[:project.parents.index(home)]),
                 project):
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("compiler source/project path is missing or linked")
        st = path.stat()
        if (st.st_uid != owner_uid or st.st_gid != owner_gid
                or (st.st_mode & 0o022)):
            raise RuntimeError("compiler Project UID/GID or permissions mismatch")

    # Check all descendants, not only the Git checkout top-level directory.
    # No symlink, device, FIFO or socket can masquerade as reviewed source.
    # Root owns immutable code; only regular world-readable files and
    # world-traversable non-writable directories are admitted.
    def _immutable_tree(root):
        count = 0
        stack = [root]
        while stack:
            path = stack.pop()
            st = path.lstat()
            if (st.st_uid != 0 or (st.st_mode & 0o022)
                    or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode))):
                raise RuntimeError("compiler immutable source tree ownership unsafe")
            if stat.S_ISDIR(st.st_mode):
                if st.st_mode & 0o005 != 0o005:
                    raise RuntimeError("compiler immutable source directory unreadable")
                with os.scandir(path) as children:
                    for entry in children:
                        count += 1
                        if count > 250000:
                            raise RuntimeError("compiler source tree exceeds audit limit")
                        stack.append(Path(entry.path))
            elif st.st_mode & 0o004 == 0:
                raise RuntimeError("compiler immutable source file unreadable")

    for root in (Path(source), Path(record_root), Path(controller_root)):
        if root != project / {"source": "source",
                              "build-record": "companions/build-record",
                              "box-control": "companions/box-control"}[root.name]:
            raise RuntimeError("compiler immutable source root mismatch")
        _immutable_tree(root)
    parents = (project / "companions", project / "companions/box-control")
    for path in parents:
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("compiler immutable companion parent unsafe")
        st = path.lstat()
        if (st.st_uid != 0 or st.st_mode & 0o022
                or st.st_mode & 0o005 != 0o005):
            raise RuntimeError("compiler immutable companion parent ownership unsafe")
    sock = Path(value["socket_path"])
    if sock.is_symlink():
        raise RuntimeError("root-control socket is linked")
    st = sock.stat()
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0
            or st.st_gid != owner_gid or stat.S_IMODE(st.st_mode) != 0o660):
        raise RuntimeError("root-control socket lacks exact nonroot peer grant")
    if not Path(value["python_executable"]).is_file():
        raise RuntimeError("bound producer interpreter missing")
    if pwd.getpwuid(value["build_uid"]).pw_gid != value["build_gid"]:
        raise RuntimeError("separate build account gid differs from binding")
    return account


def _as_controller(value, producer_argv, *, request_fd=None, timeout=300):
    account = _trusted_identity(
        value, value["project_root"] + "/source",
        value["project_root"] + "/companions/build-record",
        value["project_root"] + "/companions/box-control")
    if producer_argv[:1] != ["env"] or not producer_argv[1].startswith("PYTHONPATH="):
        raise RuntimeError("unreviewed producer environment")
    runtime_path = (value["project_root"] + "/source/src:"
        + value["project_root"] + "/companions/build-record/src:"
        + value["project_root"] + "/companions/box-control/box-control/src")
    if producer_argv[1] != "PYTHONPATH=" + runtime_path or producer_argv[2] != value["python_executable"]:
        raise RuntimeError("producer interpreter or module paths differ")
    command = [value["python_executable"], "-B", *producer_argv[3:]]
    if request_fd is not None:
        command[-1] = "/proc/self/fd/" + str(request_fd)
    environment = {
        "HOME": account.pw_dir, "USER": account.pw_name,
        "LOGNAME": account.pw_name, "PATH": "/usr/bin:/bin",
        "PYTHONPATH": runtime_path, "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }
    return subprocess.run(
        command, cwd=account.pw_dir, env=environment,
        user=value["controller_uid"], group=value["controller_gid"],
        extra_groups=(), pass_fds=(() if request_fd is None else (request_fd,)),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
    )
'''
