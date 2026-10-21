"""Approved nonroot image-build producer execution identity.

Only root-owned lane admission may install this schema. Root SSM is a
transport; its wrapper must drop to the controller owner for producer calls.
"""
import json
import re
from pathlib import PurePosixPath

SCHEMA = "host-deploy-compiler-execution-v1"
_SHA = re.compile(r"[a-f0-9]{40}\Z")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
FIELDS = {
    "schema", "controller_uid", "controller_gid", "controller_home",
    "project_root", "build_uid", "build_gid", "socket_path",
    "source_revision", "build_record_revision", "box_control_revision",
    "python_executable", "task_catalogue_identity",
}


def _absolute(value):
    if type(value) is not str or not value.startswith("/") or len(value) > 1024:
        return False
    path = PurePosixPath(value)
    return (str(path) == value and
            all(part not in ("", ".", "..") for part in value.split("/")[1:]) and
            all(ord(char) >= 33 and ord(char) != 127 for char in value))


def validate(value, *, project_root, python_executable, source_revision,
             build_record_revision, box_control_revision, task_identity):
    if type(value) is not dict or set(value) != FIELDS or value["schema"] != SCHEMA:
        raise ValueError("invalid nonroot compiler execution binding")
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
    if value["socket_path"] != "/run/zog/root-control.sock":
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

def _trusted_identity(value, source, record_root, controller_root):
    if os.geteuid() != 0:
        raise RuntimeError("compiler identity transition requires root transport")
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
    for path, uid in ((home, owner_uid), (project, owner_uid),
                      (Path(source), 0),
                      (project / "companions", 0),
                      (Path(record_root), 0),
                      (project / "companions/box-control", 0),
                      (Path(controller_root), 0)):
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("compiler source/project path is missing or linked")
        st = path.stat()
        if st.st_uid != uid or (st.st_mode & 0o022):
            raise RuntimeError("compiler source/project ownership is unsafe")
    sock = Path(value["socket_path"])
    if sock.is_symlink():
        raise RuntimeError("root-control socket is linked")
    st = sock.stat()
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0
            or st.st_gid != owner_gid or not (st.st_mode & 0o020)
            or (st.st_mode & 0o002)):
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
