"""Inspect and exclusively install the controller owned by a retained Fonts lane.

The retained lane is host-deploy's source of project and controller policy.
Actual socket/account/interpreter evidence comes from the selected Host. This
is not a substitute for root-control/box-control runtime authorization.
"""
import hashlib
import json
import shlex

from . import image_build_lanes as lanes

_SUBDIRS = ("", "package", "application", "catalogue", "state", "source")


def _controller_bytes(spec):
    return (json.dumps(lanes._controller(spec), sort_keys=True, indent=2) + "\n").encode()


def expected_controller_sha256(spec):
    return hashlib.sha256(_controller_bytes(spec)).hexdigest()


def script(spec, *, install=False):
    """Fixed SSM read-only probe or idempotent O_EXCL installer.

    The install variant is only selected after a saved activation intent; it
    performs one bounded remote operation, never replaces an existing file.
    """
    spec = lanes.validate(spec)
    if spec["mode"] != "managed" or spec["schema"] != lanes.INHERITED_SCHEMA:
        raise ValueError("inherited managed schema-5 controller inspection required")
    code = r'''
import hashlib, json, os, stat
from pathlib import Path
spec=json.loads(SPEC)
root=Path(spec['project_root'])
ctrl=spec['controller']
python=Path(spec['python_executable'])
if not python.is_file() or python.is_symlink() or not os.access(python, os.X_OK):
    raise RuntimeError('selected Python executable not installed')
uid,gid=os.geteuid(),os.getegid()
if uid == 0 or gid == 0:
    raise PermissionError('compiler controller probe must run as existing nonroot effective process')
if 'execution_user_id' in ctrl or 'execution_group_id' in ctrl:
    # Legacy identifiers are evidence only; cannot authorize another account.
    raise RuntimeError('legacy execution identity selectors require explicit migration')
if ctrl.get('execution_identity') != 'inherit':
    raise RuntimeError('inherited controller execution identity is required')
socket=Path(ctrl['socket_path'])
if not stat.S_ISSOCK(socket.lstat().st_mode):
    raise RuntimeError('installed root-control socket differs')
observed=spec['observed_state_dir']
if observed is not None and not Path(observed).is_dir():
    raise RuntimeError('retained observed state is absent')
ancestor=root
while not ancestor.exists():
    ancestor=ancestor.parent
for path in (*reversed(ancestor.parents),ancestor):
    if path.is_symlink() or not path.is_dir() or not os.access(path,os.X_OK,effective_ids=True):
        raise PermissionError('effective process cannot traverse selected Project ancestor: '+str(path))
if not root.exists() and not os.access(ancestor,os.W_OK|os.X_OK,effective_ids=True):
    raise PermissionError('effective process cannot create Project at selected location: '+str(ancestor))
if root.exists() and not os.access(root,os.R_OK|os.W_OK|os.X_OK,effective_ids=True):
    raise PermissionError('effective process cannot use existing Project location: '+str(root))
paths=[root/part for part in PARTS]
statuses=[]
for path in paths:
    try:
        st=path.lstat()
    except FileNotFoundError:
        statuses.append(False)
        continue
    if (not stat.S_ISDIR(st.st_mode) or path.is_symlink()
            or st.st_uid != uid or st.st_gid != gid
            or st.st_mode & 0o022):
        raise RuntimeError('existing project path differs from authorized owner')
    statuses.append(True)
config=root/'controller.json'
try:
    fd=os.open(config,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
except FileNotFoundError:
    fd=None
present=fd is not None
if present:
    try:
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_size>65536 or st.st_nlink!=1
                or st.st_uid != uid or st.st_mode & 0o022):
            raise RuntimeError('unsafe existing controller configuration')
        with os.fdopen(fd,'rb') as stream:
            fd=None
            data=stream.read(65537)
    finally:
        if fd is not None: os.close(fd)
    if data!=EXPECTED:
        raise RuntimeError('installed controller configuration conflicts with retained specification')
if INSTALL:
    # Create only as the executing principal. Never repair ownership or change identity.
    for path in paths:
        if not path.exists():
            path.mkdir(mode=0o755, parents=False, exist_ok=True)
        st=path.lstat()
        if (not stat.S_ISDIR(st.st_mode) or path.is_symlink()
                or st.st_uid != uid or st.st_gid != gid
                or st.st_mode & 0o022):
            raise RuntimeError('unsafe project directory during recovery')
    if not present:
        fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
        try:
            view=memoryview(EXPECTED)
            while view:
                written=os.write(fd,view)
                if written<=0: raise OSError('short controller config write')
                view=view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    if config.read_bytes()!=EXPECTED:
        raise RuntimeError('controller configuration differs after exclusive installation')
    statuses=[True]*len(paths)
    present=True
status=('complete' if all(statuses) and present
        else 'absent' if not any(statuses) and not present else 'partial')
print(json.dumps({
    'status': status,
    'project_root': str(root),
    'socket_path': str(socket),
    'effective_uid': uid,
    'effective_gid': gid,
    'python_executable': str(python),
    'controller_sha256': hashlib.sha256(EXPECTED).hexdigest(),
}, sort_keys=True))
'''
    prefix = ("SPEC=" + repr(json.dumps(spec, sort_keys=True)) + "\n"
              "PARTS=" + repr(_SUBDIRS) + "\n"
              "EXPECTED=" + repr(_controller_bytes(spec)) + "\n"
              "INSTALL=" + repr(bool(install)) + "\n")
    return "python3 -c " + shlex.quote(prefix + code)


def inspect(host, spec):
    """Authenticate installed state against its retained source policy."""
    result = json.loads(host.command(script(spec)))
    controller = spec["controller"]
    expected = {
        "project_root": spec["project_root"],
        "socket_path": controller["socket_path"],
        "python_executable": spec["python_executable"],
        "controller_sha256": expected_controller_sha256(spec),
    }
    if (type(result) is not dict
            or set(result) != set(expected) | {"status", "effective_uid", "effective_gid"}
            or type(result.get("effective_uid")) is not int or result["effective_uid"] == 0
            or type(result.get("effective_gid")) is not int or result["effective_gid"] == 0
            or any(result[key] != value for key, value in expected.items())
            or result["status"] not in {"complete", "absent", "partial"}):
        raise RuntimeError("installed controller inspection differs from retained lane")
    return result


def install(host, spec):
    """Create only absent project/controller state; never overwrite existing."""
    result = json.loads(host.command(script(spec, install=True)))
    if result.get("status") != "complete":
        raise RuntimeError("installed controller still incomplete")
    if inspect(host, spec)["status"] != "complete":
        raise RuntimeError("installed controller did not survive readback")
    return result
