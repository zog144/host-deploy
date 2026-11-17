"""Read-only verification and exclusive controller binding for an existing Project.

An existing box-control Project is not created or migrated by lane preparation.
The selected Project and controller are the stable binding. Its checkout may
change independently; no account selection, state migration or source pin gate.
"""
import hashlib
import json
import shlex

from . import image_build_lanes as lanes

CONTROLLER_SUFFIX = "-inherited-v1.json"
REQUIRED_DIRS = ("package", "application", "catalogue", "state", "source")


def controller_file(spec):
    spec = lanes.validate(spec)
    if (spec["schema"] != lanes.INHERITED_SCHEMA
            or spec.get("project_selection") != "existing"
            or spec["mode"] != "managed"):
        raise ValueError("existing Project controller requires a reviewed schema-5 managed lane")
    return "controller-" + spec["lane"] + CONTROLLER_SUFFIX


def expected_bytes(spec):
    return (json.dumps(lanes._controller(spec), sort_keys=True, indent=2) + "\n").encode()


def script(spec, *, install=False):
    spec = lanes.validate(spec)
    filename = controller_file(spec)
    code = r'''
import hashlib, json, os, stat, subprocess
from pathlib import Path
root=Path(PROJECT)
uid,gid=os.geteuid(),os.getegid()
if not root.is_absolute() or str(root)!=PROJECT:
    raise RuntimeError('existing Project path is not canonical')
# The selected path and ancestors must not redirect to another Project.
for node in (root,*root.parents):
    st=node.lstat()
    if not stat.S_ISDIR(st.st_mode) or node.is_symlink():
        raise RuntimeError('existing Project path contains a non-directory or symlink')
    if not os.access(node,os.X_OK,effective_ids=True):
        raise RuntimeError('running process cannot traverse existing Project')
for name in REQUIRED:
    path=root/name
    try:
        st=path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError('existing Project directory missing: '+name) from exc
    if not stat.S_ISDIR(st.st_mode) or path.is_symlink():
        raise RuntimeError('existing Project directory is foreign: '+name)
    access=os.R_OK|os.X_OK
    if name!='source':
        access|=os.W_OK
    if not os.access(path,access,effective_ids=True):
        raise RuntimeError('running process cannot access existing Project directory: '+name)
source=root/'source'
# A checkout revision is an observation, not an activation authorization.
# The current files and package pins are selected by the next build itself.
p=subprocess.run(['git','-C',str(source),'rev-parse','--verify','HEAD'],
                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
revision=p.stdout.strip() if p.returncode==0 else None
python=Path(PYTHON)
if python.is_symlink() or not python.is_file() or not os.access(python,os.X_OK,effective_ids=True):
    raise RuntimeError('selected Project Python is missing or inaccessible')
socket=Path(SOCKET)
if socket.is_symlink() or not stat.S_ISSOCK(socket.lstat().st_mode):
    raise RuntimeError('selected controller socket is missing or redirected')
if not os.access(socket,os.R_OK|os.W_OK,effective_ids=True):
    raise RuntimeError('running process cannot use selected controller socket')
controller=root/CONTROLLER
try:
    fd=os.open(controller,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
except FileNotFoundError:
    fd=None
if fd is not None:
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>65536 or st.st_mode & 0o022:
            raise RuntimeError('existing controller file is foreign or unsafe')
        with os.fdopen(fd,'rb') as stream:
            fd=-1
            current=stream.read(65537)
    finally:
        if fd>=0: os.close(fd)
    if current!=EXPECTED:
        raise RuntimeError('existing controller differs from reviewed lane specification')
elif INSTALL:
    fd=os.open(controller,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(EXPECTED)
        while view:
            n=os.write(fd,view)
            if n<=0: raise OSError('short existing Project controller write')
            view=view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if controller.read_bytes()!=EXPECTED:
        raise RuntimeError('controller readback differs after exclusive creation')
state='complete' if controller.is_file() else 'prepared'
print(json.dumps({
    'status':state,
    'project_root':PROJECT,
    'project_identity':root.name,
    'source_revision':revision,
    'controller_file':str(controller),
    'controller_sha256':hashlib.sha256(EXPECTED).hexdigest(),
    'effective_user_id':uid,'effective_group_id':gid,
},sort_keys=True))
'''
    prefix = (
        "PROJECT=" + repr(spec["project_root"]) + "\n"
        "PYTHON=" + repr(spec["python_executable"]) + "\n"
        "SOCKET=" + repr(spec["controller"]["socket_path"]) + "\n"
        "REQUIRED=" + repr(REQUIRED_DIRS) + "\n"
        "CONTROLLER=" + repr(filename) + "\n"
        "EXPECTED=" + repr(expected_bytes(spec)) + "\n"
        "INSTALL=" + repr(bool(install)) + "\n"
    )
    return "python3 -c " + shlex.quote(prefix + code)


def inspect(host, spec):
    """Read-only check in the selected Host command context, not a build grant."""
    spec = lanes.validate(spec)
    result = json.loads(host.command(script(spec)))
    expected = {
        "project_root": spec["project_root"],
        "project_identity": spec["project_root"].rstrip("/").split("/")[-1],
        "controller_file": spec["project_root"] + "/" + controller_file(spec),
        "controller_sha256": hashlib.sha256(expected_bytes(spec)).hexdigest(),
    }
    if (type(result) is not dict
            or set(result) != set(expected) | {
                "status","effective_user_id","effective_group_id","source_revision"}
            or (result.get("source_revision") is not None
                and (not isinstance(result["source_revision"], str)
                     or not lanes._REVISION.fullmatch(result["source_revision"])))
            or any(result.get(k)!=v for k,v in expected.items())
            or result.get("status") not in {"prepared","complete"}
            or type(result.get("effective_user_id")) is not int
            or type(result.get("effective_group_id")) is not int
            or min(result["effective_user_id"],result["effective_group_id"])<0):
        raise RuntimeError("selected existing Project inspection was not authenticated")
    return result


def install(host, spec):
    """Only create the absent lane-specific controller, not any Project tree."""
    result = json.loads(host.command(script(spec, install=True)))
    if result.get("status") != "complete":
        raise RuntimeError("selected existing Project controller write was incomplete")
    readback = inspect(host, spec)
    # HEAD is reported for history only. A checkout update between the
    # installation and readback is not a controller or Project mismatch.
    for observation in (result, readback):
        observation.pop("source_revision", None)
    if result != readback:
        raise RuntimeError("existing Project controller changed during readback")
    return readback
