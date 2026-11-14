"""Inspect the first Fonts controller under the execution process's own identity.

No passwd account, home-directory rule or UID/GID selection participates.
Old account-bound schema-4 lanes are inspection-only historical evidence.
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
    """Fixed read-only SSM inspection or exclusive creation under current identity."""
    spec = lanes.validate(spec)
    if spec["mode"] != "managed" or spec["schema"] != lanes.INHERITED_SCHEMA:
        raise ValueError("controller installation requires a corrected schema-5 lane")
    code = r'''
import hashlib, json, os, stat
from pathlib import Path
spec=json.loads(SPEC)
root=Path(spec['project_root'])
python=Path(spec['python_executable'])
uid,gid=os.geteuid(),os.getegid()
# The running execution context is the authority, including UID/GID zero.
if not python.is_file() or python.is_symlink() or not os.access(python,os.X_OK,effective_ids=True):
    raise RuntimeError('selected Python executable is missing or not executable as running process')
socket=Path(spec['controller']['socket_path'])
if socket.is_symlink() or not stat.S_ISSOCK(socket.lstat().st_mode):
    raise RuntimeError('root-control socket missing or redirected')
if not os.access(socket,os.R_OK|os.W_OK,effective_ids=True):
    raise RuntimeError('running process cannot access root-control socket')
observed=spec['observed_state_dir']
if observed is not None and (not Path(observed).is_dir() or
                              not os.access(observed,os.R_OK|os.X_OK,effective_ids=True)):
    raise RuntimeError('observed state is missing or inaccessible to running process')
parent=root.parent
if not parent.is_dir() or parent.is_symlink() or not os.access(parent,os.X_OK,effective_ids=True):
    raise RuntimeError('application data parent is missing, linked or inaccessible')
paths=[root/part for part in PARTS]
statuses=[]
for path in paths:
    try: st=path.lstat()
    except FileNotFoundError:
        statuses.append(False)
        continue
    if not stat.S_ISDIR(st.st_mode) or path.is_symlink():
        raise RuntimeError('existing application directory type differs: '+str(path))
    if not os.access(path,os.R_OK|os.W_OK|os.X_OK,effective_ids=True):
        raise RuntimeError('running process cannot access application directory: '+str(path))
    statuses.append(True)
config=root/'controller.json'
try: fd=os.open(config,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
except FileNotFoundError: fd=None
present=fd is not None
if present:
    try:
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_size>65536 or st.st_nlink!=1
                or st.st_mode & 0o022):
            raise RuntimeError('existing controller configuration type or permissions differ')
        with os.fdopen(fd,'rb') as stream:
            fd=None
            data=stream.read(65537)
    finally:
        if fd is not None: os.close(fd)
    if data != EXPECTED:
        raise RuntimeError('existing controller configuration differs from corrected specification')
if INSTALL:
    for path in paths:
        if not path.exists():
            try: path.mkdir(mode=0o755,parents=False)
            except OSError as exc:
                raise RuntimeError('running process cannot create application directory: '+str(path)) from exc
        st=path.lstat()
        if not stat.S_ISDIR(st.st_mode) or path.is_symlink():
            raise RuntimeError('application directory changed during installation: '+str(path))
        if not os.access(path,os.R_OK|os.W_OK|os.X_OK):
            raise RuntimeError('running process cannot write application directory: '+str(path))
    if not present:
        fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
        try:
            view=memoryview(EXPECTED)
            while view:
                written=os.write(fd,view)
                if written<=0: raise OSError('short controller configuration write')
                view=view[written:]
            os.fsync(fd)
        finally: os.close(fd)
    if config.read_bytes()!=EXPECTED:
        raise RuntimeError('controller configuration differs after exclusive creation')
    statuses=[True]*len(paths)
    present=True
status=('complete' if all(statuses) and present else
        'absent' if not any(statuses) and not present else 'partial')
print(json.dumps({
    'status':status,'project_root':str(root),'socket_path':str(socket),
    'effective_user_id':uid,'effective_group_id':gid,
    'python_executable':str(python),
    'controller_sha256':hashlib.sha256(EXPECTED).hexdigest(),
},sort_keys=True))
'''
    prefix = ("SPEC=" + repr(json.dumps(spec,sort_keys=True)) + "\n"
              "PARTS=" + repr(_SUBDIRS) + "\n"
              "EXPECTED=" + repr(_controller_bytes(spec)) + "\n"
              "INSTALL=" + repr(bool(install)) + "\n")
    return "python3 -c " + shlex.quote(prefix + code)


def inspect(host, spec):
    """Read actual kernel credentials, never resolve or select an account."""
    result=json.loads(host.command(script(spec)))
    fixed={
        "project_root":spec["project_root"],
        "socket_path":spec["controller"]["socket_path"],
        "python_executable":spec["python_executable"],
        "controller_sha256":expected_controller_sha256(spec),
    }
    if (type(result) is not dict or
            set(result) != set(fixed)|{"status","effective_user_id","effective_group_id"} or
            any(result[key]!=value for key,value in fixed.items()) or
            result["status"] not in {"complete","absent","partial"} or
            type(result["effective_user_id"]) is not int or
            type(result["effective_group_id"]) is not int or
            min(result["effective_user_id"],result["effective_group_id"])<0):
        raise RuntimeError("installed controller inspection differs from current execution context")
    return result


def install(host,spec):
    """Only create absent files as the already running process; never chown."""
    result=json.loads(host.command(script(spec,install=True)))
    if result.get("status")!="complete":
        raise RuntimeError("controller installation incomplete")
    if inspect(host,spec)!=result:
        raise RuntimeError("installed controller changed during readback")
    return result
