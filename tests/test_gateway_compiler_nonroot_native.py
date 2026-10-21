"""Disposable Linux kernel credential-switch acceptance for fixed compiler launcher.

Run as root on an isolated GitHub-hosted CI runner only. No real root-control
server, AWS host, managed project or compiler bootstrap is touched.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile

import pytest

from zog.host_deploy.gateway.compiler_execution_identity import IDENTITY_RUNTIME


@pytest.mark.skipif(os.geteuid() != 0, reason="native UID/GID transition needs isolated root runner")
def test_real_kernel_uid_drop_home_groups_and_socket_binding(tmp_path, monkeypatch):
    # Fail if the ephemeral runner already owns these reserved integration
    # names or the protected socket: never disturb an installed controller.
    socket_path = Path("/run/zog/root-control.sock")
    if socket_path.exists() or socket_path.is_symlink():
        pytest.skip("CI runner has a real root-control socket")
    uid, gid, build_uid, build_gid = 46201, 46202, 46301, 46302
    owner_name, build_name = "zogciowner", "zogcibuild"
    for name in (owner_name, build_name):
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        pytest.skip("CI runner already contains reserved test account")
    # Need genuine entries in the kernel/passwd database; no monkeypatch of
    # _trusted_identity, subprocess.run, os.setgroups, uid or socket stat.
    for args in (["groupadd", "-g", str(gid), owner_name],
                 ["groupadd", "-g", str(build_gid), build_name]):
        subprocess.run(args, check=True)
    base = Path(tempfile.mkdtemp(prefix="zog-ci-compiler-", dir="/tmp"))
    os.chmod(base, 0o755)
    home = base / "controller-home"
    home.mkdir()
    os.chown(home, uid, gid)
    project = home / "project"
    project.mkdir()
    os.chown(project, uid, gid)
    for name in ("source", "companions/build-record", "companions/box-control"):
        (project / name).mkdir(parents=True, exist_ok=True)
        # All source checkouts, including parent companion directory, must
        # remain root-owned and non-group-writable.
    for path in (project / "source", project / "companions",
                 project / "companions/build-record",
                 project / "companions/box-control"):
        os.chown(path, 0, 0)
        os.chmod(path, 0o755)
    server = None
    try:
        subprocess.run(["useradd", "-M", "-u", str(uid), "-g", str(gid),
                        "-d", str(home), "-s", "/usr/sbin/nologin",
                        owner_name], check=True)
        subprocess.run(["useradd", "-M", "-u", str(build_uid), "-g", str(build_gid),
                        "-d", "/nonexistent", "-s", "/usr/sbin/nologin",
                        build_name], check=True)
        sock_dir = socket_path.parent
        sock_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        os.chown(socket_path, 0, gid)
        os.chmod(socket_path, 0o660)
        namespace = {"subprocess": subprocess, "json": json}
        exec(IDENTITY_RUNTIME, namespace)
        transition = namespace["_as_controller"]
        data = {
            "controller_uid": uid, "controller_gid": gid,
            "controller_home": str(home), "project_root": str(project),
            "build_uid": build_uid, "build_gid": build_gid,
            "socket_path": str(socket_path),
            "python_executable": sys.executable,
        }
        pythonpath = (
            str(project / "source/src") + ":" +
            str(project / "companions/build-record/src") + ":" +
            str(project / "companions/box-control/box-control/src")
        )
        payload = (
            "import json,os; print(json.dumps({"
            "'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),"
            "'home':os.environ['HOME'],'cwd':os.getcwd(),"
            "'path':os.environ['PYTHONPATH'],"
            "'root_env':os.getenv('ZOG_HOST_ROOT_SECRET'),"
            "'user':os.environ['USER']}))"
        )
        producer = ["env", "PYTHONPATH=" + pythonpath, sys.executable,
                    "-c", payload]
        monkeypatch.setenv("HOME", "/root/spoofed")
        monkeypatch.setenv("ZOG_HOST_ROOT_SECRET", "must-not-be-visible")
        observed = transition(data, producer)
        assert observed.returncode == 0, observed.stderr
        fields = json.loads(observed.stdout)
        assert fields == {
            "uid": uid, "gid": gid, "groups": [],
            "home": str(home), "cwd": str(home),
            "path": pythonpath, "root_env": None, "user": owner_name,
        }
        # Kernel-bound ownership, socket ACL, and passwd home must all
        # reject before any further producer process can start.
        os.chmod(socket_path, 0o666)
        with pytest.raises(RuntimeError, match="socket"):
            transition(data, producer)
        os.chmod(socket_path, 0o660)
        os.chmod(project / "source", 0o777)
        with pytest.raises(RuntimeError, match="ownership"):
            transition(data, producer)
        os.chmod(project / "source", 0o755)
        with pytest.raises(RuntimeError, match="passwd home"):
            transition({**data, "controller_home": "/root"}, producer)
    finally:
        if server is not None:
            server.close()
        if socket_path.exists():
            socket_path.unlink()
        for name in (build_name, owner_name):
            subprocess.run(["userdel", name], check=False)
        for name in (build_name, owner_name):
            subprocess.run(["groupdel", name], check=False)
        shutil.rmtree(base)
