"""Disposable Linux kernel credential-switch acceptance for fixed compiler launcher.

Run as root on an isolated GitHub-hosted CI runner only. No real root-control
server, AWS host, managed project or compiler bootstrap is touched.
"""
import json
import fcntl
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
            "schema": "host-deploy-compiler-execution-v2",
            "root_control_revision": "e4f25110c854c000bdde5ec564c8119370da9a52",
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
        # The controller receives a *sealed inherited descriptor* for the
        # exact request. It cannot write root-owned gateway request/result
        # files, and its descriptor cannot mutate the input after review.
        payload_bytes = b'{"selected":"same-operation"}'
        fd = os.memfd_create("zog-ci-request", os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, payload_bytes)
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            reader = (
                "from pathlib import Path; import os,sys,json,fcntl; "
                "fd=int(sys.argv[1].rsplit('/',1)[-1]); "
                "print(json.dumps({'payload':Path(sys.argv[1]).read_text(),"
                "'uid':os.geteuid(), 'write_sealed':bool("
                "fcntl.fcntl(fd,fcntl.F_GET_SEALS)&fcntl.F_SEAL_WRITE)}))"
            )
            inherited = transition(
                data, ["env", "PYTHONPATH=" + pythonpath, sys.executable,
                       "-c", reader, "frozen-request-placeholder"],
                request_fd=fd,
            )
            assert inherited.returncode == 0, inherited.stderr
            assert json.loads(inherited.stdout) == {
                "payload": payload_bytes.decode(),
                "uid": uid, "write_sealed": True,
            }
        finally:
            os.close(fd)
        # A second, isolated future controller socket must be a genuinely
        # separate kernel listener, not the historical root-control.sock.
        fresh_path = Path("/run/zog/root-control-fresh-native-acceptance.sock")
        if fresh_path.exists() or fresh_path.is_symlink():
            pytest.skip("CI runner already has a fresh-controller listener")
        fresh_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            fresh_listener.bind(str(fresh_path))
            os.chown(fresh_path, 0, gid)
            os.chmod(fresh_path, 0o660)
            fresh = {
                **data, "schema": "host-deploy-compiler-execution-v3",
                "root_control_revision": "cacacbee66c0401e04dfe702d6b90e87215280d0",
                "source_revision": "53ad8c2166e6b73dffbc722c2e47ccf3593612ec",
                "box_control_revision": "b7934882cfacd2fbfd60c7964713ed3dde7f9460",
                "socket_path": str(fresh_path),
                "fresh_scope": {
                    "schema": "host-deploy-fresh-cross-bootstrap-v1",
                    "phase": "cross-bootstrap",
                    "execution_limit_seconds": 21600,
                    "additional_disk_bytes": 34359738368,
                    "existing_host_only": True,
                    "automatic_later_phases": False,
                },
            }
            observed = transition(fresh, producer)
            assert observed.returncode == 0, observed.stderr
            fields = json.loads(observed.stdout)
            assert fields["uid"] == uid and fields["gid"] == gid
            assert fields["groups"] == []
            with pytest.raises(RuntimeError, match="root-control or scope"):
                transition({**fresh, "socket_path": str(socket_path)}, producer)
            with pytest.raises(RuntimeError, match="root-control or scope"):
                transition({**fresh, "fresh_scope": {
                    **fresh["fresh_scope"], "automatic_later_phases": True,
                }}, producer)
        finally:
            fresh_listener.close()
            if fresh_path.exists():
                fresh_path.unlink()

        # Kernel-bound ownership, socket ACL, and passwd home must all
        # reject before any further producer process can start.
        os.chmod(socket_path, 0o666)
        with pytest.raises(RuntimeError, match="socket"):
            transition(data, producer)
        os.chmod(socket_path, 0o660)
        os.chmod(socket_path, 0o770)
        with pytest.raises(RuntimeError, match="socket"):
            transition(data, producer)
        os.chmod(socket_path, 0o660)
        os.chmod(project / "source", 0o777)
        with pytest.raises(RuntimeError, match="ownership"):
            transition(data, producer)
        os.chmod(project / "source", 0o755)
        # The kernel launcher must validate the *primary group* on the
        # home AND Project, not only the UID that owns the directories.
        os.chown(home, uid, build_gid)
        with pytest.raises(RuntimeError, match="Project UID/GID"):
            transition(data, producer)
        os.chown(home, uid, gid)
        os.chown(project, uid, build_gid)
        with pytest.raises(RuntimeError, match="Project UID/GID"):
            transition(data, producer)
        os.chown(project, uid, gid)
        nested = project / "source" / "nested" / "module"
        nested.mkdir(parents=True)
        source_file = nested / "compiler.py"
        source_file.write_text("print('pinned source')")
        os.chown(source_file, 0, 0)
        # A root-owned root directory is insufficient if a descendant
        # becomes writable by the controller or build identity.
        os.chmod(source_file, 0o666)
        with pytest.raises(RuntimeError, match="immutable source tree"):
            transition(data, producer)
        os.chmod(source_file, 0o644)
        os.chown(source_file, uid, gid)
        with pytest.raises(RuntimeError, match="immutable source tree"):
            transition(data, producer)
        os.chown(source_file, 0, 0)
        linked = nested / "substituted.py"
        linked.symlink_to(source_file)
        with pytest.raises(RuntimeError, match="immutable source tree"):
            transition(data, producer)
        linked.unlink()
        os.chmod(nested, 0o777)
        with pytest.raises(RuntimeError, match="immutable source tree"):
            transition(data, producer)
        os.chmod(nested, 0o755)
        os.chmod(source_file, 0o600)
        with pytest.raises(RuntimeError, match="unreadable"):
            transition(data, producer)
        os.chmod(source_file, 0o644)
        # Both pinned companion trees receive the same recursive checks
        # as image-build, not only protected checkout top-level directories.
        for companion in ("build-record", "box-control"):
            subdir = project / "companions" / companion / "nested"
            subdir.mkdir()
            nested_file = subdir / "module.py"
            nested_file.write_text("build-code")
            os.chmod(nested_file, 0o666)
            with pytest.raises(RuntimeError, match="immutable source tree"):
                transition(data, producer)
            os.chmod(nested_file, 0o644)
            nested_file.unlink()
            subdir.rmdir()
        assert transition(data, producer).returncode == 0
        with pytest.raises(RuntimeError, match="root-control pin"):
            transition({**data, "root_control_revision":
                        "62dca363d27a043a4b573e5b687f68ab5a16adeb"}, producer)
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
