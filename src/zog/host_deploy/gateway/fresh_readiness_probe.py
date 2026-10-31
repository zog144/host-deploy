"""Fixed one-shot read-only child for bounded PID1 process/socket evidence.

Executed as an isolated native Python child with JSON on stdin. A parent's
subprocess timeout bounds procfs/kernel I/O; no process environment, socket
path or token is returned. This program never starts a unit or submits work.
"""
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys


def _bad():
    raise RuntimeError("protected process/socket identity unverified")


def _bytes(path, size=65536):
    with open(path, "rb", buffering=0) as source:
        data = source.read(size + 1)
    if len(data) > size:
        _bad()
    return data


def _verified_listener(path, pid, uid, gid):
    """Kernel LISTEN socket inode, owner's FD and SO_PEERCRED; not path ino."""
    st = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != uid
            or st.st_gid != gid or stat.S_IMODE(st.st_mode) != 0o660):
        _bad()
    # The pathname's st_ino is NOT the kernel socket fd inode.
    inodes = []
    for line in _bytes("/proc/net/unix", 1024 * 1024).decode(
            "utf-8").splitlines()[1:]:
        cols = line.split(maxsplit=7)
        if (len(cols) == 8 and cols[7] == path
                and cols[4] == "0001"
                and int(cols[3], 16) & 0x00010000):
            inodes.append(cols[6])
    if len(inodes) != 1:
        _bad()
    target = "socket:[" + inodes[0] + "]"
    fds = Path("/proc") / str(pid) / "fd"
    if not fds.is_dir():
        _bad()
    if not any(os.readlink(fds / fd) == target
               for fd in os.listdir(fds)
               if fd.isdecimal() and (fds / fd).is_symlink()):
        _bad()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        sock.connect(path)
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", creds)
        if (peer_pid, peer_uid, peer_gid) != (pid, uid, gid):
            _bad()


def inspect(requirement):
    if (type(requirement) is not dict
            or set(requirement) != {"kind", "pid", "argv", "env", "cgroup",
                                    "socket", "socket_gid", "registration"}):
        _bad()
    kind = requirement["kind"]
    pid = requirement["pid"]
    if (kind not in ("watchdog", "sidecar") or type(pid) is not int
            or not 1 < pid < (2**31)
            or type(requirement["argv"]) is not list
            or not 1 <= len(requirement["argv"]) <= 8
            or any(type(v) is not str or not v or len(v) > 1024
                   for v in requirement["argv"])
            or type(requirement["env"]) is not list
            or len(requirement["env"]) > 12
            or any(type(v) is not str or "=" not in v
                   for v in requirement["env"])
            or type(requirement["cgroup"]) is not str
            or not requirement["cgroup"].startswith("/")
            or (kind == "watchdog" and
                (requirement["socket"] is not None or
                 requirement["registration"] is not None))
            or (kind == "sidecar" and (
                requirement["socket"] !=
                    "/run/zog/root-control-fresh-cross-bootstrap-oct25.sock"
                or type(requirement["socket_gid"]) is not int
                or type(requirement["registration"]) is not list
                or len(requirement["registration"]) != 2))):
        _bad()
    root = Path("/proc") / str(pid)
    expected = [x.encode("utf-8") for x in requirement["argv"]]
    if _bytes(root / "cmdline").rstrip(b"\0").split(b"\0") != expected:
        _bad()
    environment = _bytes(root / "environ").rstrip(b"\0").split(b"\0")
    observed_env = {}
    for entry in environment:
        if b"=" not in entry:
            continue
        key, value = entry.split(b"=", 1)
        if key in observed_env:
            _bad()
        observed_env[key] = value
    for setting in requirement["env"]:
        key, value = setting.encode("utf-8").split(b"=", 1)
        if observed_env.get(key) != value:
            _bad()
    exe_stat = (root / "exe").stat()
    expected_stat = os.stat(requirement["argv"][0])
    if (exe_stat.st_dev, exe_stat.st_ino) != (
            expected_stat.st_dev, expected_stat.st_ino):
        _bad()
    if _bytes(root / "cgroup").decode("ascii").splitlines() != [
            "0::" + requirement["cgroup"]]:
        _bad()
    status = _bytes(root / "status", 32768).decode("ascii")
    attributes = dict(line.split(":", 1) for line in status.splitlines()
                      if ":" in line)
    if (attributes.get("Uid", "").split() != ["0"] * 4
            or attributes.get("Gid", "").split() != ["0"] * 4
            or attributes.get("Pid", "").strip() != str(pid)):
        _bad()
    if kind == "sidecar":
        _verified_listener(requirement["socket"], pid, 0,
                           requirement["socket_gid"])
        origin, destination = requirement["registration"]
        source_stat = os.stat(origin, follow_symlinks=False)
        child_stat = (root / "root" / destination.lstrip("/")).stat()
        if (not stat.S_ISDIR(source_stat.st_mode)
                or not stat.S_ISDIR(child_stat.st_mode)
                or (source_stat.st_dev, source_stat.st_ino) !=
                    (child_stat.st_dev, child_stat.st_ino)):
            _bad()
    return {"status": "exact-process-verified",
            "kind": kind, "pid": str(pid), "cgroup": requirement["cgroup"],
            "socket_listener_verified": kind == "sidecar"}


def main():
    if os.geteuid() != 0:
        _bad()
    request = json.loads(sys.stdin.buffer.read(8192))
    result = inspect(request)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
