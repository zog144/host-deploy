"""Real unprivileged kernel AF_UNIX LISTEN + PID fd + peer credential tests.

Uses only temporary filesystem sockets; no real root-control path or PID1.
"""
import os
from pathlib import Path
import socket
import stat

import pytest

from zog.host_deploy.gateway import fresh_readiness_probe as probe


def create_listener(tmp_path):
    path = tmp_path / "listener.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(2)
    os.chmod(path, 0o660)
    return server, str(path)


def test_live_listener_matches_kernel_socket_fd_and_peer_identity(tmp_path):
    server, path = create_listener(tmp_path)
    try:
        assert stat.S_ISSOCK(os.lstat(path).st_mode)
        rows = [row.split(maxsplit=7) for row in
                Path("/proc/net/unix").read_text().splitlines()[1:]]
        matching = [row for row in rows if len(row) == 8 and row[7] == path]
        assert matching, "expected real bound socket in /proc/net/unix"
        assert matching[0][4] == "0001", matching
        assert int(matching[0][3], 16) & 0x10000, matching
        # Works even though the pathname inode and socket:[inode] are NOT
        # the same identity. No false pathname-inode equality shortcut.
        probe._verified_listener(path, os.getpid(), os.getuid(), os.getgid())
        with pytest.raises(RuntimeError, match="identity unverified"):
            probe._verified_listener(
                path, os.getpid() + 100000, os.getuid(), os.getgid())
        with pytest.raises(RuntimeError, match="identity unverified"):
            probe._verified_listener(path, os.getpid(), os.getuid()+1,
                                     os.getgid())
    finally:
        server.close()


def test_stale_but_correctly_owned_socket_path_cannot_pass(tmp_path):
    server, path = create_listener(tmp_path)
    server.close()  # Path inode remains, no kernel LISTEN socket or owner FD.
    assert Path(path).exists()
    with pytest.raises(RuntimeError, match="identity unverified"):
        probe._verified_listener(path, os.getpid(), os.getuid(), os.getgid())


def test_bound_not_listening_socket_is_not_a_valid_endpoint(tmp_path):
    path = str(tmp_path / "bound.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        os.chmod(path, 0o660)
        with pytest.raises(RuntimeError, match="identity unverified"):
            probe._verified_listener(
                path, os.getpid(), os.getuid(), os.getgid())
    finally:
        server.close()


def test_mode_or_gid_drift_fails_even_when_listening(tmp_path):
    server, path = create_listener(tmp_path)
    try:
        os.chmod(path, 0o666)
        with pytest.raises(RuntimeError, match="identity unverified"):
            probe._verified_listener(path, os.getpid(), os.getuid(), os.getgid())
    finally:
        server.close()


def test_procfs_chunked_seqfile_is_read_to_eof_not_first_short_page(monkeypatch):
    import builtins
    chunks = [b"earlier-header\\n", b"later-UNIX-listener-row\\n", b""]
    class ShortReader:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, count):
            return chunks.pop(0)
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", lambda *args, **kw: ShortReader())
        assert probe._bytes("/proc/net/unix", 1000) == (
            b"earlier-header\\nlater-UNIX-listener-row\\n")
    assert chunks == []


def test_oversized_procfs_seqfile_fails_closed(monkeypatch):
    import builtins
    class ShortReader:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self, count): return b"x" * count
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", lambda *args, **kw: ShortReader())
        with pytest.raises(RuntimeError, match="identity unverified"):
            probe._bytes("/proc/net/unix", 10)
