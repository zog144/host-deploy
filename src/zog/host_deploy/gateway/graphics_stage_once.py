"""Persistent once-only graphical admission, shared by supervisor and admin prepare.

Retained stage identity is not deleted after unknown, failed or completed work.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import stat

from . import graphics_generation_chain as chain
from .ledger import load_request

SCHEMA = "host-deploy-graphical-stage-once-v1"
LANE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
ID = re.compile(r"[a-f0-9]{32}\Z")


class StageReplayBlocked(RuntimeError):
    pass


def _deny():
    raise StageReplayBlocked("graphical-stage-bound-or-uncertain")


def reserve(gateway_root, request_id, binding):
    """Durable stage reservation, before preparing any remote operation."""
    request = load_request(gateway_root, request_id)
    envelope = request.get("request", {})
    task = envelope.get("parameters", {}).get("task")
    if task not in chain.TASKS:
        return
    lane = envelope["parameters"].get("lane")
    spec = binding.get("task")
    if (type(lane) is not str or not LANE.fullmatch(lane)
            or type(request_id) is not str or not ID.fullmatch(request_id)
            or request.get("states", {}).get("admission") != "admitted"
            or envelope.get("operation") != "build.submit"
            or type(spec) is not dict or spec.get("lane") != lane
            or binding.get("lane") != lane
            or type(binding.get("task_catalogue_identity")) is not str):
        _deny()
    root = Path(gateway_root)
    if root.is_symlink() or not root.is_dir():
        _deny()
    directory = root / "graphical-stage-once"
    directory.mkdir(mode=0o700, exist_ok=True)
    owner = os.geteuid()
    st = directory.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != owner
            or stat.S_IMODE(st.st_mode) != 0o700):
        _deny()
    lock = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR |
                   os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            _deny()
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = directory / (lane + "--" + task + ".json")
        expected = {
            "schema": SCHEMA, "request_id": request_id,
            "task": task, "lane": lane,
            "catalogue_sha256": binding["task_catalogue_identity"],
        }
        raw = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
        if path.exists() or path.is_symlink():
            if path.is_symlink():
                _deny()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_size != len(raw)
                        or os.read(fd, len(raw) + 1) != raw):
                    _deny()
            finally:
                os.close(fd)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                if os.write(fd, raw) != len(raw):
                    _deny()
                os.fsync(fd)
            finally:
                os.close(fd)
            root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
