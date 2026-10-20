"""Protected, exactly pinned unattended compiler-toolchain task definition.

A GitHub request only names this task. It cannot supply seed, producer revision,
recipe paths, controller configuration, environment, or compilation commands.
"""
import hashlib
import json
import re
import stat
from pathlib import Path

CONTRACT = "host-deploy-toolchain-task-v1"
# Retained historical producer: existing immutable dispatches must still decode.
PRODUCER_REVISION = "857bb454e64102afa51a93ce0b9f8cce5924b67c"
# New source-owned, reviewed monthly pin restoration. Only this pair may
# authorize a NEW compiler submission; never retarget the historical pin.
RESTORED_PRODUCER_REVISION = "31e6121cdf9fd05336286529666e2c35cdbe0831"
RESTORED_MONTHLY_PIN_PATH = "project/pins/2026-10-01/commit-pin.py"
RESTORED_MONTHLY_PIN_IDENTITY = (
    "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
)
TASK_NAME = "self-hosted-c-cxx-toolchain-v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"[0-9a-f]{64}\Z")
_LANE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
_MONTH = re.compile(r"\d{4}-\d{2}-01\Z")
_FIELDS = frozenset({
    "name", "source_repository", "source_revision", "lane", "lane_owner",
    "seed_generation", "monthly_pin_repository_path", "monthly_pin_identity",
    "pin_date", "specification_identity",
})


class ToolchainTaskError(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def validate(value):
    if (type(value) is not dict or set(value) != {"contract", "task"}
            or value["contract"] != CONTRACT or type(value["task"]) is not dict
            or set(value["task"]) != _FIELDS):
        raise ToolchainTaskError("invalid protected toolchain task definition")
    task = value["task"]
    if (task["name"] != TASK_NAME
            or task["source_repository"] != "zog144/image-build"
            or task["source_revision"] not in (
                PRODUCER_REVISION, RESTORED_PRODUCER_REVISION)
            or (task["source_revision"] == RESTORED_PRODUCER_REVISION
                and (task["monthly_pin_repository_path"] != RESTORED_MONTHLY_PIN_PATH
                     or task["monthly_pin_identity"] != RESTORED_MONTHLY_PIN_IDENTITY
                     or task["pin_date"] != "2026-10-01"))
            or type(task["lane"]) is not str or not _LANE.fullmatch(task["lane"])
            or type(task["lane_owner"]) is not str
            or not _LANE.fullmatch(task["lane_owner"])
            or type(task["seed_generation"]) is not str
            or not _GENERATION.fullmatch(task["seed_generation"])
            or type(task["monthly_pin_identity"]) is not str
            or not _SHA.fullmatch(task["monthly_pin_identity"])
            or type(task["specification_identity"]) is not str
            or not _SHA.fullmatch(task["specification_identity"])
            or type(task["pin_date"]) is not str
            or not _MONTH.fullmatch(task["pin_date"])
            or task["monthly_pin_repository_path"] !=
               "project/pins/" + task["pin_date"] + "/commit-pin.py"):
        raise ToolchainTaskError("toolchain task producer/seed/owner/pin is invalid")
    return json.loads(canonical(value))


def loads(payload):
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeError as exc:
            raise ToolchainTaskError("toolchain task is not UTF-8") from exc
    if type(payload) is not str or len(payload.encode("utf-8")) > 16384:
        raise ToolchainTaskError("toolchain task is oversized or absent")

    def unique(pairs):
        out = {}
        for name, value in pairs:
            if name in out:
                raise ToolchainTaskError("duplicate toolchain task key")
            out[name] = value
        return out

    try:
        parsed = json.loads(payload, object_pairs_hook=unique)
    except (ValueError, TypeError) as exc:
        raise ToolchainTaskError("invalid toolchain task JSON") from exc
    return validate(parsed)


def load(path, *, require_root_owned=False):
    path = Path(path)
    if not path.is_absolute():
        raise ToolchainTaskError("toolchain task must use an absolute path")
    if require_root_owned:
        current = path
        while True:
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022):
                raise ToolchainTaskError(
                    "toolchain task and all ancestors must be root-owned and not writable"
                )
            if current == current.parent:
                break
            current = current.parent
    if path.is_symlink() or not path.is_file():
        raise ToolchainTaskError("toolchain task must be a regular file")
    task = loads(path.read_bytes())
    return task, "sha256:" + hashlib.sha256(canonical(task)).hexdigest()


def select(protected, *, name, repository, revision, lane,
           lane_owner, monthly_pin_repository_path, monthly_pin_identity):
    task = validate(protected)["task"]
    # Historical task bindings remain inspectable for idempotency/recovery,
    # but their source had no reviewed public monthly lock and therefore
    # cannot authorize any NEW compiler dispatch.
    if task["source_revision"] != RESTORED_PRODUCER_REVISION:
        raise ToolchainTaskError("historical toolchain producer cannot accept new work")
    if (name != TASK_NAME
            or repository != task["source_repository"]
            or revision != task["source_revision"]
            or lane != task["lane"]
            or lane_owner != task["lane_owner"]
            or monthly_pin_repository_path != task["monthly_pin_repository_path"]
            or monthly_pin_identity != task["monthly_pin_identity"]):
        raise ToolchainTaskError(
            "requested toolchain task differs from pinned producer/lane/owner/provenance"
        )
    return task.copy()
