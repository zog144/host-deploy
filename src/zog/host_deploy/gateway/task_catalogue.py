"""Server-owned build task catalogue for gateway build.submit requests."""

import hashlib
import json
from pathlib import Path
import re

from .protocol import BUILD_TASKS


SCHEMA = 1
_REVISION = re.compile(r"[0-9a-f]{40}")
_GENERATION = re.compile(r"[0-9a-f]{64}")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}")


class TaskCatalogueError(ValueError):
    """A server-owned build task definition is invalid."""


def _package(value):
    if not isinstance(value, str) or not _PACKAGE.fullmatch(value):
        raise TaskCatalogueError("invalid image-build package name")
    return value


def _arguments(value):
    if not isinstance(value, dict):
        raise TaskCatalogueError("task arguments must be an object")
    mode = value.get("mode")
    if mode not in {"image", "bootstrap", "seed-check", "native-check"}:
        raise TaskCatalogueError("invalid task pipeline mode")
    selection = value.get("selection")
    if not isinstance(selection, str) or not _GENERATION.fullmatch(selection):
        raise TaskCatalogueError("task selection must be an immutable generation")
    if mode == "bootstrap":
        if set(value) != {"mode", "selection", "stages"}:
            raise TaskCatalogueError("bootstrap task requires mode, selection, and stages")
        stages = value["stages"]
        if (
            not isinstance(stages, list)
            or not stages
            or len(stages) > 64
            or any(
                not isinstance(stage, list)
                or not stage
                or len(stage) > 256
                for stage in stages
            )
        ):
            raise TaskCatalogueError("invalid bootstrap task stages")
        return {
            "mode": mode,
            "selection": selection,
            "stages": [[_package(item) for item in stage] for stage in stages],
        }
    if set(value) != {"mode", "selection", "targets"}:
        raise TaskCatalogueError(
            "image/native task requires mode, selection, and targets"
        )
    targets = value["targets"]
    if (
        not isinstance(targets, list)
        or not targets
        or len(targets) > 256
    ):
        raise TaskCatalogueError("invalid task targets")
    return {
        "mode": mode,
        "selection": selection,
        "targets": [_package(item) for item in targets],
    }


def validate(value):
    if not isinstance(value, dict) or set(value) != {"schema", "tasks"}:
        raise TaskCatalogueError("task catalogue fields are invalid")
    if value["schema"] != SCHEMA or type(value["schema"]) is not int:
        raise TaskCatalogueError("unsupported task catalogue schema")
    tasks = value["tasks"]
    if not isinstance(tasks, dict) or len(tasks) > len(BUILD_TASKS):
        raise TaskCatalogueError("invalid task catalogue")
    result = {"schema": SCHEMA, "tasks": {}}
    for name, entry in sorted(tasks.items()):
        if name not in BUILD_TASKS:
            raise TaskCatalogueError("unknown gateway build task")
        if (
            not isinstance(entry, dict)
            or set(entry) != {"source_repository", "source_revision", "arguments"}
        ):
            raise TaskCatalogueError("invalid gateway build task definition")
        if entry["source_repository"] != "zog144/image-build":
            raise TaskCatalogueError("gateway task source repository is not authorized")
        revision = entry["source_revision"]
        if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
            raise TaskCatalogueError("task source revision must be exact 40-hex")
        result["tasks"][name] = {
            "source_repository": entry["source_repository"],
            "source_revision": revision,
            "arguments": _arguments(entry["arguments"]),
        }
    return result


def loads(data):
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            raise TaskCatalogueError("task catalogue must be UTF-8") from None
    if not isinstance(data, str) or len(data.encode("utf-8")) > 128 * 1024:
        raise TaskCatalogueError("task catalogue is missing or oversized")
    try:
        value = json.loads(data)
    except (TypeError, ValueError):
        raise TaskCatalogueError("invalid task catalogue JSON") from None
    return validate(value)


def load(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise TaskCatalogueError("task catalogue must be a regular file")
    value = loads(path.read_bytes())
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return value, "sha256:" + hashlib.sha256(encoded).hexdigest()


def select(catalogue, task, *, repository, revision):
    catalogue = validate(catalogue)
    if task not in catalogue["tasks"]:
        raise TaskCatalogueError("gateway build task is not configured")
    entry = catalogue["tasks"][task]
    if (
        entry["source_repository"] != repository
        or entry["source_revision"] != revision
    ):
        raise TaskCatalogueError(
            "gateway build task differs from the admitted source revision"
        )
    return json.loads(json.dumps(entry))
