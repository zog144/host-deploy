"""Immutable server-owned catalogue: finite GENERIC image-build tasks only."""
import hashlib
import os
import stat
import json
from pathlib import Path
import re

from .protocol import BUILD_TASKS

SCHEMA = 2
_REVISION = re.compile(r"[a-f0-9]{40}\Z")
_GENERATION = re.compile(r"[a-f0-9]{64}\Z")
_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+_.-]{0,127}\Z")
_RECIPE = re.compile(r"(?:[a-zA-Z0-9+_.-]+/)+[a-zA-Z0-9+_.-]+\Z")
_LANE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
_MONTH = re.compile(r"\d{4}-\d{2}-01\Z")

# Finite reviewed graphical selections only. The issue supplies a task name;
# exact recipe paths, package targets, source revision, lane owner, monthly pin
# and immutable base generation remain root-owned catalogue data.
REVIEWED_IMAGE_TASKS = {
    "graphics-fonts-image-v1": {
        "entries": (
            ("fontconfig-final", "fontconfig", "fontconfig/stages/final"),
            ("freetype-final", "freetype", "freetype/stages/final"),
            ("libpng-final", "libpng", "libpng/stages/final"),
        ),
        "targets": ("libpng-final", "freetype-final", "fontconfig-final"),
    },
    "graphics-xcb-core-image-v1": {
        "entries": (
            ("check-final", "check", "check/stages/final"),
            ("libXau-final", "libXau", "libXau/stages/final"),
            ("libXdmcp-final", "libXdmcp", "libXdmcp/stages/final"),
            ("libevdev-final", "libevdev", "libevdev/stages/final"),
            ("libxcb-final", "libxcb", "libxcb/stages/final"),
            ("python-libevdev-final", "python-libevdev", "python-libevdev/stages/final"),
            ("xcb-proto-final", "xcb-proto", "xcb-proto/stages/final"),
            ("xorgproto-final", "xorgproto", "xorgproto/stages/final"),
        ),
        "targets": (
            "check-final", "libevdev-final", "python-libevdev-final",
            "xorgproto-final", "libXau-final", "libXdmcp-final",
            "xcb-proto-final", "libxcb-final",
        ),
    },
    "graphics-x11-core-image-v1": {
        "entries": (
            ("libX11-final", "libX11", "libX11/stages/final"),
            ("libXext-final", "libXext", "libXext/stages/final"),
            ("libXfixes-final", "libXfixes", "libXfixes/stages/final"),
            ("libXfont2-final", "libXfont2", "libXfont2/stages/final"),
            ("libXi-final", "libXi", "libXi/stages/final"),
            ("libXtst-final", "libXtst", "libXtst/stages/final"),
            ("libXv-final", "libXv", "libXv/stages/final"),
            ("libfontenc-final", "libfontenc", "libfontenc/stages/final"),
            ("libxkbfile-final", "libxkbfile", "libxkbfile/stages/final"),
            ("xtrans-final", "xtrans", "xtrans/stages/final"),
        ),
        "targets": (
            "xtrans-final", "libX11-final", "libXext-final", "libXfixes-final",
            "libXi-final", "libXtst-final", "libXv-final", "libxkbfile-final",
            "libfontenc-final", "libXfont2-final",
        ),
    },
    "xcb-support-image-v1": {
        "entries": (
            ("xcb-util-final", "xcb-util", "xcb-util/stages/final"),
            ("xcb-util-image-final", "xcb-util-image", "xcb-util-image/stages/final"),
            ("xcb-util-keysyms-final", "xcb-util-keysyms", "xcb-util-keysyms/stages/final"),
            ("xcb-util-wm-final", "xcb-util-wm", "xcb-util-wm/stages/final"),
            ("xcb-util-xrm-final", "xcb-util-xrm", "xcb-util-xrm/stages/final"),
        ),
        "targets": (
            "xcb-util-final", "xcb-util-image-final", "xcb-util-keysyms-final",
            "xcb-util-wm-final", "xcb-util-xrm-final",
        ),
    },
}

class TaskCatalogueError(ValueError):
    pass

def validate(value):
    if (type(value) is not dict or set(value) != {"schema", "tasks"}
            or type(value["schema"]) is not int or value["schema"] != SCHEMA
            or type(value["tasks"]) is not dict
            or not 1 <= len(value["tasks"]) <= len(BUILD_TASKS)):
        raise TaskCatalogueError("invalid generic task catalogue")
    output = {"schema": SCHEMA, "tasks": {}}
    for name, item in sorted(value["tasks"].items()):
        fields = {"source_repository", "source_revision", "lane",
                  "monthly_pin_repository_path", "monthly_pin_identity",
                  "pin_date", "entries", "arguments", "lane_owner"}
        if name not in BUILD_TASKS or type(item) is not dict or set(item) != fields:
            raise TaskCatalogueError("unknown or incomplete generic pipeline task")
        if (item["source_repository"] != "zog144/image-build"
                or type(item["source_revision"]) is not str
                or not _REVISION.fullmatch(item["source_revision"])
                or type(item["lane"]) is not str or not _LANE.fullmatch(item["lane"])
                or type(item["monthly_pin_identity"]) is not str
                or not _SHA.fullmatch(item["monthly_pin_identity"])
                or type(item["monthly_pin_repository_path"]) is not str
                or item["monthly_pin_repository_path"] !=
                   "project/pins/" + item["pin_date"] + "/commit-pin.py"
                or type(item["pin_date"]) is not str
                or not _MONTH.fullmatch(item["pin_date"])
                or type(item["lane_owner"]) is not str
                or not _LANE.fullmatch(item["lane_owner"])):
            raise TaskCatalogueError("generic pipeline source/pin/lane is not frozen")
        entries = item["entries"]
        if type(entries) is not list or not 1 <= len(entries) <= 32:
            raise TaskCatalogueError("invalid generic recipe entries")
        normalized = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != {"id", "project", "recipe"}:
                raise TaskCatalogueError("recipe entry requires exact id/project/recipe")
            if (any(type(entry[field]) is not str or
                    not _PACKAGE.fullmatch(entry[field])
                    for field in ("id", "project"))
                    or type(entry["recipe"]) is not str
                    or not _RECIPE.fullmatch(entry["recipe"])
                    or not entry["recipe"].startswith(entry["project"] + "/")):
                raise TaskCatalogueError("recipe selection is not an approved relative path")
            normalized.append(dict(entry))
        if normalized != sorted(normalized, key=lambda e: e["id"]) or len(
                {v["id"] for v in normalized}) != len(normalized):
            raise TaskCatalogueError("generic recipe entries must be unique and sorted")
        reviewed = REVIEWED_IMAGE_TASKS[name]
        if normalized != [
                {"id": identifier, "project": project, "recipe": recipe}
                for identifier, project, recipe in reviewed["entries"]]:
            raise TaskCatalogueError(
                "generic recipe identities differ from reviewed task selection"
            )
        arguments = item["arguments"]
        if type(arguments) is not dict or arguments.get("mode") not in {
                "bootstrap", "image", "native-check", "seed-check"}:
            raise TaskCatalogueError("unsupported generic mode")
        if (type(arguments.get("selection")) is not str or
                not _GENERATION.fullmatch(arguments["selection"])):
            raise TaskCatalogueError("generic base generation must be immutable")
        if arguments["mode"] == "bootstrap":
            if set(arguments) != {"mode", "selection", "stages"}:
                raise TaskCatalogueError("bootstrap requires exact stages")
            stages = arguments["stages"]
            if (type(stages) is not list or not 1 <= len(stages) <= 32
                    or any(type(s) is not list or not 1 <= len(s) <= 32
                           for s in stages)):
                raise TaskCatalogueError("invalid bootstrap stages")
            names = [v for stage in stages for v in stage]
        else:
            if set(arguments) != {"mode", "selection", "targets"}:
                raise TaskCatalogueError("generic mode requires exact targets")
            names = arguments["targets"]
            if type(names) is not list or not 1 <= len(names) <= 32:
                raise TaskCatalogueError("invalid generic targets")
        if (any(type(v) is not str or not _PACKAGE.fullmatch(v) for v in names)
                or len(names) != len(set(names))
                or not set(names).issubset({v["id"] for v in normalized})):
            raise TaskCatalogueError("pipeline targets are not unique selected recipes")
        if (arguments["mode"] != "image"
                or arguments.get("targets") != list(reviewed["targets"])):
            raise TaskCatalogueError(
                "generic image targets differ from reviewed task selection"
            )
        output["tasks"][name] = json.loads(json.dumps(item))
    return output

def loads(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if type(data) is not str or len(data.encode()) > 65536:
        raise TaskCatalogueError("catalogue missing or oversized")
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise TaskCatalogueError("duplicate catalogue key")
            obj[key] = value
        return obj
    try:
        value = json.loads(data, object_pairs_hook=unique)
    except (TypeError, ValueError) as error:
        raise TaskCatalogueError("invalid task catalogue") from error
    return validate(value)

def load(path, *, require_root_owned=False):
    path = Path(path)
    if require_root_owned:
        current = path
        while True:
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022):
                raise TaskCatalogueError(
                    "generic catalogue and ancestors must be root-owned, not writable")
            if current == current.parent:
                break
            current = current.parent
    if path.is_symlink() or not path.is_file():
        raise TaskCatalogueError("catalogue must be a regular file")
    value = loads(path.read_bytes())
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()

def select(catalogue, task, *, repository, revision, lane=None,
           monthly_pin_repository_path=None, monthly_pin_identity=None):
    value = validate(catalogue)
    if task not in value["tasks"]:
        raise TaskCatalogueError("generic task is not configured")
    item = value["tasks"][task]
    if (item["source_repository"] != repository
            or item["source_revision"] != revision
            or (lane is not None and item["lane"] != lane)
            or (monthly_pin_repository_path is not None
                and item["monthly_pin_repository_path"] != monthly_pin_repository_path)
            or (monthly_pin_identity is not None
                and item["monthly_pin_identity"] != monthly_pin_identity)):
        raise TaskCatalogueError("admitted source/lane/pin differs from selected task")
    return json.loads(json.dumps(item))
