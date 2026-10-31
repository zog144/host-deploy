"""The server task selector is finite, source-bound and not a worker alias."""
import copy
import json

import pytest

from zog.host_deploy.gateway.protocol import BUILD_TASKS
from zog.host_deploy.gateway.task_catalogue import (
    TaskCatalogueError, load, select, validate
)


REVISION = "a" * 40
PIN = "sha256:" + "b" * 64
MONTH = "project/pins/2026-10-01/commit-pin.py"

EXPECTED = {
    "graphics-fonts-image-v1": {
        "entries": [
            ("fontconfig-final", "fontconfig", "fontconfig/stages/final"),
            ("freetype-final", "freetype", "freetype/stages/final"),
            ("libpng-final", "libpng", "libpng/stages/final"),
        ],
        "targets": ["libpng-final", "freetype-final", "fontconfig-final"],
    },
    "graphics-xcb-core-image-v1": {
        "entries": [
            ("check-final", "check", "check/stages/final"),
            ("libXau-final", "libXau", "libXau/stages/final"),
            ("libXdmcp-final", "libXdmcp", "libXdmcp/stages/final"),
            ("libevdev-final", "libevdev", "libevdev/stages/final"),
            ("libxcb-final", "libxcb", "libxcb/stages/final"),
            ("python-libevdev-final", "python-libevdev", "python-libevdev/stages/final"),
            ("xcb-proto-final", "xcb-proto", "xcb-proto/stages/final"),
            ("xorgproto-final", "xorgproto", "xorgproto/stages/final"),
        ],
        "targets": [
            "check-final", "libevdev-final", "python-libevdev-final",
            "xorgproto-final", "libXau-final", "libXdmcp-final",
            "xcb-proto-final", "libxcb-final",
        ],
    },
    "graphics-x11-core-image-v1": {
        "entries": [
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
        ],
        "targets": [
            "xtrans-final", "libX11-final", "libXext-final", "libXfixes-final",
            "libXi-final", "libXtst-final", "libXv-final", "libxkbfile-final",
            "libfontenc-final", "libXfont2-final",
        ],
    },
    "xcb-support-image-v1": {
        "entries": [
            ("xcb-util-final", "xcb-util", "xcb-util/stages/final"),
            ("xcb-util-image-final", "xcb-util-image", "xcb-util-image/stages/final"),
            ("xcb-util-keysyms-final", "xcb-util-keysyms", "xcb-util-keysyms/stages/final"),
            ("xcb-util-wm-final", "xcb-util-wm", "xcb-util-wm/stages/final"),
            ("xcb-util-xrm-final", "xcb-util-xrm", "xcb-util-xrm/stages/final"),
        ],
        "targets": [
            "xcb-util-final", "xcb-util-image-final", "xcb-util-keysyms-final",
            "xcb-util-wm-final", "xcb-util-xrm-final",
        ],
    },
}


def item(name):
    spec = EXPECTED[name]
    return {
        "source_repository": "zog144/image-build",
        "source_revision": REVISION,
        "lane": "lane-a",
        "lane_owner": "host-a",
        "monthly_pin_repository_path": MONTH,
        "monthly_pin_identity": PIN,
        "pin_date": "2026-10-01",
        "entries": [
            {"id": identifier, "project": project, "recipe": recipe}
            for identifier, project, recipe in spec["entries"]
        ],
        "arguments": {
            "mode": "image",
            "selection": "e" * 64,
            "targets": list(spec["targets"]),
        },
    }


def catalogue(*names):
    names = names or ("xcb-support-image-v1",)
    return {"schema": 2, "tasks": {name: item(name) for name in names}}


def test_protocol_and_catalogue_have_exact_same_finite_build_tasks():
    assert set(BUILD_TASKS) == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_reviewed_graphics_task_is_exact_and_selectable(tmp_path, name):
    path = tmp_path / "tasks.json"
    path.write_text(json.dumps(catalogue(name)))
    value, digest = load(path)
    assert digest.startswith("sha256:")
    task = select(
        value, name, repository="zog144/image-build", revision=REVISION,
        lane="lane-a", monthly_pin_repository_path=MONTH,
        monthly_pin_identity=PIN,
    )
    assert task["entries"] == item(name)["entries"]
    assert task["arguments"]["targets"] == EXPECTED[name]["targets"]
    assert task["arguments"]["mode"] == "image"


def test_multiple_reviewed_graphics_tasks_share_no_caller_selected_recipe_paths():
    value = validate(catalogue(*sorted(EXPECTED)))
    assert set(value["tasks"]) == set(EXPECTED)
    assert all(task["source_revision"] == REVISION for task in value["tasks"].values())


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_task_identity_changes_when_immutable_base_changes(tmp_path, name):
    path = tmp_path / "tasks.json"
    value = catalogue(name)
    path.write_text(json.dumps(value))
    first = load(path)[1]
    value["tasks"][name]["arguments"]["selection"] = "f" * 64
    path.write_text(json.dumps(value))
    assert load(path)[1] != first


@pytest.mark.parametrize("mutation", [
    "worker", "branch", "generation", "target", "entry", "duplicate",
    "path", "wrong-pin", "foreign-source", "owner", "unsorted", "missing",
    "unknown-mode",
])
def test_rejects_unreviewed_generic_task(mutation):
    value = catalogue()
    item_value = value["tasks"]["xcb-support-image-v1"]
    if mutation == "worker":
        value["tasks"]["final-compiler"] = value["tasks"].pop("xcb-support-image-v1")
    elif mutation == "branch":
        item_value["source_revision"] = "unstable"
    elif mutation == "generation":
        item_value["arguments"]["selection"] = "latest"
    elif mutation == "target":
        item_value["arguments"]["targets"] = ["glibc-final"]
    elif mutation == "entry":
        item_value["entries"][0]["id"] = "not-approved"
    elif mutation == "duplicate":
        item_value["entries"].append(dict(item_value["entries"][0]))
    elif mutation == "path":
        item_value["entries"][0]["recipe"] = "../../private"
    elif mutation == "wrong-pin":
        item_value["monthly_pin_repository_path"] = "project/pins/latest"
    elif mutation == "foreign-source":
        item_value["source_repository"] = "untrusted/image-build"
    elif mutation == "owner":
        item_value["lane_owner"] = "../../root"
    elif mutation == "unsorted":
        item_value["entries"].reverse()
    elif mutation == "missing":
        del item_value["entries"]
    elif mutation == "unknown-mode":
        item_value["arguments"]["mode"] = "maintained"
    with pytest.raises(TaskCatalogueError):
        validate(value)


def test_task_cannot_borrow_another_reviewed_recipe_set():
    value = catalogue("graphics-fonts-image-v1")
    value["tasks"]["graphics-fonts-image-v1"]["entries"] = item(
        "graphics-xcb-core-image-v1"
    )["entries"]
    value["tasks"]["graphics-fonts-image-v1"]["arguments"]["targets"] = item(
        "graphics-xcb-core-image-v1"
    )["arguments"]["targets"]
    with pytest.raises(TaskCatalogueError, match="reviewed task selection"):
        validate(value)


def test_selector_rejects_different_lane_or_pin():
    value = catalogue()
    with pytest.raises(TaskCatalogueError, match="differs"):
        select(
            value, "xcb-support-image-v1", repository="zog144/image-build",
            revision=REVISION, lane="other",
        )
    with pytest.raises(TaskCatalogueError, match="differs"):
        select(
            value, "xcb-support-image-v1", repository="zog144/image-build",
            revision=REVISION, monthly_pin_identity="sha256:" + "f" * 64,
        )


def test_catalogue_refuses_symlink(tmp_path):
    src = tmp_path / "real.json"
    src.write_text(json.dumps(catalogue()))
    link = tmp_path / "tasks.json"
    link.symlink_to(src)
    with pytest.raises(TaskCatalogueError, match="regular file"):
        load(link)
