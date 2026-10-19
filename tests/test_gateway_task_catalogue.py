"""The server task selector is finite, source-bound and not a worker alias."""
import copy
import json
import pytest
from zog.host_deploy.gateway.task_catalogue import (
    TaskCatalogueError, load, select, validate
)

REVISION="a"*40
PIN="sha256:"+"b"*64
MONTH="project/pins/2026-10-01/commit-pin.py"
NAMES=("xcb-util-final","xcb-util-image-final","xcb-util-keysyms-final",
       "xcb-util-wm-final","xcb-util-xrm-final")

def catalogue():
    return {
        "schema":2,
        "tasks":{
            "xcb-support-image-v1":{
                "source_repository":"zog144/image-build",
                "source_revision":REVISION,
                "lane":"lane-a","lane_owner":"host-a",
                "monthly_pin_repository_path":MONTH,
                "monthly_pin_identity":PIN,
                "pin_date":"2026-10-01",
                "entries":[{"id":name,"project":name.removesuffix("-final"),
                            "recipe":name.removesuffix("-final")+"/stages/final"} for name in NAMES],
                "arguments":{"mode":"image","selection":"e"*64,
                             "targets":list(NAMES)},
            }
        }
    }

def test_catalogue_finite_selection_and_identity(tmp_path):
    path=tmp_path/"tasks.json"
    path.write_text(json.dumps(catalogue()))
    value, digest=load(path)
    assert digest.startswith("sha256:")
    task=select(value,"xcb-support-image-v1",repository="zog144/image-build",
                revision=REVISION,lane="lane-a",
                monthly_pin_repository_path=MONTH,monthly_pin_identity=PIN)
    assert task["entries"][0]["id"] == NAMES[0]
    assert task["arguments"]["mode"] == "image"
    change=catalogue()
    change["tasks"]["xcb-support-image-v1"]["arguments"]["selection"]="f"*64
    path.write_text(json.dumps(change))
    assert load(path)[1] != digest

@pytest.mark.parametrize("mutation",[
    "worker","branch","generation","target","entry","duplicate",
    "path","wrong-pin","foreign-source","owner","unsorted","missing",
    "unknown-mode",
])
def test_rejects_unreviewed_generic_task(mutation):
    value=catalogue()
    item=value["tasks"]["xcb-support-image-v1"]
    if mutation=="worker":
        value["tasks"]["final-compiler"]=value["tasks"].pop("xcb-support-image-v1")
    elif mutation=="branch": item["source_revision"]="unstable"
    elif mutation=="generation": item["arguments"]["selection"]="latest"
    elif mutation=="target": item["arguments"]["targets"]=["glibc-final"]
    elif mutation=="entry": item["entries"][0]["id"]="not-approved"
    elif mutation=="duplicate": item["entries"].append(dict(item["entries"][0]))
    elif mutation=="path": item["entries"][0]["recipe"]="../../private"
    elif mutation=="wrong-pin": item["monthly_pin_repository_path"]="project/pins/latest"
    elif mutation=="foreign-source":item["source_repository"]="untrusted/image-build"
    elif mutation=="owner":item["lane_owner"]="../../root"
    elif mutation=="unsorted":item["entries"].reverse()
    elif mutation=="missing":del item["entries"]
    elif mutation=="unknown-mode":item["arguments"]["mode"]="maintained"
    with pytest.raises(TaskCatalogueError):
        validate(value)

def test_selector_rejects_different_lane_or_pin():
    value=catalogue()
    with pytest.raises(TaskCatalogueError,match="differs"):
        select(value,"xcb-support-image-v1",repository="zog144/image-build",
               revision=REVISION,lane="other")
    with pytest.raises(TaskCatalogueError,match="differs"):
        select(value,"xcb-support-image-v1",repository="zog144/image-build",
               revision=REVISION,monthly_pin_identity="sha256:"+"f"*64)

def test_catalogue_refuses_symlink(tmp_path):
    src=tmp_path/"real.json"
    src.write_text(json.dumps(catalogue()))
    link=tmp_path/"tasks.json"
    link.symlink_to(src)
    with pytest.raises(TaskCatalogueError,match="regular file"):
        load(link)
