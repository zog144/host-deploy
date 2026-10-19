"""Supervised generic pipeline uses durable IDs; never replays uncertain SSM."""
import copy
import json
from pathlib import Path

import pytest

from zog.host_deploy.gateway import generic_pipeline as generic

GATEWAY = "a"*32
SRC = {"repository":"zog144/image-build","revision":"b"*40}
RECIPES = [
    {"id":name,"project":name.removesuffix("-final"),
     "recipe":name.removesuffix("-final")+"/stages/final"}
    for name in ("xcb-util-final", "xcb-util-image-final",
                 "xcb-util-keysyms-final", "xcb-util-wm-final",
                 "xcb-util-xrm-final")
]
SNAPSHOT="sha256:"+"e"*64
PIPELINE="c"*32

def base():
    return {
        "schema":3,
        "request_id":GATEWAY,
        "source":SRC,
        "task":{
            "entries":RECIPES,
            "pin_date":"2026-10-01",
            "arguments":{
                "mode":"image","selection":"d"*64,
                "targets":[v["id"] for v in RECIPES],
            },
        },
        "task_catalogue_identity":"sha256:"+"f"*64,
    }

def capability():
    return {"contract":"image-build-remote-capabilities-v1",
            "source":SRC,
            "request_contract":"image-build-remote-operation-v1",
            "result_contract":"image-build-remote-result-v1",
            "operations":["capabilities.inspect","recipes.snapshot",
                          "pipeline.submit","pipeline.inspect"],
            "generic_pipeline":{
                "supported":True,
                "recipe_snapshot":{"operation":"recipes.snapshot",
                                   "contract":"image-build-recipe-snapshot-v1",
                                   "required_for":["pipeline.submit","pipeline.retry"]},
                "submit":{"operation":"pipeline.submit","modes":["image"],
                          "requires_recipe_snapshot":True},
                "recovery":{"inspect":"pipeline.inspect","resume":"pipeline.resume",
                            "cancel":"pipeline.cancel","retry":"pipeline.retry",
                            "automatic_retry":False}},
            "maintained_workers":{
                "generic_pipeline_submit_equivalent":False,
                "remote_execution_operation":None,
            }}

def mock_environment(monkeypatch, *, wrong_capability=None, lost_reply=False):
    binding=base()
    monkeypatch.setattr(generic,"_base",lambda root,ident: (
        {"request":{"operation":"build.submit"},"states":{"admission":"admitted"}},
        binding))
    monkeypatch.setattr(generic,"_stage_binding",
                        lambda b,step:{
                            "request_id":step["operation_id"],
                            "remote_request":step["request"],
                            "source":SRC,
                        })
    monkeypatch.setattr(generic,"verify_current_target",
                        lambda root,b:{"instance_id":"i-0123456789abcdef0"})
    monkeypatch.setattr(generic,"producer_runtime_preflight",
                        lambda host,b:{"ready":True,"mutation":False})
    monkeypatch.setattr(generic,"remote_script",
                        lambda stage:stage["remote_request"]["operation"])
    seen=[]
    class Host:
        def __init__(self,configuration):pass
        def submit_command(self,script,seconds):
            seen.append(("submit",script))
            if lost_reply:
                raise TimeoutError("unknown SSM SendCommand reply")
            return "command-"+str(len(seen))
        def inspect_command(self,ident):
            seen.append(("inspect",ident))
            return {"Status":"Success","StandardOutputContent":"fixture"}
    def parse(text,binding):
        operation=binding["remote_request"]["operation"]
        if operation=="capabilities.inspect":
            result={"status":"completed","uncertainty":False,
                    "artifacts":{"remote_capabilities":
                                 wrong_capability or capability()}}
        elif operation=="recipes.snapshot":
            result={"status":"completed","uncertainty":False,
                    "recipe_identity":SNAPSHOT,
                    "artifacts":{"recipe_snapshot":SNAPSHOT,
                                 "contract":"image-build-recipe-snapshot-v1",
                                 "pin_date":"2026-10-01"}}
        elif operation=="pipeline.submit":
            assert binding["remote_request"]["arguments"]["recipe_snapshot"]==SNAPSHOT
            assert binding["remote_request"]["predecessor"]==generic._operation_id(
                GATEWAY,"snapshot")
            result={"status":"pending","uncertainty":False,
                    "pipeline_id":PIPELINE}
        else:
            assert operation=="pipeline.inspect"
            assert binding["remote_request"]["arguments"]["pipeline_id"]==PIPELINE
            result={"status":"completed","uncertainty":False,
                    "pipeline_id":PIPELINE}
        return {"result":result}
    monkeypatch.setattr(generic,"parse_receipt",parse)
    return Host,seen

def test_four_separate_durable_operations(tmp_path,monkeypatch):
    Host,calls=mock_environment(monkeypatch)
    stages=[]
    for _ in range(16):
        state=generic.advance(tmp_path,GATEWAY,host_factory=Host)
        if state["phase"]=="completed":break
        stages.append(copy.deepcopy(state))
    assert state["phase"]=="completed"
    assert [x["name"] for x in state["stages"]]==list(generic.STAGES)
    assert all(x["phase"]=="completed" for x in state["stages"])
    assert len({x["operation_id"] for x in state["stages"]})==4
    assert state["recipe_identity"]==SNAPSHOT
    assert state["pipeline_id"]==PIPELINE
    assert len([v for v in calls if v[0]=="submit"])==4
    assert generic.status(tmp_path,GATEWAY)==state
    assert generic.advance(tmp_path,GATEWAY,host_factory=Host)==state
    assert len([v for v in calls if v[0]=="submit"])==4

def test_unknown_ssm_send_reply_never_reissues_operation(tmp_path,monkeypatch):
    Host,calls=mock_environment(monkeypatch,lost_reply=True)
    state=generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert state["stages"][0]["phase"]=="prepared"
    with pytest.raises(TimeoutError):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    retained=generic.status(tmp_path,GATEWAY)
    assert retained["phase"]=="uncertain"
    assert retained["stages"][0]["phase"]=="uncertain"
    assert generic.advance(tmp_path,GATEWAY,host_factory=Host)==retained
    assert len([v for v in calls if v[0]=="submit"])==1

def test_restart_with_saved_submitting_is_uncertain(tmp_path,monkeypatch):
    Host,calls=mock_environment(monkeypatch)
    generic.advance(tmp_path,GATEWAY,host_factory=Host)
    path=tmp_path/"requests"/GATEWAY/generic.FILE
    value=json.loads(path.read_text())
    value["stages"][0]["phase"]="submitting"
    path.write_text(json.dumps(value))
    state=generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert state["phase"]=="uncertain"
    assert not calls

def test_source_mismatched_capability_blocks_before_snapshot(tmp_path,monkeypatch):
    document=capability()
    document["source"]={"repository":"zog144/image-build","revision":"0"*40}
    Host,calls=mock_environment(monkeypatch,wrong_capability=document)
    generic.advance(tmp_path,GATEWAY,host_factory=Host)
    generic.advance(tmp_path,GATEWAY,host_factory=Host)
    with pytest.raises(RuntimeError,match="bound to deployed source"):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    state=generic.status(tmp_path,GATEWAY)
    assert state["phase"]=="uncertain"
    assert len(state["stages"])==1
    assert len([v for v in calls if v[0]=="submit"])==1

@pytest.mark.parametrize("change",[
    {"generic_pipeline":{"supported":False}},
    {"maintained_workers":{"generic_pipeline_submit_equivalent":True,
                           "remote_execution_operation":"worker.submit"}},
])
def test_capability_rejects_maintained_worker_fallback(change):
    document=capability()
    document.update(change)
    with pytest.raises(RuntimeError):
        generic._capabilities({"status":"completed","uncertainty":False,
                               "artifacts":{"remote_capabilities":document}},
                              base())
