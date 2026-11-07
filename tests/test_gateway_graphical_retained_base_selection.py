"""Shared gateway selection: distinct original base and image output evidence.

No AWS/SSM, protected owner, or actual generation acceptance occurs here.
"""
import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as graphics
from zog.host_deploy.gateway import graphics_base_acceptance as base
from zog.host_deploy.gateway import image_build_dispatch as dispatch
from zog.host_deploy.gateway import task_catalogue
from test_gateway_first_graphics_catalogue import example, candidate, base_evidence


def fixture():
    approval,lane,accepted,reservation=example()
    cat=candidate(approval,lane,accepted,reservation)["catalogue"]
    selected=cat["tasks"][graphics.TASK]["arguments"]["selection"]
    receipt,issuer,binding=base_evidence(approval,lane)
    bound=base.checked_base(receipt,issuer,binding,approval=approval,lane=lane)
    retained={"generation_id":selected,"kind":"toolchain","evidence":bound}
    request={"operation":"build.submit","request_id":"1"*32,
             "parameters":{"task":graphics.TASK,"lane":approval["lane"]},
             "source":{"repository":graphics.REPOSITORY,
                       "commit":graphics.SOURCE}}
    return request,lane,cat,retained


def run(request,lane,cat,evidence):
    return dispatch._remote_request(
        request,lane,task_catalogue=cat,
        task_catalogue_identity="sha256:"+"0"*64,
        retained_input_evidence=evidence)


def test_fonts_original_base_required_for_request_selection():
    req,lane,cat,evidence=fixture()
    with pytest.raises(task_catalogue.TaskCatalogueError):
        run(req,lane,cat,None)
    command,binding=run(req,lane,cat,evidence)
    assert command["operation"]=="capabilities.inspect"
    assert binding["task"]["arguments"]["selection"]==evidence["generation_id"]
    assert binding["task_catalogue_identity"]=="sha256:"+"0"*64


@pytest.mark.parametrize("change",[
    lambda ev:ev.update(generation_id="0"*64),
    lambda ev:ev.update(kind="image"),
    lambda ev:ev["evidence"].update(target_abi="aarch64-linux-gnu"),
    lambda ev:ev["evidence"].update(accepted_receipt_sha256="sha256:"+"0"*64),
])
def test_wrong_accepted_input_does_not_select_graphical_request(change):
    req,lane,cat,evidence=fixture()
    change(evidence)
    with pytest.raises(task_catalogue.TaskCatalogueError):
        run(req,lane,cat,evidence)


def test_source_pin_lane_and_task_remain_independent():
    req,lane,cat,evidence=fixture()
    req["source"]["commit"]="0"*40
    with pytest.raises(RuntimeError):
        run(req,lane,cat,evidence)
    req,lane,cat,evidence=fixture()
    lane["monthly_pin_identity"]="sha256:"+"0"*64
    with pytest.raises(task_catalogue.TaskCatalogueError):
        run(req,lane,cat,evidence)
    req,lane,cat,evidence=fixture()
    req["parameters"]["task"]="graphics-xcb-core-image-v1"
    with pytest.raises(task_catalogue.TaskCatalogueError):
        run(req,lane,cat,evidence)


def test_later_image_batch_retains_image_kind_with_exact_native_receipt():
    """Acceptance is reusable as a pinned image, not a toolchain substitute.

    A separately approved dependency edge and original operation owner remain
    mandatory outside this narrow task-selection test.
    """
    import hashlib
    import json
    req,lane,cat,_=fixture()
    task_name="graphics-xcb-core-image-v1"
    image_generation="9"*64
    attested={
        "schema":base.OUTPUT_SCHEMA,
        "task":"graphics-fonts-image-v1",
        "host_id":lane["provenance_host_id"],
        "installation_id":"fixture-installation",
        "lane":lane["lane"],
        "lane_owner":lane["provenance_host_id"],
        "project_root":lane["project_root"],
        "source_revision":graphics.SOURCE,
        "monthly_pin_identity":"sha256:"+graphics.PIN_SHA256,
        "request_id":"7"*32,"pipeline_id":"8"*32,
        "predecessor_catalogue_sha256":"sha256:"+"0"*64,
        "input_generation_id":cat["tasks"][graphics.TASK]["arguments"]["selection"],
        "output_generation_id":image_generation,
        "output_kind":"image",
        "generation_manifest_sha256":"sha256:"+"1"*64,
        "acceptance_receipt_sha256":"sha256:"+"2"*64,
        "producer_receipt_sha256":"sha256:"+"3"*64,
        "status":"accepted","terminal_outcome":"success",
        "uncertainty":False,"missing_evidence_count":0,
    }
    retained={"generation_id":image_generation,"kind":"image","evidence":attested}
    digest="sha256:"+hashlib.sha256(json.dumps(
        retained,sort_keys=True,separators=(",",":"),
        ensure_ascii=True).encode("ascii")).hexdigest()
    selected=cat["tasks"][graphics.TASK].copy()
    reviewed=task_catalogue.REVIEWED_IMAGE_TASKS[task_name]
    selected["entries"]=[{"id":id,"project":project,"recipe":recipe}
                          for id,project,recipe in reviewed["entries"]]
    selected["arguments"]={"mode":"image","selection":image_generation,
                           "targets":list(reviewed["targets"])}
    selected["retained_acceptance_sha256"]=digest
    catalogue={"schema":task_catalogue.SCHEMA,"tasks":{task_name:selected}}
    req["parameters"]["task"]=task_name
    command,binding=run(req,lane,catalogue,retained)
    assert command["operation"]=="capabilities.inspect"
    assert binding["task"]["arguments"]["selection"]==image_generation
    assert binding["task"]["retained_acceptance_sha256"]==digest
    # A valid-looking *different* accepted image cannot replace the original.
    alternate=dict(retained)
    alternate["evidence"]={**attested,
                          "producer_receipt_sha256":"sha256:"+"4"*64}
    with pytest.raises(task_catalogue.TaskCatalogueError):
        run(req,lane,catalogue,alternate)
    with pytest.raises(task_catalogue.TaskCatalogueError):
        run(req,lane,catalogue,{**retained,"kind":"toolchain"})


def test_initial_fonts_can_keep_signed_compiler_image_original_kind():
    approval,lane,accepted,reservation=example("image")
    catalogue=candidate(approval,lane,accepted,reservation)["catalogue"]
    receipt,issuer,binding=base_evidence(approval,lane,kind="image")
    selected=base.checked_base(receipt,issuer,binding,approval=approval,lane=lane)
    retained={"generation_id":approval["accepted_base_generation_id"],
              "kind":"image","evidence":selected}
    req={"operation":"build.submit","request_id":"1"*32,
         "parameters":{"task":graphics.TASK,"lane":approval["lane"]},
         "source":{"repository":graphics.REPOSITORY,"commit":graphics.SOURCE}}
    _,choice=run(req,lane,catalogue,retained)
    assert choice["task"]["arguments"]["selection"]==selected["generation_id"]
    assert choice["task"]["retained_acceptance_sha256"]==catalogue[
        "tasks"][graphics.TASK]["retained_acceptance_sha256"]
    assert retained["kind"]=="image"
    assert selected["historical_provenance"]["status"]=="historical-gap-declared"
