"""Shared gateway selection: distinct original base and image output evidence.

No AWS/SSM, protected owner, or actual generation acceptance occurs here.
"""
import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as graphics
from zog.host_deploy.gateway import graphics_base_acceptance as base
from zog.host_deploy.gateway import image_build_dispatch as dispatch
from zog.host_deploy.gateway import task_catalogue
from test_gateway_first_graphics_catalogue import example, candidate


def fixture():
    approval,lane,accepted,reservation=example()
    cat=candidate(approval,lane,accepted,reservation)["catalogue"]
    selected=cat["tasks"][graphics.TASK]["arguments"]["selection"]
    retained={"generation_id":selected,"kind":"toolchain",
              "evidence":{"generation_id":selected,"kind":"toolchain",
                          "stage":2,
                          "accepted_receipt_sha256":
                              approval["accepted_base_receipt_sha256"]}}
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
    lambda ev:ev["evidence"].update(stage=1),
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
