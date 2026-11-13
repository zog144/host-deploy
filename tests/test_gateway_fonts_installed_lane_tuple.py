"""Exact selected PR30 successor / PR7 tuple and native-lane source reconciliation.

All identities and Ed25519 keys used here are synthetic. No Host reads,
lane file writes, AWS, SQS or SSM execution.
"""
import copy
import hashlib
import os
from pathlib import Path
import sys

import pytest

from zog.host_deploy import image_build_lanes
from zog.host_deploy.gateway import (
    fonts_lane_review, graphics_catalogue_owner as owner,
    graphics_base_acceptance as reader, task_catalogue,
)


EXPECTED_BLOBS = {
    "gateway/task_catalogue.py": "c96218c9312fd5447aa386711438e9b458008d16",
    # Successor lane-admission source from PR #32; PR30 pinned the predecessor at 998354c9... .
    "image_build_lanes.py": "48abc6dca385b5d171b6fa00146d6edbefa26d50",
    "gateway/graphics_catalogue_owner.py": "bdd2bb6bdf7f337a8e174be5f3dbea02819288d8",
    "gateway/graphics_base_acceptance.py": "fab7f59bb43afdc057339a9e80d7d3b548b4d5b2",
}


def git_blob(path):
    raw=Path(path).read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+bytes([0])+raw).hexdigest()


def test_reviewed_installed_module_tuple_is_exact_fonts_profile_successor_contract():
    root=Path(__file__).resolve().parents[1]/"src/zog/host_deploy"
    for path,sha in EXPECTED_BLOBS.items():
        assert git_blob(root/path)==sha, path
    assert owner.SOURCE=="1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert owner.PIN_SHA256=="d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert owner.READER_SOURCE=="1616f192ef9d8964a8f37f32a86c69c0242a213c"
    assert owner.STORE==Path("/var/lib/host-deploy-gateway")
    assert reader.SOURCE==owner.SOURCE
    assert reader.PIN=="sha256:"+owner.PIN_SHA256


def test_pr30_task_catalogue_and_lane_accept_exact_pr7_signed_fonts_selection():
    source=Path(os.environ["ZOG_HOSTDEPLOY_FONTS_PR7"])
    assert source.is_dir()
    sys.path.insert(0,str(source/"tests"))
    from test_gateway_first_graphics_catalogue import example, candidate
    for kind in ("image","toolchain"):
        source_context,lane,selection=example(kind)
        review=fonts_lane_review.review([
            {"schema":lane["schema"],"lane":lane["lane"],
             "specification":lane,"state":"active"}])
        assert review["status"]=="MATCHING_ACTIVE_LANE_SOURCE_ONLY"
        assert review["specification_sha256"]==image_build_lanes.specification_sha256(lane)
        selected=candidate(source_context,lane,selection)
        assert selected["accepted_base_kind"]==kind
        assert selected["compiler_authorized"] is False
        parsed=task_catalogue.loads(selected["bytes"])
        task=parsed["tasks"][owner.TASK]
        assert task["arguments"]["selection"]==source_context["accepted_base_generation_id"]
        assert task["arguments"]["compiler_base"]==source_context["accepted_base_receipt_sha256"]
        assert task["retained_acceptance_sha256"]==selected["retained_acceptance_sha256"]
        assert task["monthly_pin_identity"]=="sha256:"+owner.PIN_SHA256
        assert list(parsed["tasks"])==[owner.TASK]


def lane(name, *, source=None, pin=None, project=None, project_id=None):
    return image_build_lanes.specification(
        name, source_repository=owner.REPOSITORY,
        source_revision=source or owner.SOURCE,
        monthly_pin_repository_path=owner.PIN_PATH,
        monthly_pin_identity=pin or "sha256:"+owner.PIN_SHA256,
        provenance_host_id="compiler-host-fixture",
        provenance_project_id=project_id or "project-"+name,
        project_root=project or "/var/lib/zog/image-build-lanes/"+name,
        memory_maximum_bytes=1024**3,
        thread_count_maximum=4,cpu_weight=100,disk_reservation_bytes=1,
        execution_user_id=24302,execution_group_id=24302,
        python_executable="/usr/bin/python3")


def record(spec, state="active"):
    return {"schema":spec["schema"],"lane":spec["lane"],
            "specification":spec,"state":state}


def test_two_mismatched_active_lanes_require_a_distinct_reviewed_proposal():
    original=lane("original",source="a"*40)
    oldpin=lane("legacy",source="b"*40,pin="sha256:"+"c"*64)
    retained=[record(original),record(oldpin)]
    snapshot=copy.deepcopy(retained)
    result=fonts_lane_review.review(retained)
    assert result=={
        "status":"NO_MATCHING_ACTIVE_LANE_REVIEW_REQUIRED",
        "examined":2,"mutated":False,
    }
    proposed=lane("compiler-fonts")
    outcome=fonts_lane_review.review(retained,proposed)
    assert outcome["status"]=="DISTINCT_LANE_PROPOSAL_NOT_PREPARED"
    assert outcome["lane"]=="compiler-fonts"
    assert outcome["source_revision"]==owner.SOURCE
    assert outcome["monthly_pin_identity"]=="sha256:"+owner.PIN_SHA256
    assert outcome["specification_sha256"]==image_build_lanes.specification_sha256(proposed)
    assert outcome["mutated"] is False
    assert retained==snapshot


@pytest.mark.parametrize("change", [
    lambda p:p.update(lane="original"),
    lambda p:p.update(project_root="/var/lib/zog/image-build-lanes/original"),
    lambda p:p.update(provenance_project_id="project-original"),
    lambda p:p.update(source_revision="0"*40),
    lambda p:p.update(monthly_pin_identity="sha256:"+"0"*64),
    lambda p:p.update(mode="reservation"),
])
def test_no_rebinding_existing_lanes_or_foreign_proposed_producer(change):
    records=[record(lane("original",source="a"*40)),
             record(lane("legacy",source="b"*40,
                         pin="sha256:"+"c"*64))]
    proposal=lane("compiler-fonts")
    change(proposal)
    with pytest.raises((fonts_lane_review.FontsLaneHeld,ValueError)):
        fonts_lane_review.review(records,proposal)


def test_ambiguous_matching_lanes_and_reuse_of_active_lane_hold():
    first=lane("first-fonts")
    second=lane("other-fonts")
    with pytest.raises(fonts_lane_review.FontsLaneHeld):
        fonts_lane_review.review([record(first),record(second)])
    with pytest.raises(fonts_lane_review.FontsLaneHeld):
        fonts_lane_review.review([record(first)],proposed_spec=lane("third-fonts"))
