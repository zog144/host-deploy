"""Exact selected PR30 successor / PR7 tuple and native-lane source reconciliation.

All identities and Ed25519 keys used here are synthetic. No Host reads,
lane file writes, AWS, SQS or SSM execution.
"""
import copy
import hashlib
import json
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
    # The old lane module is allowed an additive immutable producer successor.
    # Its historical exact source identities are checked below instead.
    "gateway/graphics_catalogue_owner.py": "bf96526d7b7005258dac0b29f3ffe94427fe4cc3",
    "gateway/graphics_base_acceptance.py": "66f5c0c57fc49688973e05c28ad1cf31d157344e",
}


def git_blob(path):
    raw=Path(path).read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+bytes([0])+raw).hexdigest()


_CURRENT_SPECIFICATION = image_build_lanes.specification  # before fixture-only patch


def historical_specification(*args, **kwargs):
    """Serialize an old synthetic lane; not an executable identity selector."""
    user = kwargs.pop("execution_user_id")
    group = kwargs.pop("execution_group_id")
    # Use the current strict API; add historical fields only AFTER it returns.
    new = _CURRENT_SPECIFICATION(*args, **kwargs)
    new["schema"] = image_build_lanes.SCHEMA
    new["controller"]["execution_user_id"] = user
    new["controller"]["execution_group_id"] = group
    return image_build_lanes.validate(new)


def test_reviewed_installed_module_tuple_is_exact_fonts_profile_successor_contract():
    root=Path(__file__).resolve().parents[1]/"src/zog/host_deploy"
    for path,sha in EXPECTED_BLOBS.items():
        assert git_blob(root/path)==sha, path
    assert image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION == (
        "620378bdd8075daeb5eaad45eedea4af7db36423")
    assert image_build_lanes.FIRST_FONTS_PROJECT_DEFAULT_PRODUCER_REVISION == (
        "6b344aad3d3389d3f444bd69b63214a4a5903ad5")
    assert image_build_lanes.FIRST_FONTS_ORIGINAL_PIN_IDENTITY == (
        "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36")
    assert image_build_lanes.FIRST_FONTS_ORIGINAL_PIN_PATH == (
        "project/pins/2026-10-01/commit-pin.py")
    assert image_build_lanes.expected_build_record_revision(
        image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION) == (
        image_build_lanes.FIRST_FONTS_BUILD_RECORD_COMPATIBILITY)
    assert owner.SOURCE=="1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert owner.PIN_SHA256=="d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert owner.READER_SOURCE=="1616f192ef9d8964a8f37f32a86c69c0242a213c"
    assert owner.STORE==Path("/var/lib/host-deploy-gateway")
    assert reader.SOURCE==owner.SOURCE
    assert reader.PIN=="sha256:"+owner.PIN_SHA256


def test_original_pr7_signed_fonts_generation_still_selects_new_catalogue(monkeypatch):
    """Original signed image/toolchain receipts survive without origin-lane lookup."""
    source = Path(os.environ["ZOG_HOSTDEPLOY_FONTS_PR7"])
    assert source.is_dir()
    sys.path.insert(0, str(source / "tests"))
    from test_gateway_first_graphics_catalogue import (
        example, base_evidence, accepted_pin_bytes,
    )
    # PR7's historical fixture is used only to construct ORIGINAL signed
    # compiler evidence. The current consumer receives no origin-lane record.
    with monkeypatch.context() as patch:
        patch.setattr(image_build_lanes, "specification", historical_specification)
        selections = [example(kind) for kind in ("image", "toolchain")]
    for kind, (source_context, original, selection) in zip(
            ("image", "toolchain"), selections):
        raw, issuer, binding = base_evidence(source_context, original, kind)
        execution = _CURRENT_SPECIFICATION(
            "reviewed-fonts-" + kind, mode="managed",
            project_root="/var/lib/zog/image-build/projects/reviewed-fonts-" + kind,
            provenance_host_id=original["provenance_host_id"],
            provenance_project_id="fonts-execution-" + kind,
            source_repository=owner.REPOSITORY,
            source_revision=image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
            monthly_pin_repository_path=owner.PIN_PATH,
            monthly_pin_identity="sha256:" + owner.PIN_SHA256,
            memory_maximum_bytes=1024**3, thread_count_maximum=4,
            cpu_weight=100, disk_reservation_bytes=1,
            python_executable="/usr/bin/python3",
        )
        selected = owner.prepare(
            lane_record=execution, accepted_base=selection,
            installed_pin_bytes=accepted_pin_bytes(),
            compiler_base_receipt_bytes=raw,
            compiler_base_issuer_policy=issuer,
            compiler_base_binding=binding,
            compiler_base_provenance=compiler_origin(raw, original["project_root"]),
        )
        assert selected["accepted_base_kind"] == kind
        assert selected["compiler_authorized"] is False
        assert selected["compiler_origin_project_id"] == original["provenance_project_id"]
        assert selected["execution_project_id"] == execution["provenance_project_id"]
        assert selected["compiler_origin_project_root"] != selected["execution_project_root"]
        parsed = task_catalogue.loads(selected["bytes"])
        task = parsed["tasks"][owner.TASK]
        assert task["arguments"]["selection"] == source_context["accepted_base_generation_id"]
        assert task["arguments"]["compiler_base"] == source_context["accepted_base_receipt_sha256"]
        assert task["retained_acceptance_sha256"] == selected["retained_acceptance_sha256"]
        assert task["monthly_pin_identity"] == "sha256:" + owner.PIN_SHA256
        assert list(parsed["tasks"]) == [owner.TASK]



def lane(name, *, source=None, pin=None, project=None, project_id=None):
    return historical_specification(
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


def compiler_origin(receipt, project_root):
    """Extract independently attestable generation identity, not a lane record."""
    claim = json.loads(receipt)["claim"]
    return {
        key: (
            reader.ORIGIN_SCHEMA if key == "schema"
            else project_root if key == "project_root"
            else reader.digest(receipt) if key == "acceptance_receipt_sha256"
            else claim[key]
        )
        for key in reader.ORIGIN_FIELDS
    }


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


def test_corrected_first_fonts_catalogue_binds_new_executable_to_original_signed_base(monkeypatch):
    """Same signed compiler acceptance; only the executable lane/source changes."""
    source=Path(os.environ["ZOG_HOSTDEPLOY_FONTS_PR7"])
    assert source.is_dir()
    sys.path.insert(0, str(source / "tests"))
    from test_gateway_first_graphics_catalogue import (example, base_evidence,
                                                       accepted_pin_bytes)
    with monkeypatch.context() as patch:
        patch.setattr(image_build_lanes, "specification", historical_specification)
        evidence, origin, selected = example("image")
    revised = _CURRENT_SPECIFICATION(
        "gateway-first-fonts-runtime", mode="managed",
        source_repository=owner.REPOSITORY,
        source_revision=image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
        monthly_pin_repository_path=owner.PIN_PATH,
        monthly_pin_identity="sha256:" + owner.PIN_SHA256,
        provenance_host_id=origin["provenance_host_id"],
        provenance_project_id="migrated-first-fonts-project",
        project_root=str(image_build_lanes.FIRST_FONTS_MIGRATED_ROOT),
        memory_maximum_bytes=1024**3, thread_count_maximum=4,
        cpu_weight=100, disk_reservation_bytes=1,
        python_executable="/usr/bin/python3",
    )
    raw, issuer, binding = base_evidence(evidence, origin, "image")
    result = owner.prepare(
        lane_record=revised, accepted_base=selected,
        installed_pin_bytes=accepted_pin_bytes(),
        compiler_base_receipt_bytes=raw,
        compiler_base_issuer_policy=issuer,
        compiler_base_binding=binding,
        compiler_base_provenance=compiler_origin(raw, origin["project_root"]),
    )
    assert result["source_revision"] == revised["source_revision"]
    assert result["lane_specification_sha256"] == image_build_lanes.specification_sha256(revised)
    task = result["catalogue"]["tasks"][owner.TASK]
    assert task["source_revision"] == revised["source_revision"]
    assert task["arguments"]["compiler_base"] == evidence["accepted_base_receipt_sha256"]
    assert task["retained_acceptance_sha256"] == result["retained_acceptance_sha256"]
    assert result["accepted_base_kind"] == "image"
    assert result["compiler_authorized"] is False


def test_existing_project_selection_does_not_require_fonts_only_root(monkeypatch):
    """No Project path is selected by the source; caller chooses verified lane."""
    source = Path(os.environ["ZOG_HOSTDEPLOY_FONTS_PR7"])
    sys.path.insert(0, str(source / "tests"))
    from test_gateway_first_graphics_catalogue import (
        example, base_evidence, accepted_pin_bytes)
    with monkeypatch.context() as patch:
        patch.setattr(image_build_lanes, "specification", historical_specification)
        evidence, origin, selected = example("image")
    spec = _CURRENT_SPECIFICATION(
        "reviewed-existing", mode="managed",
        project_root="/var/lib/zog/image-build/projects/reviewed-existing",
        provenance_host_id=origin["provenance_host_id"],
        provenance_project_id="reviewed-existing-project",
        source_repository=owner.REPOSITORY,
        source_revision=image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
        monthly_pin_repository_path=owner.PIN_PATH,
        monthly_pin_identity="sha256:" + owner.PIN_SHA256,
        memory_maximum_bytes=1024**3, thread_count_maximum=4,
        cpu_weight=100, disk_reservation_bytes=1,
        python_executable="/usr/bin/python3",
    )
    raw, issuer, binding = base_evidence(evidence, origin, "image")
    result = owner.prepare(
        lane_record=spec, accepted_base=selected,
        installed_pin_bytes=accepted_pin_bytes(),
        compiler_base_receipt_bytes=raw,
        compiler_base_issuer_policy=issuer,
        compiler_base_binding=binding,
        compiler_base_provenance=compiler_origin(raw, origin["project_root"]))
    assert result["execution_project_root"] == spec["project_root"]
    assert result["execution_project_id"] == spec["provenance_project_id"]
    assert result["compiler_origin_project_root"] == origin["project_root"]
    assert result["compiler_origin_project_id"] == origin["provenance_project_id"]
    assert result["shared_project_compatible"] is False
    assert result["accepted_base_generation_id"] == evidence["accepted_base_generation_id"]
    assert result["accepted_base_receipt_sha256"] == evidence["accepted_base_receipt_sha256"]
    assert result["source_revision"] == image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION


def test_same_existing_project_and_same_named_lane_needs_no_second_project(monkeypatch):
    """Original acceptance binds the project; schema-5 execution uses it."""
    source = Path(os.environ["ZOG_HOSTDEPLOY_FONTS_PR7"])
    sys.path.insert(0, str(source / "tests"))
    from test_gateway_first_graphics_catalogue import (
        example, base_evidence, accepted_pin_bytes)
    with monkeypatch.context() as patch:
        patch.setattr(image_build_lanes, "specification", historical_specification)
        evidence, origin, selected = example("image")
    spec = _CURRENT_SPECIFICATION(
        origin["lane"], mode="managed",
        project_root=origin["project_root"],
        provenance_host_id=origin["provenance_host_id"],
        provenance_project_id=origin["provenance_project_id"],
        source_repository=owner.REPOSITORY,
        source_revision=image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
        monthly_pin_repository_path=owner.PIN_PATH,
        monthly_pin_identity="sha256:" + owner.PIN_SHA256,
        memory_maximum_bytes=1024**3, thread_count_maximum=4,
        cpu_weight=100, disk_reservation_bytes=1,
        python_executable="/usr/bin/python3",
    )
    raw, issuer, binding = base_evidence(evidence, origin, "image")
    result = owner.prepare(
        lane_record=spec, accepted_base=selected,
        installed_pin_bytes=accepted_pin_bytes(),
        compiler_base_receipt_bytes=raw,
        compiler_base_issuer_policy=issuer,
        compiler_base_binding=binding,
        compiler_base_provenance=compiler_origin(raw, origin["project_root"]))
    assert result["execution_project_root"] == origin["project_root"]
    assert result["compiler_origin_project_root"] == origin["project_root"]
    assert result["execution_project_id"] == origin["provenance_project_id"]
    assert result["shared_project_compatible"] is False
    assert result["compiler_authorized"] is False


def test_existing_project_selection_rejects_unapproved_source_and_identity(monkeypatch):
    source = Path(os.environ["ZOG_HOSTDEPLOY_FONTS_PR7"])
    sys.path.insert(0, str(source / "tests"))
    from test_gateway_first_graphics_catalogue import (
        example, base_evidence, accepted_pin_bytes)
    with monkeypatch.context() as patch:
        patch.setattr(image_build_lanes, "specification", historical_specification)
        evidence, origin, selected = example("image")
    raw, issuer, binding = base_evidence(evidence, origin, "image")
    spec = _CURRENT_SPECIFICATION(
        "reviewed-existing", mode="managed",
        project_root="/var/lib/zog/image-build/projects/reviewed-existing",
        provenance_host_id=origin["provenance_host_id"],
        provenance_project_id="reviewed-existing-project",
        source_repository=owner.REPOSITORY,
        source_revision=image_build_lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION,
        monthly_pin_repository_path=owner.PIN_PATH,
        monthly_pin_identity="sha256:" + owner.PIN_SHA256,
        memory_maximum_bytes=1024**3, thread_count_maximum=4,
        cpu_weight=100, disk_reservation_bytes=1,
        python_executable="/usr/bin/python3",
    )
    opts = dict(
        accepted_base=selected, installed_pin_bytes=accepted_pin_bytes(),
        compiler_base_receipt_bytes=raw,
        compiler_base_issuer_policy=issuer,
        compiler_base_binding=binding,
        compiler_base_provenance=compiler_origin(raw, origin["project_root"]))
    for change in (
        {"source_revision": "f" * 40},
        {"provenance_host_id": "foreign-host"},
        {"monthly_pin_identity": "sha256:" + "f" * 64},
    ):
        other = copy.deepcopy(spec)
        other.update(change)
        with pytest.raises((owner.GraphicalCatalogueBlocked, ValueError)):
            owner.prepare(lane_record=other, **opts)
