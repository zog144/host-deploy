"""Negative review gates for held future LLVM/Mesa/Xvnc/i3/xterm proposal.

This test never selects real tasks, makes SSM calls or installs authority.
It tests that proposed metadata cannot be promoted by a GitHub issue, locally
fabricated generation receipts, source movement or rights flag edits.
"""
import copy
import importlib.util
import os
from pathlib import Path

import pytest

from zog.host_deploy.gateway import (
    graphics_generation_chain, graphics_catalogue_owner,
    protocol, task_catalogue,
)

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools/verify_held_graphical_extension.py"
spec = importlib.util.spec_from_file_location("held_graphics_verify", PATH)
held = importlib.util.module_from_spec(spec)
spec.loader.exec_module(held)


def proposal():
    return held.load_proposal()


def test_held_candidate_is_valid_only_as_non_authority():
    p = proposal()
    assert held.validate(p) == held.STATUS
    assert [s["id"] for s in p["stage_order"]] == list(held.STAGES)
    assert all(v is None for v in p["required_predecessor_receipts"].values())
    assert p["authority"]["protected_send_once_highwater"] is None
    assert p["authority"]["independently_signed_current_checkpoint"] is None
    assert graphics_catalogue_owner.SOURCE != p["producer"]["workspace_pr9_candidate_revision"]
    assert set(graphics_generation_chain.TASKS).isdisjoint(held.STAGES)
    with pytest.raises(held.HeldProposalRejected, match="HELD_NOT_SUBMITTABLE"):
        held.refuse_submission(p)
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate(p)


@pytest.mark.parametrize("case", (
    "accept-X11", "accept-Mesa", "fabricate-receipt", "operator-approval",
    "issuer-epoch", "checkpoint", "replay-history", "live-worker",
    "enable-submit", "enable-catalogue", "enable-install", "enable-promotion",
    "rights-approved", "installed-license", "source-repin", "wrong-mesa-source",
    "wrong-PR9-input", "wrong-monthly-pin", "reordered-producer",
    "cyclic-source", "future-stage-recipe", "smoke-authorized",
    "fake-smoke-result", "fps-threshold",
))
def test_no_source_metadata_can_be_promoted_to_authority(case):
    p = proposal()
    if case == "accept-X11":
        p["required_predecessor_receipts"]["X11"] = "a"*64
    elif case == "accept-Mesa":
        p["stage_order"][1]["accepted_generation_receipt"] = "b"*64
    elif case == "fabricate-receipt":
        p["required_predecessor_receipts"]["accepted_toolchain"] = {"signed": True}
    elif case == "operator-approval":
        p["authority"]["protected_operator_approval"] = {"issuer": "synthetic"}
    elif case == "issuer-epoch":
        p["authority"]["installed_authority_epoch"] = 3
    elif case == "checkpoint":
        p["authority"]["independently_signed_current_checkpoint"] = "signed-looking"
    elif case == "replay-history":
        p["authority"]["protected_send_once_highwater"] = {"sequence": 2}
    elif case == "live-worker":
        p["execution"]["workers_authorized"] = True
    elif case == "enable-submit":
        p["authority"]["build_submission_allowed"] = True
    elif case == "enable-catalogue":
        p["authority"]["task_allowlist_extension_allowed"] = True
    elif case == "enable-install":
        p["authority"]["installer_selection_allowed"] = True
    elif case == "enable-promotion":
        p["authority"]["canonical_promotion_allowed"] = True
    elif case == "rights-approved":
        p["rights"]["rights_holder_authorized"] = True
    elif case == "installed-license":
        p["rights"]["native_installed_notice_sha256_accepted"] = True
    elif case == "source-repin":
        p["producer"]["current_protected_selected_revision"] = held.PR9
    elif case == "wrong-mesa-source":
        p["producer"]["mesa_pr8_candidate_revision"] = "0"*40
    elif case == "wrong-PR9-input":
        p["producer"]["workspace_pr9_reviewed_input_revision"] = held.PR9
    elif case == "wrong-monthly-pin":
        p["producer"]["current_protected_monthly_pin"] = "sha256:"+"0"*64
    elif case == "reordered-producer":
        p["stage_order"][0],p["stage_order"][1] = (
            p["stage_order"][1],p["stage_order"][0])
    elif case == "cyclic-source":
        p["stage_order"][0]["depends_on"] = ["Mesa"]
    elif case == "future-stage-recipe":
        p["stage_order"][0]["recipe_status"] = "NATIVE_ACCEPTED"
    elif case == "smoke-authorized":
        p["smoke"]["run_authorized"] = True
    elif case == "fake-smoke-result":
        p["smoke"]["result_receipt"] = {"glxgears": "PASS"}
    elif case == "fps-threshold":
        p["smoke"]["fps_threshold"] = 60
    else:
        raise AssertionError(case)
    with pytest.raises(held.HeldProposalRejected):
        held.validate(p)


@pytest.mark.parametrize("name", held.STAGES)
def test_proposed_stage_cannot_be_submitted_through_actual_github_protocol(name):
    assert name not in protocol.BUILD_TASKS
    assert name not in task_catalogue.REVIEWED_IMAGE_TASKS
    with pytest.raises(protocol.RequestProtocolError, match="unknown build task"):
        protocol.validate_request({
            "schema": 1,
            "request_id": "a"*32,
            "workspace_id": "b"*32,
            "operation": "build.submit",
            "origin": {
                "repository": "zog144/host-deploy",
                "issue_number": 17,
                "trigger_actor": "operator",
            },
            "source": {
                "repository": "zog144/image-build",
                "commit": held.PR9,
            },
            "parameters": {"lane": "graphical-test-lane", "task": name},
        })


def test_changing_actual_gateway_allowlist_invalidates_held_verifier(monkeypatch):
    monkeypatch.setattr(
        protocol, "BUILD_TASKS",
        frozenset((*protocol.BUILD_TASKS, "graphics-mesa-held-v1")),
    )
    with pytest.raises(held.HeldProposalRejected, match="active graphical authority changed"):
        held.validate(proposal())


def test_exact_pr9_and_mesa_git_revisions_and_source_holds_are_independently_checked():
    pr9 = os.environ["ZOG_HELD_PR9_SOURCE"]
    mesa = os.environ["ZOG_HELD_MESA_SOURCE"]
    assert held.attest_source_checkouts(proposal(), pr9, mesa) == held.STATUS


def test_checkout_revision_substitution_never_becomes_a_generation():
    pr9 = os.environ["ZOG_HELD_PR9_SOURCE"]
    # Same checkout cannot satisfy the distinct image-build Mesa PR #8 ref.
    with pytest.raises(held.HeldProposalRejected, match="moving or stale"):
        held.attest_source_checkouts(proposal(), pr9, pr9)
