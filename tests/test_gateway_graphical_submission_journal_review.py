"""Second-pass source review: no forged generic stage crosses SSM boundary.

Tests invoke the *existing* generic_pipeline.advance state machine with a
synthetic Host. The test "SSM" client is an in-memory spy, not AWS.
"""
import copy
import hashlib
import json

import pytest

from zog.host_deploy.gateway import generic_pipeline as generic
from zog.host_deploy.gateway import graphics_generation_chain as chain
from zog.host_deploy.gateway import task_catalogue
from test_gateway_generic_pipeline import (
    GATEWAY, SNAPSHOT, PIPELINE, base, mock_environment,
)
from test_gateway_graphics_generation_chain import (
    scenario, evidence, FONTS,
)


def _at_stage(tmp_path, monkeypatch, name):
    Host, calls = mock_environment(monkeypatch)
    for _ in range(16):
        state = generic.advance(tmp_path, GATEWAY, host_factory=Host)
        if state["stages"][-1]["name"] == name and state["stages"][-1]["phase"] == "prepared":
            return Host, calls, tmp_path / "requests" / GATEWAY / generic.FILE, state
    pytest.fail("source fixture never reached staged " + name)


@pytest.mark.parametrize("mutation", (
    "seed-selection", "recipe-targets", "unknown-operation",
    "wrong-remote-source", "wrong-predecessor", "injected-plan",
))
def test_tampered_prepared_submit_with_recomputed_digest_never_reaches_ssm(
        tmp_path, monkeypatch, mutation):
    Host, calls, path, state = _at_stage(tmp_path, monkeypatch, "submit")
    step = state["stages"][-1]
    arguments = step["request"]["arguments"]
    if mutation == "seed-selection":
        arguments["selection"] = "f" * 64
    elif mutation == "recipe-targets":
        arguments["targets"] = ["arbitrary-final"]
    elif mutation == "unknown-operation":
        step["request"]["operation"] = "pipeline.retry"
    elif mutation == "wrong-remote-source":
        step["request"]["source"]["revision"] = "a" * 40
    elif mutation == "wrong-predecessor":
        step["request"]["predecessor"] = "f" * 32
    else:
        arguments["prepared_plan"] = {
            "schema": "zog-first-workspace-source-to-native-handoff-v1",
            "status": "PREPARED_NOT_SUBMITTABLE",
        }
    step["request_sha256"] = hashlib.sha256(
        generic._canonical(step["request"])).hexdigest()
    path.write_text(json.dumps(state))
    count = len(calls)
    with pytest.raises(RuntimeError, match="identity|binding|mismatch"):
        generic.advance(tmp_path, GATEWAY, host_factory=Host)
    assert len(calls) == count
    assert state["stages"][-1]["operation_id"] == generic._operation_id(
        GATEWAY, "submit")


@pytest.mark.parametrize("mutation", (
    "stale-recipe-identity", "stale-pipeline-identity",
    "skipped-capabilities", "duplicate-submit-ordinal",
))
def test_consistent_local_record_does_not_reselect_build_inputs(
        tmp_path, monkeypatch, mutation):
    stage = "inspect" if mutation == "stale-pipeline-identity" else "submit"
    Host, calls, path, state = _at_stage(tmp_path, monkeypatch, stage)
    step = state["stages"][-1]
    if mutation == "stale-recipe-identity":
        state["recipe_identity"] = "sha256:" + "0" * 64
        step["request"]["arguments"]["recipe_snapshot"] = state["recipe_identity"]
    elif mutation == "stale-pipeline-identity":
        state["pipeline_id"] = "0" * 32
        step["request"]["arguments"]["pipeline_id"] = state["pipeline_id"]
    elif mutation == "skipped-capabilities":
        state["stages"].pop(0)
    else:
        step["ordinal"] = 1
        step["operation_id"] = generic._operation_id(GATEWAY, "submit", 1)
        step["request"]["operation_id"] = step["operation_id"]
    step["request_sha256"] = hashlib.sha256(
        generic._canonical(step["request"])).hexdigest()
    path.write_text(json.dumps(state))
    count = len(calls)
    with pytest.raises(RuntimeError, match="identity|mismatch|order|stage|binding"):
        generic.advance(tmp_path, GATEWAY, host_factory=Host)
    assert len(calls) == count


@pytest.mark.parametrize("change", (
    "stale-revision", "newer-pr9-revision", "wrong-entries",
    "wrong-predecessor", "future-mesa-task",
))
def test_graphical_task_catalogue_cannot_reselect_compiler_source(change):
    policy, fonts, receipt = scenario()
    step = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[0],
        previous_catalogue=fonts, previous_receipt=receipt,
        accepted_generation=evidence(policy, chain.TASKS[0], fonts, FONTS))
    validated = copy.deepcopy(step["catalogue"])
    spec = validated["tasks"][chain.TASKS[1]]
    if change == "stale-revision":
        spec["source_revision"] = "0" * 40
    elif change == "newer-pr9-revision":
        spec["source_revision"] = "6b64a7e1b6f9842554bd3b9eee5599e24ca2402c"
    elif change == "wrong-entries":
        spec["entries"][0]["project"] = "mesa"
        spec["entries"][0]["recipe"] = "mesa/stages/final"
    elif change == "wrong-predecessor":
        spec["arguments"]["graphical_predecessor"] = (
            policy["first_base_generation_id"])
    else:
        validated["tasks"]["graphics-mesa-llvmpipe-image-v1"] = (
            validated["tasks"].pop(chain.TASKS[1]))
    if change == "wrong-entries" or change == "wrong-predecessor" or change == "future-mesa-task":
        with pytest.raises(task_catalogue.TaskCatalogueError):
            task_catalogue.validate(validated)
    else:
        # A source revision may be syntactically well-formed, but selection
        # must always compare it against the managed lane's exact pinned SHA.
        with pytest.raises(task_catalogue.TaskCatalogueError, match="source/lane/pin"):
            task_catalogue.select(
                validated, chain.TASKS[1],
                repository="zog144/image-build",
                revision=policy["source_revision"],
                lane=policy["lane"],
                monthly_pin_repository_path=spec["monthly_pin_repository_path"],
                monthly_pin_identity=policy["monthly_pin_identity"])


def test_signed_looking_json_is_not_an_installed_predecessor_receipt():
    """Schema-valid checksum in a data file is not protected stage authority."""
    policy, original, receipt = scenario()
    plausible = {
        "schema": chain.EVIDENCE,
        "output_generation_id": "a"*64,
        "signed": True,
        "accepted": True,
    }
    with pytest.raises(chain.ChainBlocked):
        chain.resolve_successor(
            policy=policy, previous_task=chain.TASKS[0],
            previous_catalogue=original, previous_receipt=receipt,
            accepted_generation=plausible)



def test_foreign_issuer_signed_x11_receipt_still_cannot_prepare(
        tmp_path, monkeypatch):
    """Valid Ed25519 from a foreign Host is not the protected current signer."""
    from zog.host_deploy.gateway import graphics_chain_export as export
    from test_gateway_workspace_submission_boundary import _non_authorizing_gateway
    from test_gateway_graphics_chain_export import setup as foreign_signer
    policy, fonts, first_receipt = scenario()
    xcb = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[0],
        previous_catalogue=fonts, previous_receipt=first_receipt,
        accepted_generation=evidence(policy, chain.TASKS[0], fonts, FONTS),
    )
    second_evidence = evidence(
        policy, chain.TASKS[1], xcb["catalogue"], "c" * 64,
        request_id="6" * 32,
    )
    x11 = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[1],
        previous_catalogue=xcb["catalogue"], previous_receipt=xcb["receipt"],
        accepted_generation=second_evidence,
    )
    _foreign_pin, source, foreign_sign, _, _ = foreign_signer()
    payload = {
        **source,
        "task": chain.TASKS[2],
        "catalogue": x11["catalogue"],
        "catalogue_sha256": x11["catalogue_sha256"],
        "receipt": x11["receipt"],
        "receipt_sha256": chain._hash(x11["receipt"]),
    }
    valid_foreign_ed25519 = foreign_sign(payload)
    # _non_authorizing_gateway independently installs a *different* synthetic
    # Host public pin. Its checkpoint stub only exercises the later actual
    # export-verification boundary; it cannot authenticate a foreign issuer.
    obj, prepared, advanced = _non_authorizing_gateway(
        tmp_path, monkeypatch, fake_export=valid_foreign_ed25519)
    with pytest.raises(export.GraphicalExportBlocked, match="wrong compiler Host signature"):
        obj._advance_one_reviewed()
    assert not prepared and not advanced
