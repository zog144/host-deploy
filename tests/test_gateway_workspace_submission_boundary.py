"""Read-only cross-owner Workspace-to-compiler submission boundary regressions.

The source handoff is NOT a compiler request and has no accepted generation.
These tests deliberately exercise the real host-deploy catalogue, issue
protocol, signed export receiver and existing GatewayConsumer. All owner,
checkpoint and SSM interactions are synthetic or explicitly fail-closed.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

from zog.host_deploy.gateway import (
    consumer, graphics_chain_export as export,
    graphics_external_checkpoint as checkpoint,
    graphics_generation_chain as chain,
    task_catalogue, protocol,
)
from test_gateway_graphics_chain_gateway import runner
from test_gateway_graphics_chain_export import setup as export_fixture

PR9_SOURCE = "54431ea8f5ed69fd120d5e862a2277c5d2a2c46d"
MESA_REVIEWED = "9cbd652226b863a7b4bb2d6d9539722e1a262508"
OLD_MESA = "0" * 40
X11 = chain.TASKS[2]
MESA_TASK = "graphics-mesa-llvmpipe-image-v1"


@pytest.fixture(scope="module")
def producer_source():
    source = os.environ.get("ZOG_WORKSPACE_HANDOFF_SOURCE")
    if source is None:
        pytest.skip("exact-revision cross-owner image-build checkout not installed")
    root = Path(source).resolve(strict=True)
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        text=True,
    ).strip()
    assert revision == PR9_SOURCE, "image-build PR9 source ref changed"
    script = root / "tools/verify_workspace_native_handoff.py"
    specification = importlib.util.spec_from_file_location(
        "zog_pr9_native_handoff_test", script)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    record = json.loads(
        (root/"project/graphics-first-workspace/source-to-native-handoff.json")
        .read_text())
    assert module.verify(record)
    return module, record


def test_source_to_native_handoff_is_never_an_admitted_task(producer_source):
    checker, handoff = producer_source
    assert handoff["schema"] == "zog-first-workspace-source-to-native-handoff-v1"
    assert handoff["status"] == "PREPARED_NOT_SUBMITTABLE"
    assert handoff["native_accepted"] is False
    assert handoff["build_submission_allowed"] is False
    assert handoff["canonical_promotion_allowed"] is False
    assert handoff["rights_authorized"] is False
    with pytest.raises(ValueError, match="native-readiness DENIED"):
        checker.refuse_native_readiness(handoff)
    # A source plan is never the root-owned task catalogue selected by the
    # real binding_for_request / task_catalogue.select path.
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate(handoff)
    assert all(v is None for v in handoff["accepted_generation_receipts"].values())


@pytest.mark.parametrize("tamper", (
    "unaccepted-X11", "fabricated-predecessor", "fake-complete-flag",
    "forged-authority", "unsigned-catalogue",
))
def test_fabricated_source_evidence_not_submission_authority(producer_source, tamper):
    checker, held = producer_source
    attempted = copy.deepcopy(held)
    if tamper == "unaccepted-X11":
        attempted["accepted_generation_receipts"]["X11"] = "f" * 64
    elif tamper == "fabricated-predecessor":
        attempted["accepted_generation_receipts"]["XCB"] = {
            "generation_id": "b" * 64, "accepted": True,
            "acceptance_receipt_sha256": "sha256:" + "c" * 64,
        }
    elif tamper == "fake-complete-flag":
        attempted["build_submission_allowed"] = True
    elif tamper == "forged-authority":
        attempted["rights_authorized"] = True
    else:
        attempted["catalogue_sha256"] = "sha256:" + "d" * 64
    with pytest.raises(ValueError):
        checker.verify(attempted)
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate(attempted)


@pytest.mark.parametrize("revision", (OLD_MESA, "f" * 40, "unknown", None))
def test_outdated_mesa_source_cannot_be_refrozen_by_a_request(
        producer_source, revision):
    checker, source = producer_source
    assert source["source_revisions"]["mesa_pr8"] == MESA_REVIEWED
    forged = copy.deepcopy(source)
    forged["source_revisions"]["mesa_pr8"] = revision
    with pytest.raises(ValueError, match="source revision changed"):
        checker.verify(forged)
    # No caller can take the held Mesa revision straight to the existing
    # GitHub issue -> typed generic selection (only Fonts/XCB/X11 allowed).
    with pytest.raises(protocol.RequestProtocolError, match="unknown build task"):
        protocol.validate_request({
            "schema": 1, "request_id": "a"*32, "workspace_id": "b"*32,
            "operation": "build.submit",
            "origin": {
                "repository": "zog144/host-deploy",
                "issue_number": 42, "trigger_actor": "operator",
            },
            "source": {
                "repository": "zog144/image-build",
                "commit": MESA_REVIEWED if revision is None else
                          revision if isinstance(revision, str) and len(revision)==40
                          else MESA_REVIEWED,
            },
            "parameters": {"lane": "graphical-test-lane", "task": MESA_TASK},
        })


def _non_authorizing_gateway(tmp_path, monkeypatch, *, fake_export=None):
    """Real receiver and real consumer; synthetic checkpoint reaches cache read."""
    actual = export.load_selected_step
    obj, _, prepared, advanced = runner(
        tmp_path, monkeypatch, task=X11,
    )
    pin, payload, signed, _, _ = export_fixture()
    monkeypatch.setattr(export, "load_selected_step", actual)
    monkeypatch.setattr(export, "_read_public_pin", lambda path: pin)
    # Test-only: bypass independent service availability just far enough to
    # exercise genuine export cache verification. This never installs a pin.
    monkeypatch.setattr(checkpoint, "require_current", lambda _: True)
    obj.approved_graphical_export_pin_path = export.CURRENT_AUTHORITY_PATH
    obj.approved_graphical_chain_policy_sha256 = pin["chain_policy_sha256"]
    directory = Path(obj.graphical_export_directory)
    directory.mkdir()
    if fake_export is not None:
        (directory/(X11+".json")).write_bytes(fake_export)
    return obj, prepared, advanced


def test_missing_accepted_x11_export_denied_before_prepare_or_ssm(
        tmp_path, monkeypatch):
    obj, prepared, advanced = _non_authorizing_gateway(tmp_path, monkeypatch)
    with pytest.raises(export.GraphicalExportBlocked, match="authenticated Host export missing"):
        obj._advance_one_reviewed()
    assert prepared == [] and advanced == []


def test_fabricated_x11_predecessor_receipt_cannot_authorize_submission(
        tmp_path, monkeypatch):
    pin, base, signed, fonts, _ = export_fixture()
    forged = copy.deepcopy(base)
    forged["task"] = X11
    forged["receipt"] = {
        "schema": chain.RECEIPT, "task": X11,
        "predecessor_evidence_sha256": "sha256:" + "f"*64,
        "graphical_predecessor_generation_id": "c"*64,
        "status": "installed-not-compiler-admission",
        "compiler_authorized": False,
    }
    forged["receipt_sha256"] = chain._hash(forged["receipt"])
    # The cache is caller writable in this synthetic scenario. It MUST not
    # turn a self-consistent JSON receipt into a *signed* protected export.
    fake = export._canonical({"payload": forged, "signature": "AA=="})
    obj, prepared, advanced = _non_authorizing_gateway(
        tmp_path, monkeypatch, fake_export=fake)
    with pytest.raises(export.GraphicalExportBlocked):
        obj._advance_one_reviewed()
    assert prepared == [] and advanced == []


def test_prepared_not_submittable_plan_is_not_generic_or_toolchain_binding(
        producer_source):
    checker, plan = producer_source
    # The existing gateway cannot accept a source handoff via either mode:
    # it can only select exact protected task definitions, never plan flags.
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate({
            "schema": task_catalogue.SCHEMA,
            "tasks": {MESA_TASK: copy.deepcopy(plan)},
        })
    assert MESA_TASK not in protocol.BUILD_TASKS
    assert MESA_TASK not in protocol.TOOLCHAIN_TASKS
    assert X11 in chain.TASKS
    assert "Mesa" not in chain.TASKS


def test_existing_native_x11_submission_requires_distinct_future_acceptance(
        producer_source):
    _, plan = producer_source
    assert plan["accepted_generation_receipts"]["X11"] is None
    assert plan["accepted_generation_receipts"]["LLVM"] is None
    assert plan["accepted_generation_receipts"]["Mesa"] is None
    assert plan["accepted_generation_receipts"]["zlib_native_environment"] is None
    assert plan["accepted_generation_receipts"]["ncurses_temporary"] is None
    assert ["X11", "Mesa"] in plan["producer_edges"]
    assert ["LLVM", "Mesa"] in plan["producer_edges"]
    assert plan["rights_gate"].startswith("HOLD:")



def test_selected_graphical_task_source_revision_is_bound_to_native_catalogue():
    # A 40-hex SHA is syntactically plausible, but not the protected lane pin.
    from test_gateway_graphics_generation_chain import scenario, evidence, FONTS
    policy, first_catalogue, first_receipt = scenario()
    successor = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[0],
        previous_catalogue=first_catalogue, previous_receipt=first_receipt,
        accepted_generation=evidence(policy, chain.TASKS[0], first_catalogue, FONTS))
    selected = successor["catalogue"]
    assert task_catalogue.select(selected, chain.TASKS[1],
        repository=chain.first.REPOSITORY, revision=chain.first.SOURCE,
        lane=policy["lane"], monthly_pin_identity=policy["monthly_pin_identity"])
    for invalid in (PR9_SOURCE, "f"*40):
        with pytest.raises(task_catalogue.TaskCatalogueError,
                           match="source/lane/pin differs"):
            task_catalogue.select(selected, chain.TASKS[1],
                repository=chain.first.REPOSITORY, revision=invalid,
                lane=policy["lane"],
                monthly_pin_identity=policy["monthly_pin_identity"])


def test_catalogue_relabel_or_fabricated_mesa_task_is_not_a_selected_job():
    from test_gateway_graphics_generation_chain import scenario, evidence, FONTS
    policy, first_catalogue, first_receipt = scenario()
    successor = chain.resolve_successor(
        policy=policy, previous_task=chain.TASKS[0],
        previous_catalogue=first_catalogue, previous_receipt=first_receipt,
        accepted_generation=evidence(policy, chain.TASKS[0], first_catalogue, FONTS))
    catalogue = copy.deepcopy(successor["catalogue"])
    spec = catalogue["tasks"].pop(chain.TASKS[1])
    catalogue["tasks"][chain.TASKS[2]] = spec
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate(catalogue)
    catalogue["tasks"] = {MESA_TASK: spec}
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate(catalogue)


def test_signed_looking_local_export_cannot_overwrite_selected_source(
        tmp_path, monkeypatch):
    pin, payload, signed, _, _ = export_fixture()
    copied = copy.deepcopy(payload)
    catalogue = copied["catalogue"]
    selected = catalogue["tasks"][copied["task"]]
    selected["source_revision"] = PR9_SOURCE
    copied["catalogue_sha256"] = chain._hash(catalogue)
    copied["source_revision"] = PR9_SOURCE
    # Reusing a valid signature from a different source is not authority.
    forged = export._canonical({"payload": copied,
                                "signature": json.loads(signed)["signature"]})
    obj, prepared, advanced = _non_authorizing_gateway(
        tmp_path, monkeypatch, fake_export=forged)
    with pytest.raises(export.GraphicalExportBlocked):
        obj._advance_one_reviewed()
    assert not prepared and not advanced


def test_prepared_dispatch_with_stale_source_catalogue_digest_never_advances(
        tmp_path, monkeypatch):
    from test_gateway_graphics_chain_gateway import APPROVAL_DIGEST
    obj, prepared, advanced = _non_authorizing_gateway(tmp_path, monkeypatch)
    # Test the current gateway's actual immutable dispatch consistency
    # boundary without allowing a synthetic generic advance.
    state = {"phase":"prepared","binding":{
        "task_catalogue_identity":"sha256:"+"a"*64}}
    monkeypatch.setattr(consumer,"load_dispatch",lambda *_:state)
    # The missing authenticated export must be rejected first, even with
    # a preexisting dispatch that claims to be already frozen.
    with pytest.raises(export.GraphicalExportBlocked):
        obj._advance_one_reviewed()
    assert not prepared and not advanced
