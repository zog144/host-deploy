"""Project-current normalized receipt, old CommandId readback, no replay."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from test_gateway_project_current import project, selected, intent, target, git
from test_gateway_simple_forward import approved, admit
from zog.host_deploy.gateway import (
    project_current, image_build_execution as execution, simple_forward,
)
from zog.host_deploy.gateway.ledger import (
    prepare_dispatch, load_dispatch, load_request,
    mark_dispatch_submitting, mark_dispatch_submitted,
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def receipt_fixture(tmp_path, *, request_id="a" * 32):
    root, source, controller = project(tmp_path)
    (source / "project/package/pins.txt").write_text("sha256:" + "a" * 64)
    git(source, "add", ".")
    git(source, "commit", "-qm", "sha256 recipe snapshot for parser")
    spec, record = selected(root, controller, historic=False)
    binding = project_current.binding(intent(request_id), record, spec, target())
    command = project_current.remote_script(binding)
    assert len(command.encode("utf-8")) <= 32768
    result = subprocess.run(command, shell=True, capture_output=True,
                            text=True, timeout=25)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout.strip().splitlines()[-1])
    return root, binding, receipt, result.stdout


def _rehash(receipt):
    receipt = copy.deepcopy(receipt)
    raw = _canonical(receipt["result"])
    receipt["result_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt["result_bytes"] = len(raw)
    return receipt


def _legacy(receipt):
    old = copy.deepcopy(receipt)
    old.pop("result_representation")
    old["result"] = {key: receipt["result"][key] for key in (
        "status", "pipeline_id", "source_revision", "recipe_identity",
        "selected_generation", "terminal_outcome", "failure",
        "allowed_next_operations", "uncertainty", "attempt_ids",
        "reconciliation_required",
    )}
    # The REAL old wrapper hashed produced, not the reduced summary; those
    # producer bytes were never transmitted. Their digest is not computable
    # from the old receipt. Do not fake a matching digest.
    old["result_sha256"] = "f" * 64
    old["result_bytes"] = 8192
    return old


def test_current_normalized_receipt_verifies_exact_wire_result_and_source(tmp_path):
    root, binding, receipt, output = receipt_fixture(tmp_path)
    assert receipt["result_representation"] == "normalized-summary-v1"
    assert receipt["result"]["source_repository"] == "zog144/image-build"
    assert receipt["result"]["source_revision"] == git(root / "source",
                                                        "rev-parse", "HEAD")
    assert receipt["result"]["schema"] == "image-build-remote-result-v1"
    assert receipt["result"]["operation_id"] == binding["request_id"]
    assert receipt["result"]["operation_type"] == "pipeline.submit"
    assert receipt["result"]["missing_evidence_count"] == 0
    assert receipt["result"]["allowed_next_operations"] == []
    assert receipt["result"]["attempt_ids"] == []
    assert receipt["result"]["controller_jobs"] == []
    assert receipt["result"]["uncertainty"] is False
    assert receipt["result"]["failure"] is None
    raw = _canonical(receipt["result"])
    assert receipt["result_bytes"] == len(raw)
    assert receipt["result_sha256"] == hashlib.sha256(raw).hexdigest()
    source = receipt["result"]["source_evidence"]
    requested = copy.deepcopy(binding["remote_request"])
    requested["source"]["revision"] = receipt["result"]["source_revision"]
    assert source == {
        "schema": "host-deploy-project-current-source-v1",
        "repository": "zog144/image-build",
        "revision": receipt["result"]["source_revision"],
        "request_sha256": hashlib.sha256(_canonical(requested) + b"\n").hexdigest(),
    }
    assert execution.parse_receipt(output, binding) == receipt
    assert execution.completion_for_receipt(receipt) == "running"


@pytest.mark.parametrize("alter", [
    "hash", "byte-count", "repo", "wrong-revision", "source-request",
    "source-schema", "operation", "request-id", "frozen-template", "missing-evidence",
    "missing-identity", "uncertainty-type",
])
def test_normalized_receipt_rejects_rehashed_tampering_and_wrong_binding(
        tmp_path, alter):
    root, binding, receipt, _ = receipt_fixture(tmp_path)
    modified = copy.deepcopy(receipt)
    if alter == "hash":
        modified["result_sha256"] = "0" * 64
    elif alter == "byte-count":
        modified["result_bytes"] += 1
    elif alter == "repo":
        modified["result"]["source_repository"] = "unreviewed/repo"
        modified = _rehash(modified)
    elif alter == "wrong-revision":
        modified["result"]["source_revision"] = "f" * 40
        modified = _rehash(modified)
    elif alter == "source-request":
        modified["result"]["source_evidence"]["request_sha256"] = "f" * 64
        modified = _rehash(modified)
    elif alter == "source-schema":
        modified["result"]["source_evidence"]["schema"] = "not-reviewed"
        modified = _rehash(modified)
    elif alter == "operation":
        modified["result"]["operation_id"] = "b" * 32
        modified = _rehash(modified)
    elif alter == "request-id":
        modified["request_id"] = "b" * 32
    elif alter == "frozen-template":
        modified["remote_request_sha256"] = "0" * 64
    elif alter == "missing-evidence":
        del modified["result"]["missing_evidence_count"]
        modified = _rehash(modified)
    elif alter == "missing-identity":
        del modified["result"]["source_repository"]
        modified = _rehash(modified)
    else:
        modified["result"]["uncertainty"] = "false"
        modified = _rehash(modified)
    with pytest.raises(RuntimeError):
        execution.parse_receipt(json.dumps(modified), binding)


def test_pinned_source_contract_is_unchanged_for_historical_binding(monkeypatch, tmp_path):
    root, selected_binding, receipt, output = receipt_fixture(tmp_path)
    from zog.host_deploy.gateway import image_build_execution as legacy
    pinned = dict(selected_binding, schema=3, source={
        "repository": "zog144/image-build",
        "revision": receipt["result"]["source_revision"],
    })
    # Synthetic shape isolates the existing legacy pinned-source branch,
    # whose complete immutable binding format is separately source-tested.
    monkeypatch.setattr(legacy, "_binding", lambda value: value["binding"])
    old = copy.deepcopy(receipt)
    old.pop("result_representation")
    assert legacy.parse_receipt(json.dumps(old), pinned) == old
    pinned["source"] = {**pinned["source"], "revision": "f" * 40}
    with pytest.raises(RuntimeError, match="result summary differs"):
        legacy.parse_receipt(json.dumps(old), pinned)


def test_already_sent_legacy_receipt_is_observed_without_false_digest_or_replay(
        tmp_path, monkeypatch):
    request = approved()
    compiler, binding, receipt, output = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    old = _legacy(receipt)
    assert execution.parse_receipt(json.dumps(old), binding) == old
    gateway = tmp_path / "gateway"
    admit(gateway, request)
    prepare_dispatch(gateway, request["request_id"], binding)
    mark_dispatch_submitting(gateway, request["request_id"])
    mark_dispatch_submitted(gateway, request["request_id"],
                            "retained-original-command-63")
    frozen = load_dispatch(gateway, request["request_id"])
    calls = []
    monkeypatch.setattr(execution, "verify_current_target",
                        lambda *_: target())

    class Host:
        def __init__(self, configuration):
            assert configuration == target()
        def inspect_command(self, command_id):
            calls.append(command_id)
            return {
                "CommandId": "retained-original-command-63",
                "InstanceId": target()["instance_id"],
                "Status": "Success",
                "StandardOutputContent": json.dumps(old),
            }
        def submit_command(self, *args, **kwargs):
            pytest.fail("legacy receipt observation attempted command replay")

    state, observation, retained = execution.observe_submitted(
        gateway, request["request_id"], host_factory=Host)
    assert state["states"]["completion"] == "recovery_blocked"
    assert observation["observation"]["raw_result_digest_verified"] is False
    assert observation["observation"]["declared_result_sha256"] == "f" * 64
    assert observation["observation"]["source_revision"] == (
        receipt["result"]["source_revision"])
    assert observation["observation"]["selected_project_observation_required"]
    assert retained is None
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert calls == ["retained-original-command-63"]


@pytest.mark.parametrize("mutation", ["wrong-command", "wrong-instance",
                                      "wrong-request", "wrong-repository",
                                      "bad-revision", "oversized-count"])
def test_legacy_readback_never_trusts_foreign_identity_or_creates_terminal(
        tmp_path, monkeypatch, mutation):
    request = approved()
    _, binding, receipt, output = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    old = _legacy(receipt)
    if mutation == "wrong-request":
        old["request_id"] = "e" * 32
    elif mutation == "wrong-repository":
        altered = dict(binding, remote_request={
            **binding["remote_request"],
            "source": {"repository": "foreign/source"},
        })
        monkeypatch.setattr(execution, "_binding",
                            lambda _: altered)
    elif mutation == "bad-revision":
        old["result"]["source_revision"] = "non-git"
    elif mutation == "oversized-count":
        old["result_bytes"] = 999999
    gateway = tmp_path / "gateway"
    admit(gateway, request)
    prepare_dispatch(gateway, request["request_id"], binding)
    mark_dispatch_submitting(gateway, request["request_id"])
    mark_dispatch_submitted(gateway, request["request_id"], "original-command")
    frozen = load_dispatch(gateway, request["request_id"])
    monkeypatch.setattr(execution, "verify_current_target",
                        lambda *_: target())
    class Host:
        def __init__(self, cfg):
            pass
        def inspect_command(self, command_id):
            return {
                "CommandId": ("foreign-command" if mutation == "wrong-command"
                              else "original-command"),
                "InstanceId": ("i-fffffffffffffffff" if
                               mutation == "wrong-instance" else target()["instance_id"]),
                "Status": "Success",
                "StandardOutputContent": json.dumps(old),
            }
        def submit_command(self, *args, **kwargs):
            pytest.fail("replay")
    with pytest.raises(RuntimeError):
        execution.observe_submitted(
            gateway, request["request_id"], host_factory=Host)
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()
