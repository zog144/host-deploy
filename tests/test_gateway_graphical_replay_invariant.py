"""Offline regression gates for original-operation and snapshot-history replay.

Tests exercise a synthetic SSM adapter, never a real AWS or compiler host.
"""

import hashlib
import json

import pytest

from zog.host_deploy.gateway import generic_pipeline as generic
from test_gateway_generic_pipeline import GATEWAY, mock_environment
from test_gateway_graphical_submission_journal_review import _at_stage


def test_rollback_of_submitted_pipeline_prepared_state_must_not_send_again(
        tmp_path, monkeypatch):
    """The *same original* frozen valid request can be replayed unmodified.

    There is no altered hash, task, generation or source revision here. A
    separate trustworthy monotonic operation record must prevent the second
    SSM command after the earlier journal snapshot is restored.
    """
    Host, calls, path, prepared = _at_stage(tmp_path, monkeypatch, "submit")
    originally_prepared_bytes = path.read_bytes()
    operation_id = prepared["stages"][-1]["operation_id"]
    initial_count = sum(k == "submit" and v == "pipeline.submit" for k,v in calls)
    sent = generic.advance(tmp_path, GATEWAY, host_factory=Host)
    assert sent["stages"][-1]["phase"] == "submitted"
    assert sent["stages"][-1]["operation_id"] == operation_id
    assert sum(k == "submit" and v == "pipeline.submit" for k,v in calls) == initial_count + 1
    # Synthetic local journal restoration: same valid request, exact original
    # SHA, correct order and operation ID; no SSM or remote access in tests.
    path.write_bytes(originally_prepared_bytes)
    from zog.host_deploy.gateway import graphics_operation_send_intent
    with pytest.raises(graphics_operation_send_intent.SendIntentBlocked):
        generic.advance(tmp_path, GATEWAY, host_factory=Host)
    assert sum(k == "submit" and v == "pipeline.submit" for k,v in calls) == initial_count + 1, (
        "second SSM submission for same operation after journal replay")


def test_coherently_rewritten_snapshot_history_must_not_submit(
        tmp_path, monkeypatch):
    """A forged snapshot+result+hash can satisfy current PR15 _read checks."""
    Host, calls, path, state = _at_stage(tmp_path, monkeypatch, "submit")
    substitute_snapshot = "sha256:" + "0" * 64
    snapshot_step = next(s for s in state["stages"] if s["name"] == "snapshot")
    assert snapshot_step["phase"] == "completed"
    # Unkeyed self-consistency: the snapshot's local result and selected
    # submit request both change together; frozen task source is unchanged.
    snapshot_step["result"]["result"]["recipe_identity"] = substitute_snapshot
    snapshot_step["result"]["result"]["artifacts"]["recipe_snapshot"] = substitute_snapshot
    state["recipe_identity"] = substitute_snapshot
    submit_step = state["stages"][-1]
    submit_step["request"]["arguments"]["recipe_snapshot"] = substitute_snapshot
    submit_step["request_sha256"] = hashlib.sha256(
        generic._canonical(submit_step["request"])).hexdigest()
    path.write_text(json.dumps(state))
    count = sum(k == "submit" and v == "pipeline.submit" for k,v in calls)
    with pytest.raises(RuntimeError, match="original snapshot receipt differs"):
        generic.advance(tmp_path, GATEWAY, host_factory=Host)
    assert sum(k == "submit" and v == "pipeline.submit" for k,v in calls) == count, (
        "substituted recipe snapshot sent to producer with forged local history")


def test_actual_submitting_record_remains_uncertain_and_never_auto_retries(
        tmp_path, monkeypatch):
    """Separate honest restart path *is* blocked by the existing guard."""
    Host, calls = mock_environment(monkeypatch)
    generic.advance(tmp_path, GATEWAY, host_factory=Host)
    path = tmp_path / "requests" / GATEWAY / generic.FILE
    state = json.loads(path.read_text())
    assert state["stages"][0]["phase"] == "prepared"
    state["stages"][0]["phase"] = "submitting"
    path.write_text(json.dumps(state))
    resumed = generic.advance(tmp_path, GATEWAY, host_factory=Host)
    assert resumed["phase"] == "uncertain"
    assert resumed["stages"][0]["phase"] == "uncertain"
    assert not calls
