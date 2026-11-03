"""Security source regressions: no replacement SSM send or local forged snapshot.

Never invokes AWS. The Host class is an in-memory SSM simulation and the
local send-once directory is intentionally separate from the pipeline JSON.
Whole-STATE rollback resilience still requires independent native authority.
"""
import json
from pathlib import Path

import pytest

from zog.host_deploy.gateway import generic_pipeline as pipeline
from zog.host_deploy.gateway import graphics_operation_send_intent as intent
from test_gateway_generic_pipeline import GATEWAY, mock_environment
from test_gateway_graphical_submission_journal_review import _at_stage


def _count_submit(calls):
    return sum(k == "submit" and v == "pipeline.submit" for k, v in calls)


def _sidecar(root, step, suffix):
    return (root / "generic-operation-send-intents" /
            (GATEWAY + "--" + step["operation_id"] + suffix))


def test_operation_and_original_command_are_separate_exclusive_records(
        tmp_path, monkeypatch):
    Host, calls = mock_environment(monkeypatch)
    pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    submitted = pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    step = submitted["stages"][0]
    assert step["phase"] == "submitted"
    record = _sidecar(tmp_path, step, ".json")
    original = _sidecar(tmp_path, step, ".command.json")
    assert record.is_file() and original.is_file()
    expected = json.loads(record.read_text())
    command = json.loads(original.read_text())
    assert expected["operation_id"] == step["operation_id"]
    assert expected["task_catalogue_sha256"] == "sha256:" + "f"*64
    assert command["command_id"] == step["command_id"]
    assert command["operation_id"] == step["operation_id"]
    assert command["send_intent_sha256"] and len(command["send_intent_sha256"]) == 64
    assert record.stat().st_mode & 0o777 == 0o600
    assert original.stat().st_mode & 0o777 == 0o600
    # Not a new send authority even with the original exact bytes.
    with pytest.raises(intent.SendIntentBlocked):
        intent.claim(tmp_path, GATEWAY,
                     pipeline._base(tmp_path, GATEWAY)[1], step)


def test_lost_ack_plus_prepared_journal_replay_never_sends_twice(
        tmp_path, monkeypatch):
    Host, calls = mock_environment(monkeypatch, lost_reply=True)
    prepared = pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    original = (tmp_path / "requests" / GATEWAY / pipeline.FILE)
    before = original.read_bytes()
    assert prepared["stages"][0]["phase"] == "prepared"
    with pytest.raises(TimeoutError):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert len([v for v in calls if v[0] == "submit"]) == 1
    original.write_bytes(before)
    with pytest.raises(intent.SendIntentBlocked):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert len([v for v in calls if v[0] == "submit"]) == 1


@pytest.mark.parametrize("fault", ("partial-intent", "symlink-intent", "incorrect-mode"))
def test_torn_or_replaced_original_intent_is_not_authority(
        tmp_path, monkeypatch, fault):
    Host, calls = mock_environment(monkeypatch)
    state = pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    step = state["stages"][0]
    directory = tmp_path/"generic-operation-send-intents"
    directory.mkdir(mode=0o700)
    record = _sidecar(tmp_path, step, ".json")
    if fault == "symlink-intent":
        record.symlink_to(tmp_path / "not-an-intent")
    else:
        record.write_bytes(b"{")
        record.chmod(0o644 if fault == "incorrect-mode" else 0o600)
    with pytest.raises(intent.SendIntentBlocked):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert not calls


@pytest.mark.parametrize("fault", ("no-command", "changed-command", "wrong-mode"))
def test_snapshot_command_replacement_is_not_authenticated_history(
        tmp_path, monkeypatch, fault):
    Host, calls, path, prepared = _at_stage(tmp_path, monkeypatch, "submit")
    original = next(step for step in prepared["stages"] if step["name"] == "snapshot")
    command = _sidecar(tmp_path, original, ".command.json")
    if fault == "no-command":
        command.unlink()
    elif fault == "wrong-mode":
        command.chmod(0o644)
    else:
        altered = json.loads(command.read_text())
        altered["command_id"] = "foreign-command-id"
        command.write_text(json.dumps(altered))
    count = _count_submit(calls)
    with pytest.raises(intent.SendIntentBlocked):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert _count_submit(calls) == count


def test_forged_snapshot_command_id_in_local_journal_is_not_trusted(
        tmp_path, monkeypatch):
    Host, calls, path, state = _at_stage(tmp_path, monkeypatch, "submit")
    step = next(s for s in state["stages"] if s["name"] == "snapshot")
    step["command_id"] = "command-from-wrong-host"
    path.write_text(json.dumps(state))
    count = _count_submit(calls)
    with pytest.raises(intent.SendIntentBlocked):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert _count_submit(calls) == count


def test_original_snapshot_ssm_readback_unavailable_holds_before_submit(
        tmp_path, monkeypatch):
    Host, calls, path, state = _at_stage(tmp_path, monkeypatch, "submit")
    count = _count_submit(calls)
    monkeypatch.setattr(Host, "inspect_command", lambda self, command_id: None)
    with pytest.raises(RuntimeError, match="original SSM snapshot observation unavailable"):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert _count_submit(calls) == count
    # A transient inspection outage does not mint an SSM send intent.
    submit = state["stages"][-1]
    assert not _sidecar(tmp_path, submit, ".json").exists()



def test_surviving_command_receipt_with_missing_intent_never_reissues(
        tmp_path, monkeypatch):
    Host, calls = mock_environment(monkeypatch)
    prepared = pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    original = tmp_path/"requests"/GATEWAY/pipeline.FILE
    previous = original.read_bytes()
    sent = pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    step = sent["stages"][0]
    intent_path = _sidecar(tmp_path, step, ".json")
    command_path = _sidecar(tmp_path, step, ".command.json")
    assert intent_path.exists() and command_path.exists()
    intent_path.unlink()
    original.write_bytes(previous)
    with pytest.raises(intent.SendIntentBlocked):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert len([v for v in calls if v[0] == "submit"]) == 1


@pytest.mark.parametrize("observation", ("foreign-command-id", "missing-command-id",
                                          "failed-status", "stale-result"))
def test_external_snapshot_readback_requires_original_ssm_identity_and_result(
        tmp_path, monkeypatch, observation):
    Host, calls, path, prepared = _at_stage(tmp_path, monkeypatch, "submit")
    original = next(s for s in prepared["stages"] if s["name"] == "snapshot")
    count = _count_submit(calls)
    inspect = Host.inspect_command

    def changed(self, command_id):
        if command_id != original["command_id"]:
            return inspect(self, command_id)
        found = inspect(self, command_id)
        if observation == "foreign-command-id":
            found["CommandId"] = "another-ssm-invocation"
        elif observation == "missing-command-id":
            found.pop("CommandId")
        elif observation == "failed-status":
            found["Status"] = "Failed"
        return found

    monkeypatch.setattr(Host, "inspect_command", changed)
    if observation == "stale-result":
        old_parser = pipeline.parse_receipt

        def forged(text, binding):
            value = old_parser(text, binding)
            if binding["remote_request"]["operation"] == "recipes.snapshot":
                value["result"]["recipe_identity"] = "sha256:" + "0"*64
            return value

        monkeypatch.setattr(pipeline, "parse_receipt", forged)
    with pytest.raises(RuntimeError):
        pipeline.advance(tmp_path, GATEWAY, host_factory=Host)
    assert _count_submit(calls) == count
