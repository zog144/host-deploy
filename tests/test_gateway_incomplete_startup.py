"""Incomplete durable Gateway requests are retained and cannot restart SSM.

All tests are local: FakeSQS contains no AWS credentials and every forwarding
candidate is either skipped or intercepted before a real host is constructed.
"""
import json
import logging

import pytest

from zog.host_deploy.gateway import simple_forward
from zog.host_deploy.gateway.consumer import GatewayConsumer
from zog.host_deploy.gateway.ledger import (
    LedgerConflict, accept, reconcile_all, request_lock,
    summary, valid_request_ids,
)
from test_gateway_consumer import (
    FakeSQS, PRIMARY_ARN, DLQ_ARN, message, request,
)
from test_gateway_simple_forward import approved, admit


INCOMPLETE_ID = "c" * 32
WORKSPACE_ID = "d" * 32


def _gateway(root, client=None, *, direct_forward=False):
    return GatewayConsumer(root, PRIMARY_ARN, DLQ_ARN,
                           client=client or FakeSQS(),
                           direct_forward=direct_forward)


def _snapshot(directory):
    """Retain exact file names, bytes and symlink targets across inspection."""
    return {
        p.name: ("symlink", p.readlink().as_posix()) if p.is_symlink()
                else ("file", p.read_bytes())
        for p in directory.iterdir()
    }


@pytest.mark.parametrize("failure", [
    "lock_only", "missing_state", "empty_state", "truncated_state",
    "invalid_state_schema", "missing_transport", "truncated_transport",
    "truncated_dispatch", "symlink_state",
])
def test_incomplete_directory_is_reported_and_preserved_without_dispatch(
        tmp_path, caplog, failure):
    root = tmp_path / "gateway"
    original = request(WORKSPACE_ID, INCOMPLETE_ID)
    with request_lock(root, INCOMPLETE_ID):
        pass
    directory = root / "requests" / INCOMPLETE_ID
    if failure != "lock_only":
        # Start from genuine durable accept data, then simulate interrupted
        # storage rather than constructing a fictional valid request.
        # This intentionally avoids accept() here: existing lock-only state
        # must not be implicitly adopted on redelivery.
        directory.rmdir() if not any(directory.iterdir()) else None
        # Create a real request under a separate clean gateway root then
        # copy its original durable bytes without altering its request ID.
        fresh = tmp_path / "fresh"
        accept(fresh, original, message_id="initial-1", receive_count=1)
        for p in (fresh / "requests" / INCOMPLETE_ID).iterdir():
            (directory / p.name).write_bytes(p.read_bytes())
        if failure == "missing_state":
            (directory / "state.json").unlink()
        elif failure == "empty_state":
            (directory / "state.json").write_bytes(b"")
        elif failure == "truncated_state":
            (directory / "state.json").write_bytes(b"{")
        elif failure == "invalid_state_schema":
            (directory / "state.json").write_text(json.dumps({"schema": 1}))
        elif failure == "missing_transport":
            (directory / "transport.json").unlink()
        elif failure == "truncated_transport":
            (directory / "transport.json").write_bytes(b"{")
        elif failure == "truncated_dispatch":
            (directory / "dispatch.json").write_bytes(b"{")
        elif failure == "symlink_state":
            (directory / "state.json").unlink()
            outside = tmp_path / "outside.json"
            outside.write_text("{}")
            (directory / "state.json").symlink_to(outside)

    before = _snapshot(directory)
    observed = reconcile_all(root)
    assert len(observed) == 1
    assert observed[0]["request_id"] == INCOMPLETE_ID
    assert observed[0]["status"] == "invalid"
    assert observed[0]["error"]
    assert valid_request_ids(root) == []
    assert summary(root)["states"]["invalid"] == 1
    assert _snapshot(directory) == before

    gateway = _gateway(root, direct_forward=True)
    with caplog.at_level(logging.ERROR):
        gateway._reconcile()
        gateway._reconcile()
    errors = [line for line in caplog.messages
              if "retained request " + INCOMPLETE_ID in line]
    assert len(errors) == 1
    assert "invalid" in errors[0]
    assert gateway.poll_once(wait_seconds=0) is None
    assert gateway.client.receive_calls
    assert simple_forward.advance_one(root) is None
    assert _snapshot(directory) == before


@pytest.mark.parametrize("failure", [
    "lock_only", "missing_state", "truncated_state", "missing_transport",
])
def test_redelivery_cannot_reinitialize_incomplete_identity(tmp_path, failure):
    root = tmp_path / "gateway"
    original = request(WORKSPACE_ID, INCOMPLETE_ID)
    if failure == "lock_only":
        with request_lock(root, INCOMPLETE_ID):
            pass
    else:
        accept(root, original, message_id="original-1", receive_count=1)
        directory = root / "requests" / INCOMPLETE_ID
        if failure == "missing_state":
            (directory / "state.json").unlink()
        elif failure == "truncated_state":
            (directory / "state.json").write_text("{")
        elif failure == "missing_transport":
            (directory / "transport.json").unlink()
    directory = root / "requests" / INCOMPLETE_ID
    before = _snapshot(directory)
    client = FakeSQS([message(original, message_id="redelivery-2")])
    gateway = _gateway(root, client)
    outcome = gateway.poll_once(wait_seconds=0)
    assert outcome["accepted"] is False
    assert not client.deleted
    assert _snapshot(directory) == before
    assert summary(root)["states"]["invalid"] == 1


def test_startup_continues_to_reconcile_valid_neighbor_and_poll_empty_queue(
        tmp_path, caplog, monkeypatch):
    root = tmp_path / "gateway"
    with request_lock(root, INCOMPLETE_ID):
        pass
    good_id = "e" * 32
    good = request(WORKSPACE_ID, good_id)
    accept(root, good, message_id="good-1", receive_count=1)
    observed = reconcile_all(root)
    assert len(observed) == 2
    assert [r["request_id"] for r in observed if r.get("status") == "invalid"] == [
        INCOMPLETE_ID
    ]
    valid = [r for r in observed if r.get("request_id") == good_id]
    assert len(valid) == 1
    assert valid[0]["states"]["admission"] == "pending"
    assert valid_request_ids(root) == [good_id]

    client = FakeSQS()
    gateway = _gateway(root, client, direct_forward=True)
    class StopTestLoop(Exception):
        pass
    with caplog.at_level(logging.ERROR):
        def one_iteration():
            raise StopTestLoop()
        monkeypatch.setattr(gateway, "poll_once", one_iteration)
        with pytest.raises(StopTestLoop):
            gateway.run()
    assert any(INCOMPLETE_ID in line for line in caplog.messages)
    # After startup (without real SQS/SSM), the normal empty-queue poll is
    # still functional and does not attempt to forward host.status work.
    monkeypatch.undo()
    assert gateway.poll_once(wait_seconds=0) is None
    assert len(client.receive_calls) == 1
    assert summary(root)["requests"] == 1
    assert summary(root)["states"]["invalid"] == 1


def test_direct_forward_skips_incomplete_and_selects_only_valid_fonts_request(
        tmp_path, monkeypatch):
    root = tmp_path / "gateway"
    with request_lock(root, INCOMPLETE_ID):
        pass
    before = _snapshot(root / "requests" / INCOMPLETE_ID)
    approved_fonts = approved()
    admit(root, approved_fonts)
    selected = []
    def assess(gateway_root, request_id, *, host_factory):
        selected.append((gateway_root, request_id))
        return {"request_id": request_id, "phase": "assessed-only"}
    monkeypatch.setattr(simple_forward, "advance", assess)
    result = simple_forward.advance_one(root)
    assert result["phase"] == "assessed-only"
    assert selected == [(root, approved_fonts["request_id"])]
    assert _snapshot(root / "requests" / INCOMPLETE_ID) == before
