"""Reviewed unattended generic SQS advancement and immutable policy admission."""
import json
from pathlib import Path

import pytest

from zog.host_deploy.gateway import consumer
from zog.host_deploy.gateway import task_catalogue


def test_xcb_task_cannot_be_remapped_to_another_valid_recipe():
    item = {
        "source_repository": "zog144/image-build",
        "source_revision": "0fd3f00cafc7138d3bac9695c87a8ece65821868",
        "lane": "xcb-lane", "lane_owner": "reviewed-host",
        "monthly_pin_repository_path": "project/pins/2026-10-01/commit-pin.py",
        "monthly_pin_identity": "sha256:" + "a"*64,
        "pin_date": "2026-10-01",
        "entries": [
            {"id": ident, "project": project, "recipe": recipe}
            for ident, project, recipe in task_catalogue.XCB_ENTRIES
        ],
        "arguments": {
            "mode": "image", "selection": "b"*64,
            "targets": [item[0] for item in task_catalogue.XCB_ENTRIES],
        },
    }
    catalogue = {"schema": 2, "tasks": {"xcb-support-image-v1": item}}
    assert task_catalogue.validate(catalogue)["tasks"]["xcb-support-image-v1"] == item
    unreviewed = json.loads(json.dumps(catalogue))
    entry = unreviewed["tasks"]["xcb-support-image-v1"]["entries"][0]
    entry["id"] = "xcb-util-alternate"
    unreviewed["tasks"]["xcb-support-image-v1"]["arguments"]["targets"][0] = "xcb-util-alternate"
    with pytest.raises(task_catalogue.TaskCatalogueError, match="reviewed selection"):
        task_catalogue.validate(unreviewed)
    unreviewed = json.loads(json.dumps(catalogue))
    unreviewed["tasks"]["xcb-support-image-v1"]["arguments"]["mode"] = "native-check"
    with pytest.raises(task_catalogue.TaskCatalogueError, match="XCB image targets"):
        task_catalogue.validate(unreviewed)


def test_unattended_advancer_detects_catalogue_revocation_before_request_scan(
        tmp_path, monkeypatch):
    owner = object.__new__(consumer.GatewayConsumer)
    owner.state_directory = tmp_path
    owner.approved_generic_catalogue = {"schema": 2, "tasks": {}}
    owner.approved_catalogue_identity = "sha256:" + "a"*64
    owner.approved_catalogue_path = "/etc/host-deploy/approved-generic-tasks.json"
    (tmp_path / "requests").mkdir()
    monkeypatch.setattr(consumer, "load_task_catalogue",
                        lambda path, require_root_owned: (
                            {"schema": 2, "tasks": {"different": {}}},
                            "sha256:" + "b"*64,
                        ))
    monkeypatch.setattr(consumer, "load_request",
                        lambda *args: pytest.fail("revoked catalogue must halt before request"))
    with pytest.raises(RuntimeError, match="authorization revoked"):
        owner._advance_one_reviewed()


def test_unattended_advancer_can_continue_only_with_same_root_owned_policy(
        tmp_path, monkeypatch):
    owner = object.__new__(consumer.GatewayConsumer)
    owner.state_directory = tmp_path
    owner.approved_generic_catalogue = {"schema": 2, "tasks": {"xcb-support-image-v1": {}}}
    owner.approved_catalogue_identity = "sha256:" + "a"*64
    owner.approved_catalogue_path = "/etc/host-deploy/approved-generic-tasks.json"
    (tmp_path / "requests").mkdir()
    seen = []
    def loader(path, *, require_root_owned):
        seen.append((path, require_root_owned))
        return owner.approved_generic_catalogue, owner.approved_catalogue_identity
    monkeypatch.setattr(consumer, "load_task_catalogue", loader)
    assert owner._advance_one_reviewed() is None
    assert seen == [(owner.approved_catalogue_path, True)]


def test_missing_or_replaced_supervisor_digest_rejected_before_aws(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(consumer, "_client",
                        lambda: pytest.fail("rejected catalogue must not contact AWS"))
    args = [
        "--state-directory", str(tmp_path), "run",
        "--queue-target", "reviewed-queue",
        "--dead-letter-target", "reviewed-dlq",
        "--once", "--advance-reviewed-generic",
        "--approved-task-catalogue", "/etc/host-deploy/tasks.json",
    ]
    with pytest.raises(SystemExit):
        consumer.main(args)
    monkeypatch.setattr(consumer, "load_task_catalogue",
                        lambda path, *, require_root_owned: (
                            {"schema": 2, "tasks": {}}, "sha256:"+"a"*64,
                        ))
    with pytest.raises(SystemExit):
        consumer.main(args + [
            "--approved-task-catalogue-sha256", "sha256:" + "b"*64,
        ])


def test_reviewed_override_is_explicit_not_a_second_consumer():
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/zog/host_deploy/gateway/host-deploy-gateway.service").read_text()
    reviewed = (root / "examples/host-deploy-gateway-reviewed-generic.conf").read_text()
    assert "--advance-reviewed-generic" not in source
    assert "ExecStart=" in reviewed
    assert reviewed.count("ExecStart=") == 2
    assert "--advance-reviewed-generic" in reviewed
    assert "--approved-task-catalogue-sha256" in reviewed
    assert "REPLACE_WITH_OWNER_APPROVED_SHA256" in reviewed


def test_durable_supervisor_rate_bound_prevents_sqs_flood_and_survives_restart(
        tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    instant = datetime(2026, 10, 19, 18, 0, tzinfo=timezone.utc)
    clock = [instant]
    monkeypatch.setattr(consumer, "_reviewed_clock", lambda: clock[0])
    rid = "a"*32
    digest = "sha256:" + "a"*64
    assert consumer._reserve_reviewed_advance(tmp_path, rid, digest) is True
    marker = tmp_path / consumer.REVIEWED_ADVANCE_MARKER
    original = marker.read_text()
    assert consumer._reserve_reviewed_advance(tmp_path, rid, digest) is False
    assert marker.read_text() == original
    clock[0] += timedelta(seconds=consumer.REVIEWED_MINIMUM_ADVANCE_SECONDS + 1)
    assert consumer._reserve_reviewed_advance(tmp_path, rid, digest) is True
    assert json.loads(marker.read_text())["reserved_at"] == clock[0].isoformat()
    clock[0] -= timedelta(minutes=2)
    with pytest.raises(RuntimeError, match="clock moved backwards"):
        consumer._reserve_reviewed_advance(tmp_path, rid, digest)


def test_supervisor_marker_integrity_faults_block_new_action(tmp_path):
    marker = tmp_path / consumer.REVIEWED_ADVANCE_MARKER
    marker.write_text("{}")
    with pytest.raises(RuntimeError, match="corrupted"):
        consumer._reserve_reviewed_advance(
            tmp_path, "a"*32, "sha256:"+"b"*64,
        )
    marker.unlink()
    marker.symlink_to(tmp_path / "missing")
    with pytest.raises(RuntimeError, match="symlink"):
        consumer._reserve_reviewed_advance(
            tmp_path, "a"*32, "sha256:"+"b"*64,
        )
