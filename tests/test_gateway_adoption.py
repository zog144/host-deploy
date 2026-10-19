from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading

import pytest
from botocore.exceptions import ClientError

from zog.host_deploy import checkpoint
from zog.host_deploy.gateway.adoption import (
    AdoptionConflict,
    adopt_workspace,
    load_adoption,
    recover_rejected_adoption,
    validate_request,
)
from zog.host_deploy.gateway.ledger import claim_handoff, owned_workspace
from zog.host_deploy.workspace import save


WORKSPACE = "0123456789abcdeffedcba9876543210"
OPERATION = "a1b2c3d4e5f6478890abcdef12345678"
INSTANCE = "i-0123456789abcdef0"
ACCOUNT = "123456789012"


def request(**changes):
    value = {
        "schema": 1,
        "operation_id": OPERATION,
        "workspace_id": WORKSPACE,
        "name": "example-compiler-host",
        "profile": None,
        "region": "us-east-1",
        "account_id": ACCOUNT,
        "instance_id": INSTANCE,
        "target_owner": "host-deploy-gateway",
        "missing_original_checkpoint": True,
        "operator_authorization": "synthetic fixture authorization for disposable compiler workspace",
        "saved_state_hashes": {
            "pass3-state": "1" * 64,
            "pass3-transport": "2" * 64,
        },
        "expected_writer_set": [
            "archive-mirror-work",
            "image-build-work",
            "integrate-observe-work",
        ],
        "writer_acknowledgements": [
            {
                "writer": "image-build-work",
                "acknowledgement": "stand-down handoff published",
                "quiesced": True,
            },
            {
                "writer": "archive-mirror-work",
                "acknowledgement": "no compiler-host mutations pending",
                "quiesced": True,
            },
            {
                "writer": "integrate-observe-work",
                "acknowledgement": "no production publisher mutation pending",
                "quiesced": True,
            },
        ],
    }
    value.update(changes)
    return value


def instance(*, launch_time="2026-09-29T19:10:12+00:00", state="running"):
    return {
        "InstanceId": INSTANCE,
        "InstanceType": "m6i.2xlarge",
        "State": {"Name": state},
        "LaunchTime": launch_time,
        "Tags": [
            {"Key": "ManagedBy", "Value": "host-deploy"},
            {"Key": "ZogWorkspace", "Value": WORKSPACE},
            {"Key": "Name", "Value": "example-compiler-host"},
            {"Key": "ZogLifetime", "Value": "persistent"},
        ],
        "BlockDeviceMappings": [
            {"Ebs": {"VolumeId": "vol-0942c7ea99742fb00"}},
        ],
    }


class FakeCloud:
    current = instance()

    def __init__(self, workspace):
        self.workspace = workspace

    def account(self):
        return ACCOUNT

    def owned(self, instance_id, account):
        assert instance_id == INSTANCE
        assert account == ACCOUNT
        return json.loads(json.dumps(type(self).current))


class FakeHost:
    marker = None
    expected_marker = None
    submit_calls = 0
    observe_calls = 0
    lose_reply = False
    write_before_loss = False

    def __init__(self, configuration):
        self.configuration = configuration

    @classmethod
    def reset(cls):
        cls.marker = None
        cls.expected_marker = None
        cls.submit_calls = 0
        cls.observe_calls = 0
        cls.lose_reply = False
        cls.write_before_loss = False

    def submit_command(self, script, seconds):
        type(self).submit_calls += 1
        if type(self).write_before_loss:
            type(self).marker = type(self).expected_marker
        if type(self).lose_reply:
            raise TimeoutError("lost ownership-marker reply")
        type(self).marker = type(self).expected_marker
        return "command-adopt"

    def wait_command(self, command_id, seconds):
        assert command_id == "command-adopt"
        return ""

    def command(self, script, seconds):
        type(self).observe_calls += 1
        return json.dumps(type(self).marker, sort_keys=True)


@pytest.fixture(autouse=True)
def reset_fakes():
    FakeCloud.current = instance()
    FakeHost.reset()


def marker_for(value):
    return {
        "schema": 1,
        "owner": "host-deploy-gateway",
        "workspace_id": value["workspace_id"],
        "instance_id": value["instance_id"],
        "account_id": value["account_id"],
        "region": value["region"],
        "ownership_epoch": value["operation_id"],
        "adoption_operation_id": value["operation_id"],
    }


def adopt(tmp_path, value=None):
    value = request() if value is None else value
    FakeHost.expected_marker = marker_for(value)
    return adopt_workspace(
        tmp_path / "gateway",
        value,
        at="2026-10-10T18:00:00Z",
        cloud_factory=FakeCloud,
        host_factory=FakeHost,
    )


def test_adoption_creates_auditable_gateway_owned_workspace_without_fake_launch(tmp_path):
    result = adopt(tmp_path)

    assert result["workspace_id"] == WORKSPACE
    assert result["ownership_epoch"] == OPERATION
    assert FakeHost.submit_calls == 1
    workspace = tmp_path / "gateway/workspaces" / WORKSPACE
    assert owned_workspace(tmp_path / "gateway", WORKSPACE) == workspace
    assert not (workspace / "launch.json").exists()

    host = json.loads((workspace / "host.json").read_text())
    assert host["instance_id"] == INSTANCE
    assert host["ownership_epoch"] == OPERATION
    assert host["adoption_operation_id"] == OPERATION
    assert host["lifetime"] == "persistent"

    adoption = json.loads((workspace / "adoption.json").read_text())
    assert adoption["missing_original_checkpoint"] is True
    assert adoption["operation_id"] == OPERATION
    assert adoption["saved_state_hashes"] == request()["saved_state_hashes"]
    assert adoption["expected_writer_set"] == sorted(request()["expected_writer_set"])
    assert {item["writer"] for item in adoption["writer_acknowledgements"]} == set(
        request()["expected_writer_set"]
    )

    record = load_adoption(tmp_path / "gateway", OPERATION)
    assert record["phase"] == "owned"
    assert record["inventory"]["volumes"] == ["vol-0942c7ea99742fb00"]
    assert record["inventory"]["state"] == "running"


def test_same_adoption_request_replays_without_second_marker_mutation(tmp_path):
    first = adopt(tmp_path)
    second = adopt(tmp_path)
    assert second == first
    assert FakeHost.submit_calls == 1


def test_adoption_requires_all_declared_writers_quiesced_before_aws(tmp_path):
    value = request()
    value["writer_acknowledgements"] = value["writer_acknowledgements"][:-1]
    with pytest.raises(ValueError, match="one acknowledgement"):
        adopt(tmp_path, value)
    assert FakeHost.submit_calls == 0


def test_adoption_refuses_existing_gateway_claim_for_same_instance(tmp_path):
    other = tmp_path / "gateway/workspaces/00112233445566778899aabbccddeeff"
    other.mkdir(parents=True)
    save(
        other / "host.json",
        {
            "region": "us-east-1",
            "profile": None,
            "instance_id": INSTANCE,
            "workspace_id": "00112233445566778899aabbccddeeff",
            "account_id": ACCOUNT,
        },
    )
    with pytest.raises(AdoptionConflict, match="another gateway workspace"):
        adopt(tmp_path)
    assert FakeHost.submit_calls == 0


def test_live_identity_change_after_marker_blocks_local_ownership_commit(tmp_path):
    class ChangingCloud(FakeCloud):
        observations = 0

        def owned(self, instance_id, account):
            type(self).observations += 1
            value = super().owned(instance_id, account)
            if type(self).observations >= 2:
                value["InstanceType"] = "m6i.4xlarge"
            return value

    FakeHost.expected_marker = marker_for(request())
    with pytest.raises(AdoptionConflict, match="identity changed"):
        adopt_workspace(
            tmp_path / "gateway",
            request(),
            at="2026-10-10T18:00:00Z",
            cloud_factory=ChangingCloud,
            host_factory=FakeHost,
        )
    assert FakeHost.submit_calls == 1
    assert owned_workspace(tmp_path / "gateway", WORKSPACE) is None


def test_lost_reply_after_remote_marker_recovers_same_operation_without_resubmit(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)
    FakeHost.lose_reply = True
    FakeHost.write_before_loss = True
    with pytest.raises(TimeoutError, match="lost ownership-marker reply"):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:00Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    assert load_adoption(tmp_path / "gateway", OPERATION)["phase"] == "marker_uncertain"
    assert FakeHost.submit_calls == 1

    FakeHost.lose_reply = False
    result = adopt_workspace(
        tmp_path / "gateway",
        value,
        at="2026-10-10T18:00:01Z",
        cloud_factory=FakeCloud,
        host_factory=FakeHost,
    )
    assert result["owned"] is True
    assert FakeHost.submit_calls == 1
    assert FakeHost.observe_calls >= 1


def test_uncertain_marker_absence_never_authorizes_replacement_mutation(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)
    FakeHost.lose_reply = True
    FakeHost.write_before_loss = False
    with pytest.raises(TimeoutError):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:00Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    FakeHost.lose_reply = False
    with pytest.raises(RuntimeError, match="remains uncertain"):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:01Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    assert FakeHost.submit_calls == 1


def test_adopted_workspace_can_be_checkpointed_and_claimed_normally(tmp_path):
    adopt(tmp_path)
    workspace = tmp_path / "gateway/workspaces" / WORKSPACE
    archive = tmp_path / "adopted-handoff.zip"

    checkpoint.export(workspace, archive, handoff=True)
    claimed = claim_handoff(tmp_path / "next-gateway", archive)

    assert claimed["workspace_id"] == WORKSPACE
    restored = tmp_path / "next-gateway/workspaces" / WORKSPACE
    assert json.loads((restored / "adoption.json").read_text())["operation_id"] == OPERATION
    assert json.loads((restored / "host.json").read_text())["ownership_epoch"] == OPERATION


@pytest.mark.parametrize(
    "changes",
    [
        {"missing_original_checkpoint": False},
        {"target_owner": "other-owner"},
        {"account_id": "not-an-account"},
        {"instance_id": "bad-instance"},
        {"operator_authorization": ""},
        {"saved_state_hashes": {}},
    ],
)
def test_adoption_request_rejects_unreviewed_or_invalid_identity(changes):
    with pytest.raises(ValueError):
        validate_request(request(**changes))


def test_process_loss_during_local_commit_resumes_without_remote_replay(tmp_path, monkeypatch):
    value = request()
    FakeHost.expected_marker = marker_for(value)

    from zog.host_deploy.gateway import adoption as implementation

    original_save = implementation.save
    failed = {"done": False}

    def interrupted_save(path, payload):
        path = Path(path)
        original_save(path, payload)
        if path.name == "workspace.json" and not failed["done"]:
            failed["done"] = True
            raise OSError("simulated local storage interruption")

    monkeypatch.setattr(implementation, "save", interrupted_save)
    with pytest.raises(OSError, match="local storage interruption"):
        implementation.adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:00Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    assert FakeHost.submit_calls == 1
    record = load_adoption(tmp_path / "gateway", OPERATION)
    assert record["phase"] == "marker_confirmed"

    monkeypatch.setattr(implementation, "save", original_save)
    result = implementation.adopt_workspace(
        tmp_path / "gateway",
        value,
        at="2026-10-10T18:00:01Z",
        cloud_factory=FakeCloud,
        host_factory=FakeHost,
    )
    assert result["owned"] is True
    assert FakeHost.submit_calls == 1
    workspace = tmp_path / "gateway/workspaces" / WORKSPACE
    assert (workspace / "workspace.json").is_file()
    assert (workspace / "host.json").is_file()
    assert (workspace / "adoption.json").is_file()


def test_same_adoption_operation_id_cannot_be_rebound_to_new_input(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)
    adopt(tmp_path, value)

    changed = request(name="different-name")
    with pytest.raises(AdoptionConflict, match="different input"):
        adopt_workspace(
            tmp_path / "gateway",
            changed,
            at="2026-10-10T18:00:02Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    assert FakeHost.submit_calls == 1


def test_concurrent_same_adoption_serializes_to_one_remote_marker_mutation(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)
    entered = threading.Event()
    release = threading.Event()

    class BlockingHost(FakeHost):
        def submit_command(self, script, seconds):
            type(self).submit_calls += 1
            entered.set()
            assert release.wait(timeout=5)
            type(self).marker = type(self).expected_marker
            return "command-adopt"

    BlockingHost.reset()
    BlockingHost.expected_marker = marker_for(value)

    def run():
        return adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:00Z",
            cloud_factory=FakeCloud,
            host_factory=BlockingHost,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run)
        assert entered.wait(timeout=5)
        second = pool.submit(run)
        release.set()
        first_result = first.result(timeout=5)
        second_result = second.result(timeout=5)

    assert first_result == second_result
    assert BlockingHost.submit_calls == 1


def access_denied():
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": (
                    "not authorized to perform: ssm:SendCommand on resource "
                    "arn:aws:ec2:us-east-1:123456789012:instance/" + INSTANCE
                ),
            }
        },
        "SendCommand",
    )


def test_access_denied_is_retained_as_definite_marker_rejection(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)

    class DeniedHost(FakeHost):
        def submit_command(self, script, seconds):
            type(self).submit_calls += 1
            raise access_denied()

    DeniedHost.reset()
    DeniedHost.expected_marker = marker_for(value)

    with pytest.raises(ClientError):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:20:09Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedHost,
        )

    record = load_adoption(tmp_path / "gateway", OPERATION)
    assert record["phase"] == "marker_rejected"
    assert record["rejection"]["operation"] == "SendCommand"
    assert record["rejection"]["code"] == "AccessDeniedException"
    assert "marker_command_id" not in record
    assert record["marker_attempt_count"] == 1

    with pytest.raises(RuntimeError, match="recover-rejected-adoption"):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:20:10Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedHost,
        )
    assert DeniedHost.submit_calls == 1


def test_rejected_marker_recovery_rechecks_absence_then_retries_same_operation_once(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)

    class DeniedOnceHost(FakeHost):
        deny = True

        def submit_command(self, script, seconds):
            type(self).submit_calls += 1
            if type(self).deny:
                raise access_denied()
            type(self).marker = type(self).expected_marker
            return "command-adopt"

    DeniedOnceHost.reset()
    DeniedOnceHost.expected_marker = marker_for(value)
    DeniedOnceHost.deny = True

    with pytest.raises(ClientError):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:20:09Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedOnceHost,
        )

    recovery = recover_rejected_adoption(
        tmp_path / "gateway",
        value,
        at="2026-10-10T21:35:00Z",
        cloud_factory=FakeCloud,
        host_factory=DeniedOnceHost,
    )
    assert recovery["phase"] == "marker_retry_authorized"
    assert recovery["rejection_code"] == "AccessDeniedException"
    record = load_adoption(tmp_path / "gateway", OPERATION)
    assert record["phase"] == "marker_retry_authorized"
    assert record["recovery_history"][-1]["remote_marker"] == "absent"
    assert record["marker_attempt_count"] == 1
    assert DeniedOnceHost.submit_calls == 1

    DeniedOnceHost.deny = False
    result = adopt_workspace(
        tmp_path / "gateway",
        value,
        at="2026-10-10T21:35:01Z",
        cloud_factory=FakeCloud,
        host_factory=DeniedOnceHost,
    )
    assert result["owned"] is True
    assert DeniedOnceHost.submit_calls == 2
    record = load_adoption(tmp_path / "gateway", OPERATION)
    assert record["phase"] == "owned"
    assert record["marker_attempt_count"] == 2


def test_historical_access_denied_uncertainty_can_use_reviewed_recovery(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)

    from zog.host_deploy.gateway import adoption as implementation

    record = implementation._prepare(
        tmp_path / "gateway",
        value,
        at="2026-10-10T21:20:09Z",
        cloud_factory=FakeCloud,
    )
    record["phase"] = "marker_uncertain"
    record["marker_attempt_started_at"] = "2026-10-10T21:20:09Z"
    record["uncertainty_at"] = "2026-10-10T21:20:09Z"
    record["error"] = str(access_denied())[:512]
    save(
        tmp_path / "gateway/adoptions" / (OPERATION + ".json"),
        record,
    )

    result = recover_rejected_adoption(
        tmp_path / "gateway",
        value,
        at="2026-10-10T21:35:00Z",
        cloud_factory=FakeCloud,
        host_factory=FakeHost,
    )
    assert result["retry_authorized"] is True
    retained = load_adoption(tmp_path / "gateway", OPERATION)
    rejection = retained["recovery_history"][-1]["rejection"]
    assert rejection["code"] == "AccessDeniedException"
    assert rejection["legacy_unstructured"] is True
    assert retained["marker_attempt_count"] == 1


def test_true_unknown_uncertainty_cannot_use_rejected_marker_recovery(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)
    FakeHost.lose_reply = True
    FakeHost.write_before_loss = False
    with pytest.raises(TimeoutError):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:00Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    FakeHost.lose_reply = False
    with pytest.raises(RuntimeError, match="does not prove a definite SendCommand rejection"):
        recover_rejected_adoption(
            tmp_path / "gateway",
            value,
            at="2026-10-10T18:00:01Z",
            cloud_factory=FakeCloud,
            host_factory=FakeHost,
        )
    assert FakeHost.submit_calls == 1


def test_rejected_marker_recovery_refuses_live_identity_drift(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)

    class DeniedHost(FakeHost):
        def submit_command(self, script, seconds):
            type(self).submit_calls += 1
            raise access_denied()

    DeniedHost.reset()
    DeniedHost.expected_marker = marker_for(value)
    with pytest.raises(ClientError):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:20:09Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedHost,
        )

    FakeCloud.current = instance()
    FakeCloud.current["InstanceType"] = "m6i.4xlarge"
    with pytest.raises(AdoptionConflict, match="identity changed"):
        recover_rejected_adoption(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:35:00Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedHost,
        )
    assert DeniedHost.submit_calls == 1


def test_rejected_marker_recovery_refuses_conflicting_remote_marker(tmp_path):
    value = request()
    FakeHost.expected_marker = marker_for(value)

    class DeniedHost(FakeHost):
        def submit_command(self, script, seconds):
            type(self).submit_calls += 1
            raise access_denied()

    DeniedHost.reset()
    DeniedHost.expected_marker = marker_for(value)
    with pytest.raises(ClientError):
        adopt_workspace(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:20:09Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedHost,
        )

    DeniedHost.marker = marker_for(value) | {"ownership_epoch": "f" * 32}
    with pytest.raises(AdoptionConflict, match="differs"):
        recover_rejected_adoption(
            tmp_path / "gateway",
            value,
            at="2026-10-10T21:35:00Z",
            cloud_factory=FakeCloud,
            host_factory=DeniedHost,
        )
    assert DeniedHost.submit_calls == 1
