"""No-replay historical CommandId inspection, bound to existing root journal."""
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
import hashlib
import json
import os

import pytest

from test_fonts_lane_supersession_audit import fixture as original_fixture, _snapshot
from zog.host_deploy import fonts_lane_historical_ssm_readback as historic
from zog.host_deploy import fonts_lane_supersession_audit as local


def sha(value):
    return hashlib.sha256(value).hexdigest()


class FakeSSM:
    def __init__(self, entries):
        self.entries = entries
        self.meta = SimpleNamespace(region_name="us-east-1")
        self.calls = []
        self.status_override = None
        self.script_override = None
        self.target_override = None
        self.time_override = None

    def list_commands(self, **kwargs):
        self.calls.append(("list_commands", kwargs))
        assert set(kwargs) == {"CommandId", "MaxResults"}
        assert kwargs["MaxResults"] == 2
        row = next(x for x in self.entries if x["command_id"] == kwargs["CommandId"])
        command = {
            "CommandId": row["command_id"],
            "DocumentName": "AWS-RunShellScript",
            "InstanceIds": [self.target_override or row["instance_id"]],
            "Targets": [],
            "Parameters": {
                "commands": [self.script_override or row["script"]],
                "executionTimeout": [str(row["execution_timeout_seconds"])],
            },
            "RequestedDateTime": self.time_override or datetime(
                2026, 11, 14, 19, 0, tzinfo=timezone.utc),
            "Status": self.status_override or row["status"],
        }
        return {"Commands": [command]}

    def get_command_invocation(self, **kwargs):
        self.calls.append(("get_command_invocation", kwargs))
        assert set(kwargs) == {"CommandId", "InstanceId"}
        row = next(x for x in self.entries if x["command_id"] == kwargs["CommandId"])
        return {
            "CommandId": row["command_id"],
            "InstanceId": row["instance_id"],
            "DocumentName": "AWS-RunShellScript",
            "Status": row["status"],
            "ResponseCode": 0 if row["status"] == "Success" else 1,
            "StandardOutputContent": '{"historical":"not-authority"}',
            "StandardErrorContent": "a previous migration command",
        }

    def send_command(self, **kwargs):
        pytest.fail("historical readback attempted a replay or new SSM send")


class FakeSTS:
    def __init__(self, account):
        self.account = account
        self.calls = []

    def get_caller_identity(self):
        self.calls.append("GetCallerIdentity")
        return {"Account": self.account}


def prepared(tmp_path, monkeypatch):
    root, workspace, host, record, spec, approvals = original_fixture(tmp_path)
    report = local.inspect(root, **approvals)
    journal = tmp_path / "protected-journal"
    journal.mkdir(mode=0o700)
    (journal / ".lock").write_bytes(b"")
    (journal / ".lock").chmod(0o600)
    commands = []
    for i, status in enumerate(("Failed", "Success")):
        operation_id = ("a" if i == 0 else "b") * 32
        command_id = ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                      if i == 0 else "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        script = "python3 -c 'print(\"legacy diagnostic only\")'\n" + str(i)
        row = {
            "ordinal": historic._ORDER[i],
            "operation_id": operation_id,
            "command_id": command_id,
            "request_sha256": sha(("request-" + str(i)).encode()),
            "script_sha256": sha(script.encode()),
            "execution_timeout_seconds": 120,
        }
        commands.append({**row, "script": script,
                         "status": status,
                         "instance_id": report["compiler_target"]["instance_id"]})
        intent = {
            "schema": historic.ORIGINAL_INTENT,
            "operation_id": operation_id,
            "request_sha256": row["request_sha256"],
            "script_sha256": row["script_sha256"],
            "target": {k: report["compiler_target"][k] for k in (
                "instance_id", "region", "account_id")},
            "document": "AWS-RunShellScript",
            "execution_timeout_seconds": 120,
        }
        command = {
            "schema": historic.ORIGINAL_COMMAND,
            "operation_id": operation_id,
            "request_sha256": row["request_sha256"],
            "command_id": command_id,
        }
        for suffix, data in (("intent", intent), ("command", command)):
            path = journal / (operation_id + "." + suffix + ".json")
            path.write_bytes(historic._canonical(data))
            path.chmod(0o600)
    witness = {
        "schema": historic.SCHEMA,
        "binding": report["compiler_target"],
        "selected_lane_record_sha256": report["selected_lane_record_sha256"],
        "pending_intent_sha256": report["pending_intent_sha256"],
        "original_specification_sha256": report["original_schema4_specification_sha256"],
        "commands": [{k: v for k, v in row.items()
                      if k not in {"script", "status", "instance_id"}}
                     for row in commands],
    }
    proof = root / historic.EVIDENCE
    proof.write_bytes(historic._canonical(witness) + b"\n")
    proof.chmod(0o600)
    digest = sha(proof.read_bytes())

    # Source CI is deliberately unprivileged. Stub only the native root
    # journal opening lock; test actual _file and exact journal envelopes.
    # The production native root custody gate remains separately mandatory.
    @contextmanager
    def trusted_test_journal(path):
        assert str(path) == str(journal)
        fd = os.open(journal, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)
    monkeypatch.setattr(historic, "_journal", trusted_test_journal)
    ssm, sts = FakeSSM(commands), FakeSTS(host["account_id"])
    return root, approvals, journal, witness, proof, digest, ssm, sts


def observe(data):
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    return historic.inspect(
        root, approvals=approvals,
        expected_evidence_sha256=digest,
        journal_directory=str(journal), ssm_client=ssm,
        sts_client=sts, aws_region="us-east-1")


def test_exact_original_journal_and_ssm_readback_preserves_everything(tmp_path, monkeypatch):
    data = prepared(tmp_path, monkeypatch)
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    before = _snapshot(tmp_path)
    report = observe(data)
    assert _snapshot(tmp_path) == before
    assert report["schema"] == historic.REPORT
    assert report["status"] == "supersession-unproven"
    assert report["original_journal_attested"] is True
    assert len(report["historical_ssm_readback"]) == 2
    assert [r["status"] for r in report["historical_ssm_readback"]] == [
        "Failed", "Success"]
    assert [r["response_code"] for r in report["historical_ssm_readback"]] == [1, 0]
    assert report["reviewed_witness_sha256"] == digest
    assert report["superseding_writer"] is None
    assert report["original_migration_to_current_lane_transition_verified"] is False
    for key in ("mutation", "ssm_send_authorized", "execution_authorized",
                "compilation_authorized"):
        assert report[key] is False
    for row in report["historical_ssm_readback"]:
        assert row["historical_writer_authenticated"] is False
        assert row["full_stdout_authenticated"] is False
    assert [x[0] for x in ssm.calls] == [
        "list_commands", "get_command_invocation"] * 2
    assert sts.calls == ["GetCallerIdentity"]


def test_missing_approval_blocks_before_journal_or_aws(tmp_path, monkeypatch):
    data = prepared(tmp_path, monkeypatch)
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    proof.unlink()
    with pytest.raises((local.AuditHold, historic.HistoricalHold)):
        observe(data)
    assert not ssm.calls and not sts.calls
    assert not proof.exists()


@pytest.mark.parametrize("damage", [
    "wrong-digest", "changed-lane", "changed-host", "missing-command",
    "wrong-original-command", "wrong-original-script", "cancelled",
    "symlink-journal-record", "hardlinked-journal-record",
    "reordered-operations", "duplicate-witness",
])
def test_foreign_history_cannot_trigger_aws_readback(tmp_path, monkeypatch, damage):
    data = list(prepared(tmp_path, monkeypatch))
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    op = witness["commands"][0]["operation_id"]
    if damage == "wrong-digest":
        data[5] = "f"*64
    elif damage == "changed-lane":
        lane_path = root / "image-build-lanes/gateway-first-fonts-runtime.json"
        record = json.loads(lane_path.read_text())
        record["state"] = "retired"
        lane_path.write_text(json.dumps(record))
    elif damage == "changed-host":
        host_path = root / "host.json"
        host = json.loads(host_path.read_text())
        host["instance_id"] = "i-fffffffffffffffff"
        host_path.write_text(json.dumps(host))
    elif damage == "missing-command":
        (journal / (op + ".command.json")).unlink()
    elif damage == "wrong-original-command":
        path = journal / (op + ".command.json")
        row = json.loads(path.read_bytes())
        row["command_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        path.write_bytes(historic._canonical(row))
    elif damage == "wrong-original-script":
        path = journal / (op + ".intent.json")
        row = json.loads(path.read_bytes())
        row["script_sha256"] = "0"*64
        path.write_bytes(historic._canonical(row))
    elif damage == "cancelled":
        (journal / (op + ".cancel.json")).write_bytes(b'{"cancelled":true}')
    elif damage == "symlink-journal-record":
        path = journal / (op + ".intent.json")
        path.rename(path.with_suffix(".retained"))
        path.symlink_to(path.with_suffix(".retained"))
    elif damage == "hardlinked-journal-record":
        path = journal / (op + ".intent.json")
        os.link(path, journal / "duplicate-linked-intent")
    elif damage == "reordered-operations":
        witness["commands"].reverse()
        proof.write_bytes(historic._canonical(witness) + b"\n")
        data[5] = sha(proof.read_bytes())
    else:
        proof.write_bytes(proof.read_bytes().replace(
            b'"commands":', b'"commands":[],"commands":'))
        data[5] = sha(proof.read_bytes())
    with pytest.raises((local.AuditHold, historic.HistoricalHold, OSError)):
        observe(data)
    assert not ssm.calls and not sts.calls


@pytest.mark.parametrize("damage", [
    "foreign-script", "foreign-target", "wrong-time", "terminal-status-mismatch",
])
def test_ssm_metadata_must_match_exact_original_record(tmp_path, monkeypatch, damage):
    data = prepared(tmp_path, monkeypatch)
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    if damage == "foreign-script":
        ssm.script_override = "rm -rf /not-allowed"
    elif damage == "foreign-target":
        ssm.target_override = "i-fffffffffffffffff"
    elif damage == "wrong-time":
        ssm.time_override = datetime(2026, 10, 11, tzinfo=timezone.utc)
    else:
        ssm.status_override = "Cancelled"
    with pytest.raises(historic.HistoricalHold):
        observe(data)
    assert [call[0] for call in ssm.calls] == ["list_commands"] or (
        damage == "terminal-status-mismatch" and
        [call[0] for call in ssm.calls] ==
        ["list_commands", "get_command_invocation"])


@pytest.mark.parametrize("damage", ["wrong-region", "wrong-account"])
def test_wrong_aws_identity_does_not_query_ssm(tmp_path, monkeypatch, damage):
    data = prepared(tmp_path, monkeypatch)
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    region = "us-west-2" if damage == "wrong-region" else "us-east-1"
    if damage == "wrong-account":
        sts.account = "000000000000"
    with pytest.raises(historic.HistoricalHold, match="AWS credential"):
        historic.inspect(root, approvals=approvals,
                         expected_evidence_sha256=digest,
                         journal_directory=str(journal), ssm_client=ssm,
                         sts_client=sts, aws_region=region)
    assert not ssm.calls


def test_missing_original_root_journal_is_hold_without_creating_it(tmp_path):
    journal = tmp_path / "not-present-journal"
    with pytest.raises((historic.HistoricalHold, OSError)):
        with historic._journal(journal):
            pass
    assert not journal.exists()



def test_real_ssm_client_region_cannot_be_spoofed_by_caller(tmp_path, monkeypatch):
    data = prepared(tmp_path, monkeypatch)
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    ssm.meta.region_name = "us-west-2"
    with pytest.raises(historic.HistoricalHold, match="credential account/region"):
        observe(data)
    assert not ssm.calls


def test_protected_original_witness_change_during_aws_readback_is_hold(
        tmp_path, monkeypatch):
    data = prepared(tmp_path, monkeypatch)
    root, approvals, journal, witness, proof, digest, ssm, sts = data
    original = ssm.get_command_invocation

    def mutate_after_first_existing_read(**kwargs):
        result = original(**kwargs)
        # Intentional test fixture mutation, never performed by the auditor.
        altered = json.loads(proof.read_bytes())
        altered["commands"][0]["script_sha256"] = "f"*64
        proof.write_bytes(historic._canonical(altered) + b"\n")
        return result

    ssm.get_command_invocation = mutate_after_first_existing_read
    with pytest.raises(historic.HistoricalHold, match="evidence digest"):
        observe(data)
    assert "send_command" not in [name for name, _ in ssm.calls]
