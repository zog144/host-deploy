from botocore.exceptions import ClientError
import pytest

from zog.host_deploy.runner import Host


class Mutation:
    def __init__(self, identifier="command-1"):
        self.identifier = identifier
        self.calls = []

    def send_command(self, **kwargs):
        self.calls.append(kwargs)
        return {"Command": {"CommandId": self.identifier}}


class Observe:
    def __init__(self, values):
        self.values = list(values)
        self.calls = []

    def get_command_invocation(self, **kwargs):
        self.calls.append(kwargs)
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def host(mutation, observe):
    value = Host.__new__(Host)
    value.instance = "i-test"
    value.ssm_mutation = mutation
    value.ssm = observe
    value.commands = []
    value.on_command = None
    return value


def test_submit_command_returns_identity_without_waiting():
    mutation = Mutation("command-123")
    observe = Observe([])
    value = host(mutation, observe)
    callbacks = []
    value.on_command = lambda: callbacks.append(list(value.commands))

    identifier = value.submit_command("echo safe", seconds=45)

    assert identifier == "command-123"
    assert value.commands == ["command-123"]
    assert callbacks == [["command-123"]]
    assert len(mutation.calls) == 1
    assert observe.calls == []
    assert mutation.calls[0]["InstanceIds"] == ["i-test"]
    assert mutation.calls[0]["Parameters"]["executionTimeout"] == ["45"]


def test_wait_command_observes_existing_identity_without_resubmission(monkeypatch):
    missing = ClientError(
        {"Error": {"Code": "InvocationDoesNotExist", "Message": "not visible"}},
        "GetCommandInvocation",
    )
    mutation = Mutation("must-not-be-used")
    observe = Observe(
        [
            missing,
            {"Status": "InProgress", "StandardOutputContent": ""},
            {"Status": "Success", "StandardOutputContent": "done\n"},
        ]
    )
    value = host(mutation, observe)
    monkeypatch.setattr("zog.host_deploy.runner.time.sleep", lambda seconds: None)

    assert value.wait_command("existing-command", seconds=1) == "done"
    assert mutation.calls == []
    assert all(call["CommandId"] == "existing-command" for call in observe.calls)


def test_command_remains_submit_then_wait_compatible(monkeypatch):
    mutation = Mutation("command-compat")
    observe = Observe(
        [{"Status": "Success", "StandardOutputContent": "ok", "StandardErrorContent": ""}]
    )
    value = host(mutation, observe)
    monkeypatch.setattr("zog.host_deploy.runner.time.sleep", lambda seconds: None)

    assert value.command("true", seconds=12) == "ok"
    assert value.commands == ["command-compat"]
    assert len(mutation.calls) == 1
    assert len(observe.calls) == 1


def test_wait_command_surfaces_terminal_failure(monkeypatch):
    mutation = Mutation()
    observe = Observe(
        [{"Status": "Failed", "StandardOutputContent": "", "StandardErrorContent": "bad"}]
    )
    value = host(mutation, observe)
    monkeypatch.setattr("zog.host_deploy.runner.time.sleep", lambda seconds: None)

    with pytest.raises(RuntimeError, match="command-x Failed: bad"):
        value.wait_command("command-x", seconds=1)


def test_submit_command_rejects_missing_command_identity():
    value = host(Mutation(""), Observe([]))
    with pytest.raises(RuntimeError, match="bounded command identity"):
        value.submit_command("true")


def test_adopted_host_commands_are_prefixed_with_exact_ownership_epoch_guard():
    mutation = Mutation("command-guarded")
    value = host(mutation, Observe([]))
    value.ownership_guard = {
        "schema": 1,
        "owner": "host-deploy-gateway",
        "workspace_id": "0123456789abcdeffedcba9876543210",
        "instance_id": "i-0123456789abcdef0",
        "account_id": "123456789012",
        "region": "us-east-1",
        "ownership_epoch": "a1b2c3d4e5f6478890abcdef12345678",
        "adoption_operation_id": "a1b2c3d4e5f6478890abcdef12345678",
    }

    value.submit_command("echo protected", seconds=30)

    script = mutation.calls[0]["Parameters"]["commands"][0]
    assert "/var/lib/host-deploy/ownership.json" in script
    assert "ownership epoch mismatch" in script
    assert "a1b2c3d4e5f6478890abcdef12345678" in script
    assert script.endswith("\necho protected")
