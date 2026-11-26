"""Retained Fonts request -> protected root-control owner; no AWS submission.

These tests exercise the ACTUAL host-deploy gateway and CLI dispatch path
against a stateful fake of root-control's LocalTaskCJournal interface.
Root-control separately tests the root-only fsynced journal on a root runner.
"""
from contextlib import nullcontext

import pytest

from zog.host_deploy.gateway import (
    fonts_owner_sender, image_build_dispatch, image_build_execution,
    project_current, simple_forward,
)
from zog.host_deploy.gateway.ledger import (
    load_dispatch, load_request, prepare_dispatch,
)
from test_gateway_project_current import (
    project, selected, target,
)
from test_gateway_simple_forward import admit, approved


class OwnerJournal:
    intents = {}
    commands = {}
    opened = 0

    def __init__(self):
        type(self).opened += 1

    @classmethod
    def reset(cls):
        cls.intents = {}
        cls.commands = {}
        cls.opened = 0

    def inspect(self, operation_id):
        return (self.intents.get(operation_id),
                self.commands.get(operation_id), None)

    def submit_once(self, *, operation_id, request_sha256, script, target,
                    seconds, sender):
        if operation_id in self.intents:
            raise RuntimeError("protected root owner already claimed this operation")
        assert request_sha256 and len(request_sha256) == 64
        assert target == {
            "instance_id": "i-0123456789abcdef0",
            "region": "us-east-1",
            "account_id": "123456789012",
        }
        # Model the real protected root journal's durable intent BEFORE send.
        self.intents[operation_id] = {
            "request_sha256": request_sha256, "target": target, "script": script,
        }
        command_id = sender.submit_command(script, seconds=seconds)
        self.commands[operation_id] = {"command_id": command_id}
        return command_id

    def close(self):
        pass


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    project_root, source, controller = project(tmp_path)
    spec, record = selected(project_root, controller, historic=True)
    root = tmp_path / "gateway"
    request = approved()
    admit(root, request)
    selected_host = target()
    binding = project_current.binding(request, record, spec, selected_host)
    prepare_dispatch(root, request["request_id"], binding)
    monkeypatch.setattr(simple_forward, "verify_current_target",
                        lambda gateway, value: selected_host)
    # The retained dispatch is inspected through an already reviewed
    # selection. No new issue, admission, lane record or submission.
    OwnerJournal.reset()
    monkeypatch.setattr(fonts_owner_sender, "_owner_factory",
                        lambda journal_factory: OwnerJournal)
    calls = []
    class Host:
        def __init__(self, configuration):
            assert configuration == selected_host
            self.instance = configuration["instance_id"]

        def submit_command(self, script, seconds):
            calls.append((script, seconds))
            return "owner-command-existing-request"

        def inspect_command(self, identifier):
            return None

    return root, request["request_id"], binding, Host, calls


def test_dispatch_submit_uses_root_owner_for_original_prepared_request(prepared):
    root, request_id, binding, Host, calls = prepared
    assert load_dispatch(root, request_id)["phase"] == "prepared"
    before = load_request(root, request_id)
    state, dispatch = image_build_execution.submit_prepared(
        root, request_id, host_factory=Host)
    assert state["request_id"] == request_id == before["request_id"]
    assert state["request_sha256"] == before["request_sha256"]
    assert dispatch["phase"] == "submitted"
    assert dispatch["command_id"] == "owner-command-existing-request"
    assert len(calls) == 1
    assert len(OwnerJournal.intents) == 1
    assert OwnerJournal.intents[request_id]["request_sha256"] == before["request_sha256"]
    assert len(OwnerJournal.commands) == 1
    # A second invocation reads retained evidence, never sends another SSM.
    again = image_build_execution.submit_prepared(root, request_id, host_factory=Host)
    assert again[1] == dispatch
    assert len(calls) == 1


def test_owner_unavailable_keeps_original_prepared_without_ssm_intent(prepared,
                                                                   monkeypatch):
    root, request_id, binding, Host, calls = prepared
    def unavailable(*args, **kwargs):
        raise fonts_owner_sender.ProtectedOwnerUnavailable(
            "protected root-control owner is not installed")
    monkeypatch.setattr(fonts_owner_sender, "ready", unavailable)
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable):
        image_build_execution.submit_prepared(root, request_id, host_factory=Host)
    assert load_dispatch(root, request_id)["phase"] == "prepared"
    assert not OwnerJournal.intents
    assert not calls


def test_lost_owner_ssm_acknowledgement_remains_uncertain_with_no_resend(prepared):
    root, request_id, binding, Host, calls = prepared
    class Lost(Host):
        def submit_command(self, script, seconds):
            calls.append((script, seconds))
            raise TimeoutError("SSM result acknowledgement lost")
    with pytest.raises(TimeoutError, match="acknowledgement"):
        image_build_execution.submit_prepared(root, request_id, host_factory=Lost)
    assert load_dispatch(root, request_id)["phase"] == "submission_uncertain"
    assert request_id in OwnerJournal.intents
    assert request_id not in OwnerJournal.commands
    with pytest.raises(RuntimeError, match="reconcile existing evidence"):
        image_build_execution.submit_prepared(root, request_id, host_factory=Host)
    assert len(calls) == 1


def test_protected_owner_rejects_forged_request_or_different_target(prepared):
    root, request_id, binding, Host, calls = prepared
    from zog.host_deploy.gateway.ledger import mark_dispatch_submitting
    mark_dispatch_submitting(root, request_id)
    script = project_current.remote_script(binding)
    wrong = dict(binding, project_root="/tmp/foreign-project")
    with pytest.raises((RuntimeError, ValueError)):
        fonts_owner_sender.submit_once(
            root, request_id, binding=wrong, configuration=target(),
            host=Host(target()), script=script, seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
            journal_factory=OwnerJournal)
    different = dict(target(), instance_id="i-abcdef01234567890")
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable):
        fonts_owner_sender.submit_once(
            root, request_id, binding=binding, configuration=different,
            host=Host(target()), script=script, seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
            journal_factory=OwnerJournal)
    # A new current-Project controller hash is part of the frozen binding.
    # An external caller cannot change the selected controller in send intent.
    assert len(binding["controller_sha256"]) == 64
    bad_checksum = dict(binding, controller_sha256="f" * 64)
    with pytest.raises((RuntimeError, ValueError)):
        fonts_owner_sender.submit_once(
            root, request_id, binding=bad_checksum, configuration=target(),
            host=Host(target()), script=script,
            seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
            journal_factory=OwnerJournal)
    assert OwnerJournal.intents == {}
    assert calls == []


def test_current_project_once_only_owner_refuses_replay_after_submitted(prepared):
    root, request_id, binding, Host, calls = prepared
    # Already authorized new schema-5 binding, NOT a November 14 migration.
    assert len(binding["controller_sha256"]) == 64
    first = simple_forward.advance(root, request_id, host_factory=Host)
    assert first["phase"] == "submitted"
    assert len(calls) == 1
    assert request_id in OwnerJournal.intents
    assert request_id in OwnerJournal.commands
    before = OwnerJournal.intents[request_id].copy()

    # Duplicate issue/SQS delivery or a restarted Gateway is observation,
    # never a second SSM send or a fresh root-control intent.
    repeated = simple_forward.advance(root, request_id, host_factory=Host)
    assert repeated["phase"] == "submitted"
    assert len(calls) == 1
    assert OwnerJournal.intents[request_id] == before
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable,
                       match="already claimed"):
        fonts_owner_sender.ready(request_id, journal_factory=OwnerJournal)
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable,
                       match="admission or send intent"):
        fonts_owner_sender.submit_once(
            root, request_id, binding=binding, configuration=target(),
            host=Host(target()), script=project_current.remote_script(binding),
            seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
            journal_factory=OwnerJournal)
    assert len(calls) == 1


def test_no_unprotected_send_when_root_control_owner_missing(prepared,
                                                            monkeypatch):
    root, request_id, binding, Host, calls = prepared
    def missing(factory):
        raise fonts_owner_sender.ProtectedOwnerUnavailable(
            "protected root-control Task C owner is not installed")
    monkeypatch.setattr(fonts_owner_sender, "_owner_factory", missing)
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable):
        simple_forward.advance(root, request_id, host_factory=Host)
    assert load_dispatch(root, request_id)["phase"] == "prepared"
    assert calls == []


def test_owner_source_contract_has_no_second_s3_approval_or_shell_relay():
    from zog.host_deploy.gateway import fonts_owner_sender as selected
    import inspect
    source = inspect.getsource(selected)
    assert "LocalTaskCJournal" in source
    assert "journal.submit_once(" in source
    assert "state[\"request_sha256\"]" in source
    assert "gateway_root" in source
    assert "sender=host" in source
    assert "SSM" in source
    assert "S3" not in source
    assert "compiler-selection.json" not in source
    assert "Host.submit_command(" not in inspect.getsource(simple_forward.advance)



def test_protected_inspection_owner_rejects_forged_script_target_and_original_id(
        prepared):
    from zog.host_deploy.gateway import fonts_inspection_owner
    from zog.host_deploy.gateway.project_current_observation import (
        read_only_observation_script,
    )
    from zog.host_deploy.gateway.ledger import (
        mark_dispatch_submitting, mark_dispatch_submitted,
    )
    root, request_id, binding, Host, calls = prepared
    mark_dispatch_submitting(root, request_id)
    mark_dispatch_submitted(root, request_id, "original-build-command")
    script = read_only_observation_script(
        binding["project_root"], binding["python_executable"], request_id)
    host = Host(target())
    args = dict(
        binding=binding, target=binding["target"],
        original_command_id="original-build-command",
        pipeline_id=None, script=script, host=host)
    approved = fonts_inspection_owner._validation(root, request_id, **args)
    assert approved["target"] == binding["target"]
    assert approved["project_root"] == binding["project_root"]
    assert approved["original_command_id"] == "original-build-command"
    assert approved["timeout_seconds"] == 120
    import hashlib
    assert approved["script_sha256"] == hashlib.sha256(
        script.encode("utf-8")).hexdigest()
    for altered in (
        dict(args, script=script + " ; echo unreviewed"),
        dict(args, target={**binding["target"], "instance_id": "i-aaaaaaaaaaaaaaaaa"}),
        dict(args, original_command_id="forged-command"),
        dict(args, binding={**binding, "project_root": "/tmp/foreign"}),
    ):
        with pytest.raises((RuntimeError, ValueError)):
            fonts_inspection_owner._validation(
                root, request_id, **altered)
    assert calls == []



def test_retained_digestless_prepared_dispatch_cannot_create_new_owner_intent(
        tmp_path, monkeypatch):
    """Old frozen prepared != authority for a first unguarded SSM send."""
    project_root, source, controller = project(tmp_path)
    spec, record = selected(project_root, controller, historic=True)
    root = tmp_path / "gateway"
    request = approved()
    admit(root, request)
    request_id = request["request_id"]
    binding = project_current.binding(request, record, spec, target())
    historical = dict(binding)
    historical.pop("controller_sha256")
    # Preserve old binding shape; do NOT rewrite a legacy dispatch to add
    # a hash which did not exist when it was durably admitted.
    assert project_current.validate(historical) == historical
    prepare_dispatch(root, request_id, historical)
    request_path = root / "requests" / request_id
    frozen = {name: (request_path / name).read_bytes()
              for name in ("request.json", "dispatch.json")
              if (request_path / name).exists()}
    before_dispatch = load_dispatch(root, request_id)
    before_request = load_request(root, request_id)
    OwnerJournal.reset()
    monkeypatch.setattr(simple_forward, "verify_current_target",
                        lambda *_: target())
    monkeypatch.setattr(fonts_owner_sender, "_owner_factory",
                        lambda _: OwnerJournal)
    calls = []

    class ForbiddenHost:
        def __init__(self, *args, **kwargs):
            pytest.fail("historical prepared dispatch constructed a Host")
        def submit_command(self, *args, **kwargs):
            calls.append((args, kwargs))
            pytest.fail("historical prepared dispatch sent SSM")

    with pytest.raises(simple_forward.ForwardingDenied, match="digestless historical prepared"):
        simple_forward.advance(root, request_id, host_factory=ForbiddenHost)
    assert load_dispatch(root, request_id) == before_dispatch
    assert load_request(root, request_id) == before_request
    assert all((request_path / name).read_bytes() == raw
               for name, raw in frozen.items())
    assert OwnerJournal.intents == {}
    assert OwnerJournal.commands == {}
    assert OwnerJournal.opened == 0
    assert calls == []

    # Even a caller that already holds a "submitting" dispatch cannot
    # bypass the non-sending Gateway path to create a new root-owner intent.
    from zog.host_deploy.gateway.ledger import mark_dispatch_submitting
    mark_dispatch_submitting(root, request_id)
    sending_snapshot = load_dispatch(root, request_id)
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable,
                       match="digestless historical"):
        fonts_owner_sender.submit_once(
            root, request_id, binding=historical, configuration=target(),
            host=ForbiddenHost.__new__(ForbiddenHost),
            script=project_current.remote_script(historical),
            seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
            journal_factory=OwnerJournal)
    assert load_dispatch(root, request_id) == sending_snapshot
    assert OwnerJournal.intents == {}
    assert OwnerJournal.commands == {}
    assert OwnerJournal.opened == 0
    assert calls == []



def test_retained_digestless_submitted_dispatch_only_inspects_original_command(
        tmp_path, monkeypatch):
    """Old submitted record is readable; it never becomes new send authority."""
    project_root, source, controller = project(tmp_path)
    spec, record = selected(project_root, controller, historic=True)
    root = tmp_path / "gateway"
    request = approved()
    admit(root, request)
    request_id = request["request_id"]
    binding = project_current.binding(request, record, spec, target())
    frozen = dict(binding)
    frozen.pop("controller_sha256")
    prepare_dispatch(root, request_id, frozen)
    from zog.host_deploy.gateway.ledger import (
        mark_dispatch_submitting, mark_dispatch_submitted,
    )
    mark_dispatch_submitting(root, request_id)
    mark_dispatch_submitted(root, request_id, "retained-original-command")
    before = load_dispatch(root, request_id)
    before_state = load_request(root, request_id)
    monkeypatch.setattr(simple_forward, "verify_current_target",
                        lambda *_: target())
    OwnerJournal.reset()
    monkeypatch.setattr(fonts_owner_sender, "_owner_factory",
                        lambda _: OwnerJournal)
    calls = []

    class ReadbackOnlyHost:
        instance = target()["instance_id"]
        def __init__(self, configuration):
            assert configuration == target()
        def submit_command(self, *args, **kwargs):
            pytest.fail("historical submitted operation was replayed")
        def inspect_command(self, command_id):
            calls.append(command_id)
            return None

    result = simple_forward.advance(root, request_id,
                                    host_factory=ReadbackOnlyHost)
    assert result == {
        "request_id": request_id, "phase": "submitted",
        "command_id": "retained-original-command",
        "status": "not-yet-visible",
    }
    assert calls == ["retained-original-command"]
    assert load_dispatch(root, request_id) == before
    assert load_request(root, request_id) == before_state
    assert not OwnerJournal.intents and not OwnerJournal.commands
    assert OwnerJournal.opened == 0
