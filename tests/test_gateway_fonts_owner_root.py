"""Real root-control Task C journal integration. Run only as root; no AWS."""
import os
import pytest

from zog.host_deploy.gateway import fonts_owner_sender, project_current
from zog.host_deploy.gateway.ledger import (
    load_dispatch, mark_dispatch_submitting, prepare_dispatch,
)
from zog.root_control.task_c_trusted_host import (
    LocalTaskCJournal, SubmissionBlocked, SCHEMA,
)
from test_gateway_simple_forward import approved, admit
from test_gateway_project_current import project, selected, target

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0, reason="root-control owner requires root-owned state"
)


def test_real_root_owner_journal_accepts_only_once_for_original_request(tmp_path):
    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller, historic=True)
    gateway = tmp_path / "gateway"
    request = approved()
    admit(gateway, request)
    binding = project_current.binding(request, record, spec, target())
    prepare_dispatch(gateway, request["request_id"], binding)
    owner_path = tmp_path / "operations"
    owner_path.mkdir(mode=0o700)
    factory = lambda: LocalTaskCJournal(owner_path)
    fonts_owner_sender.ready(request["request_id"], journal_factory=factory)
    mark_dispatch_submitting(gateway, request["request_id"])
    selected_script = project_current.remote_script(binding)
    calls = []
    class Sender:
        instance = target()["instance_id"]
        def submit_command(self, script, *, seconds):
            calls.append((script, seconds))
            return "root-owner-command-123"
    sender = Sender()
    returned = fonts_owner_sender.submit_once(
        gateway, request["request_id"], binding=binding,
        configuration=target(), host=sender, script=selected_script,
        seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS, journal_factory=factory,
    )
    assert returned == "root-owner-command-123"
    assert calls == [(selected_script, fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS)]
    journal = factory()
    original, result, cancel = journal.inspect(request["request_id"])
    assert original["schema"] == SCHEMA
    assert original["operation_id"] == request["request_id"]
    assert original["request_sha256"] == load_dispatch(
        gateway, request["request_id"])["request_sha256"]
    assert result["command_id"] == returned
    assert cancel is None
    journal.close()
    with pytest.raises(fonts_owner_sender.ProtectedOwnerUnavailable,
                       match="already claimed"):
        fonts_owner_sender.ready(request["request_id"], journal_factory=factory)
    with pytest.raises(SubmissionBlocked):
        fonts_owner_sender.submit_once(
            gateway, request["request_id"], binding=binding,
            configuration=target(), host=sender, script=selected_script,
            seconds=fonts_owner_sender.PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS, journal_factory=factory,
        )
    assert len(calls) == 1
