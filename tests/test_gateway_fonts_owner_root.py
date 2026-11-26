"""Real root-control Task C journal integration. Run only as root; no AWS."""
import os
import subprocess
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



def test_current_controller_preflight_uses_fixed_safe_directory_for_cross_uid_git(
        tmp_path, monkeypatch):
    """Real root SSM observer with a privately owned UID 24201 checkout.

    A clean environment without this exact safe.directory fails Git's
    dubious-ownership check as root. Ambient GIT_DIR/WORK_TREE/CONFIG_COUNT
    must never redirect a protected current Project's source revision.
    """
    from test_gateway_project_current import intent, git
    root, source, controller = project(tmp_path)
    spec, record = selected(root, controller, historic=False)
    request = intent("7" * 32)
    binding = project_current.binding(request, record, spec, target())
    expected_revision = git(source, "rev-parse", "HEAD")
    # Restrict changes to an exclusively disposable fixture tree. The
    # selected Project belongs to its own non-root application identity.
    for directory, directories, filenames in os.walk(root):
        os.chown(directory, 24201, 24201)
        for name in filenames:
            os.chown(os.path.join(directory, name), 24201, 24201)
    assert root.stat().st_uid == source.stat().st_uid == 24201
    assert controller.stat().st_uid == 24201

    foreign = tmp_path / "foreign-repo"
    foreign.mkdir()
    git(foreign, "init", "-q")
    git(foreign, "config", "user.email", "test@example.invalid")
    git(foreign, "config", "user.name", "Test")
    (foreign / "unexpected.txt").write_text("wrong source")
    git(foreign, "add", ".")
    git(foreign, "commit", "-qm", "unselected commit")
    foreign_revision = git(foreign, "rev-parse", "HEAD")
    assert foreign_revision != expected_revision

    # The exact FD-based Git command must resolve the real source even
    # when invoked by root on a Project-owned checkout. The only allowed
    # Git safe.directory is the validated frozen Project's source path.
    script = project_current.remote_script(binding)
    polluted = {
        **os.environ,
        "GIT_DIR": str(foreign / ".git"),
        "GIT_WORK_TREE": str(source),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(foreign),
    }
    completed = subprocess.run(
        script, shell=True, text=True, capture_output=True,
        env=polluted, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert expected_revision in completed.stdout
    assert foreign_revision not in completed.stdout
    assert "dubious ownership" not in completed.stderr
    assert controller.read_bytes() == __import__(
        "zog.host_deploy.existing_project_runtime", fromlist=["expected_bytes"]).expected_bytes(spec)
