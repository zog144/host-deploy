"""Cross-owner local trusted Host SSM journal contract (no AWS/native activation)."""
import inspect

import pytest
from zog.root_control import task_c_trusted_host as root
from zog.host_deploy.gateway import trusted_host_submission as gateway
from zog.host_deploy.gateway import generic_pipeline as pipeline


def _target():
    return {"instance_id":"i-0123456789abcdef0","region":"us-east-1",
            "account_id":"123456789012"}


def test_root_control_local_journal_accepts_exact_fixed_gateway_operation():
    operation="a"*32
    sha="b"*64
    script="python3 -m zog.image_build.remote --frozen-request"
    selected=root.intent(operation_id=operation,request_sha256=sha,
                         script=script,target=_target(),seconds=120)
    assert selected["schema"]==root.SCHEMA
    assert selected["operation_id"]==operation
    assert selected["request_sha256"]==sha
    assert selected["target"]==_target()
    assert selected["document"]==gateway.DOCUMENT=="AWS-RunShellScript"
    assert selected["execution_timeout_seconds"]==120
    assert root.DEFAULT_DIRECTORY=="/var/lib/zog-task-c/operations"
    assert root.LocalTaskCJournal.submit_once is not None


@pytest.mark.parametrize("changed",["document","target","operation","timeout","script"])
def test_root_counterpart_rejects_unreviewed_source_or_execution_shape(changed):
    args=dict(operation_id="a"*32,request_sha256="b"*64,
              script="fixed-server-generated-command",target=_target(),seconds=120)
    if changed=="document":
        # Neither interface has a caller-provided SSM document argument.
        with pytest.raises(TypeError):
            root.intent(**args,document="AWS-RunDocument")
        return
    elif changed=="target":args["target"]["instance_id"]="i-unapproved"
    elif changed=="operation":args["operation_id"]="escape-command"
    elif changed=="timeout":args["seconds"]=21601
    else:args["script"]=""
    with pytest.raises(root.SubmissionBlocked):
        root.intent(**args)


def test_shared_host_submission_and_root_journal_deny_automatic_retry():
    root_source=inspect.getsource(root.LocalTaskCJournal.submit_once)
    active=inspect.getsource(pipeline.advance)
    assert "with self.locked():" in root_source
    assert "_write_once(self.fd, names[0], selected)" in root_source
    assert root_source.index("_write_once(self.fd, names[0], selected)") < (
           root_source.index("sender.submit_command("))
    assert "send_intent.claim(" in active
    assert active.index("send_intent.claim(") < active.index("trusted.submit_once(")
    assert "submit_once(" in inspect.getsource(gateway)
    assert "graphics_owner_ipc" not in active
    assert "S3" not in inspect.getsource(gateway)
