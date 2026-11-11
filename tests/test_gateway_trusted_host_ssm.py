"""Trusted host-registry SSM path: fixed documents, local claims, no retry."""
import copy
import inspect
import pytest

from zog.host_deploy.gateway import trusted_host_submission as trusted
from zog.host_deploy.gateway import generic_pipeline as generic
from zog.host_deploy.gateway import graphics_operation_send_intent as intent
from test_gateway_generic_pipeline import GATEWAY, base, mock_environment


def test_fixed_command_and_compiler_host(monkeypatch):
    binding=base()
    step={"name":"submit"}
    stage={"source":binding["source"],
           "task_catalogue_identity":binding["task_catalogue_identity"],
           "remote_request":{"operation":"pipeline.submit"}}
    target={"instance_id":"i-0123456789abcdef0","region":"us-east-1",
            "account_id":"123456789012"}
    monkeypatch.setattr(trusted,"verify_current_target",lambda *_:target)
    monkeypatch.setattr(trusted,"remote_script",lambda _: "fixed-server-command")
    got,script=trusted.selected_command(None,binding,step,stage)
    assert got is target and script=="fixed-server-command"
    assert trusted.DOCUMENT=="AWS-RunShellScript"


@pytest.mark.parametrize("mode",["foreign-stage","foreign-source","foreign-catalogue",
                                   "arbitrary-operation","missing-task","target-change"])
def test_unapproved_task_or_command_denied_before_ssm(monkeypatch,mode):
    binding=base()
    step={"name":"submit"}
    stage={"source":binding["source"],
           "task_catalogue_identity":binding["task_catalogue_identity"],
           "remote_request":{"operation":"pipeline.submit"}}
    monkeypatch.setattr(trusted,"remote_script",lambda _:pytest.fail("remote command rendered"))
    monkeypatch.setattr(trusted,"verify_current_target",lambda *_:{
        "instance_id":"i-0123456789abcdef0","region":"us-east-1"})
    if mode=="foreign-stage":step["name"]="unknown"
    elif mode=="foreign-source":stage["source"]={"repository":"foreign","revision":"f"*40}
    elif mode=="foreign-catalogue":stage["task_catalogue_identity"]="sha256:"+"0"*64
    elif mode=="arbitrary-operation":stage["remote_request"]["operation"]="shell.execute"
    elif mode=="missing-task":binding.pop("task")
    else:
        monkeypatch.setattr(trusted,"verify_current_target",lambda *_:{
            "instance_id":"unexpected","region":"us-east-1"})
    with pytest.raises(trusted.TrustedSubmissionDenied):
        trusted.selected_command(None,binding,step,stage)


def test_submit_once_uses_exact_selected_document_interface_and_timeout():
    calls=[]
    class Host:
        def submit_command(self,script,seconds):
            calls.append((script,seconds))
            return "command-123"
    assert trusted.submit_once(Host(),script="fixed",seconds=generic.CONTROL_TIMEOUT_SECONDS)=="command-123"
    assert calls==[("fixed",generic.CONTROL_TIMEOUT_SECONDS)]
    for seconds in (60,-1,"120"):
        with pytest.raises(trusted.TrustedSubmissionDenied):
            trusted.submit_once(Host(),script="fixed",seconds=seconds)
    assert len(calls)==1


def test_trusted_local_journal_survives_lost_ack_and_reboot(tmp_path,monkeypatch):
    Host,calls=mock_environment(monkeypatch,lost_reply=True)
    monkeypatch.setattr(trusted,"selected_command",lambda root,binding,step,stage:
                        ({"instance_id":"i-0123456789abcdef0",
                          "region":"us-east-1"},stage["remote_request"]["operation"]))
    first=generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert first["stages"][0]["phase"]=="prepared"
    with pytest.raises(TimeoutError):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    uncertain=generic.status(tmp_path,GATEWAY)
    assert uncertain["phase"]=="uncertain"
    assert len([c for c in calls if c[0]=="submit"])==1
    assert generic.advance(tmp_path,GATEWAY,host_factory=Host)==uncertain
    assert len([c for c in calls if c[0]=="submit"])==1


def test_no_graphical_owner_broker_signing_or_s3_on_active_gateway_route():
    source=inspect.getsource(generic.advance)
    assert "_selected_protected_owner_preflight(" not in source
    assert "_selected_protected_owner_sender(" not in source
    assert "graphics_owner_ipc" not in source
    assert "trusted.selected_command(" in source
    assert "trusted.submit_once(" in source
    assert source.index("send_intent.claim(")<source.index("trusted.submit_once(")
    assert "host.inspect_command(" in source
    adapter=inspect.getsource(trusted)
    for forbidden in ("boto3", "PutObject", "ObjectLock",
                      "signed_approval","S3AppendOnlyCheckpoint",
                      "GetObjectOnly","broker-private.key"):
        assert forbidden not in adapter
