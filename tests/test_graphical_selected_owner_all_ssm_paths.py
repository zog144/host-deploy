"""Independently verify every selected graphical SSM send route at fixed owner head.

Root owner's synthetic external ledger is separate from gateway journal. No
native install, SSM send, IAM grant, state volume or real signing key.
"""
import copy
import importlib.util
import inspect
import pathlib
import sys
import threading
import pytest

from zog.host_deploy.gateway import generic_pipeline as generic
from zog.host_deploy.gateway import image_build_execution as legacy
from zog.host_deploy.gateway import graphics_protected_owner_handoff as bridge

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from test_gateway_generic_pipeline import GATEWAY,mock_environment
from test_graphics_selected_owner_direct_route_denial import data

ROOT=pathlib.Path(__file__).resolve().parents[1]
path=ROOT/"companion-root-control/src/zog/root_control/graphical_operation_owner_source.py"
spec=importlib.util.spec_from_file_location("selected_graphical_root_owner",path)
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def selected():
    binding,step,protected=data()
    request=bridge.selected_owner_request(
        binding,GATEWAY,step,protected_selection=protected)
    return owner.validate_request(request)


def independent_backend(request, sender):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ledger=owner.SyntheticExternalLedger(
        owner.scope_from_request(request),
        independently_approved_operations={request["operation_id"]:owner.digest(request)})
    signer=Ed25519PrivateKey.generate()
    return ledger,owner.SourceOnlyProtectedOwner(
        ledger,test_sender=sender,test_signer=signer),signer


def test_missing_sender_denies_before_any_preflight_host_or_ssm(tmp_path,monkeypatch):
    Host,events=mock_environment(monkeypatch)
    # mock_environment stubs both selected owner operations; restore true
    # fail-closed defaults with no native protected owner.
    original_send=generic.__dict__["_selected_protected_owner_sender"]
    original_preflight=generic.__dict__["_selected_protected_owner_preflight"]
    from inspect import getsourcelines
    # A regular runtime error must precede any preflight Host.command.
    def deny_send(*args):raise RuntimeError("protected graphical operation owner required")
    def deny_preflight(*args):raise AssertionError("preflight must not run before deny")
    monkeypatch.setattr(generic,"_selected_protected_owner_sender",deny_send)
    monkeypatch.setattr(generic,"_selected_protected_owner_preflight",deny_preflight)
    generic.advance(tmp_path,GATEWAY,host_factory=Host)
    with pytest.raises(RuntimeError,match="protected graphical operation owner"):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert events == []


def test_sender_injected_without_protected_preflight_cannot_use_direct_host_command(tmp_path,monkeypatch):
    Host,events=mock_environment(monkeypatch)
    def deny_preflight(*args):
        raise RuntimeError("protected graphical preflight owner required")
    monkeypatch.setattr(generic,"_selected_protected_owner_preflight",deny_preflight)
    monkeypatch.setattr(generic,"producer_runtime_preflight",
                        lambda *args:pytest.fail("unprotected Host.command"))
    generic.advance(tmp_path,GATEWAY,host_factory=Host)
    with pytest.raises(RuntimeError,match="protected graphical preflight"):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert events == []


def test_unattributed_preflight_response_denies_without_sending(tmp_path,monkeypatch):
    Host,events=mock_environment(monkeypatch)
    monkeypatch.setattr(generic,"_selected_protected_owner_preflight",
                        lambda *a: lambda: {"ready":True,"mutation":False})
    generic.advance(tmp_path,GATEWAY,host_factory=Host)
    with pytest.raises(RuntimeError,match="protected graphical preflight evidence"):
        generic.advance(tmp_path,GATEWAY,host_factory=Host)
    assert events==[]


def test_legacy_graphical_submit_denied_before_any_host_factory(monkeypatch,tmp_path):
    from zog.host_deploy.gateway import image_build_execution as legacy
    monkeypatch.setattr(legacy,"load_dispatch",lambda *a:{"phase":"prepared"})
    monkeypatch.setattr(legacy,"_binding",
                        lambda *a:{"remote_request":{"operation":"pipeline.submit"}})
    monkeypatch.setattr(legacy,"load_request",
                        lambda *a:{"request":{"operation":"build.submit",
                          "parameters":{"task":"graphics-fonts-image-v1"}}})
    with pytest.raises(RuntimeError,match="legacy SSM route denied"):
        legacy.submit_prepared(
            tmp_path,GATEWAY,
            host_factory=lambda _:pytest.fail("legacy Host created"))


def test_owner_external_claim_blocks_gateway_restore_and_lost_ack():
    request=selected()
    calls=[]
    def lost_ack(row):
        calls.append(row)
        raise TimeoutError("SendCommand acknowledgement lost")
    ledger,first,signer=independent_backend(request,lost_ack)
    with pytest.raises(TimeoutError):
        first.submit_once(request)
    assert ledger.claims[request["operation_id"]]["outcome"]=="CLAIMED_UNCERTAIN"
    # Restore gateway journal + request + local send-intent to any old snapshot.
    restored=copy.deepcopy(request)
    restarted=owner.SourceOnlyProtectedOwner(
        ledger,test_sender=lambda _:pytest.fail("second SSM command"),
        test_signer=signer)
    with pytest.raises(owner.OperationDenied):
        restarted.submit_once(restored)
    assert len(calls)==1
    response=restarted.read_signed(request=restored,nonce="a"*48)
    assert owner.verify_signed_observation(
        response,expected_nonce="a"*48,original_request=request,
        externally_pinned_public_key=restarted.public_key,
        externally_pinned_key_sha256="sha256:"+__import__("hashlib").sha256(
            restarted.public_key).hexdigest(),minimum_sequence=1)["outcome"]=="CLAIMED_UNCERTAIN"


def test_concurrent_selected_gateway_claim_only_one_external_send():
    request=selected()
    calls=[]
    gate=threading.Event();release=threading.Event()
    def sender(row):
        calls.append(row)
        gate.set()
        assert release.wait(5)
        return "original-command"
    ledger,protected,signer=independent_backend(request,sender)
    outcomes=[]
    def submit():
        try:outcomes.append(protected.submit_once(request)["outcome"])
        except owner.OperationDenied:outcomes.append("DENIED")
    a=threading.Thread(target=submit);b=threading.Thread(target=submit)
    a.start();assert gate.wait(5);b.start();release.set()
    a.join(5);b.join(5)
    assert sorted(outcomes)==["DENIED","SENT_ORIGINAL"]
    assert len(calls)==1 and ledger.sequence==1


def test_signed_revoke_shares_selected_owner_lock_and_prohibits_replay():
    request=selected()
    sent=[]
    ledger,protected,signer=independent_backend(
        request,lambda row:sent.append(row) or "original-command")
    assert protected.submit_once(request)["outcome"]=="SENT_ORIGINAL"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    operator=Ed25519PrivateKey.generate()
    body={"schema":owner.REVOCATION_APPROVAL_SCHEMA,"approval_id":"a"*32,
          "scope_sha256":owner.digest(owner.scope_from_request(request)),
          "action":"revoke","expires_at":600}
    import base64
    grant={**body,"signature_ed25519":base64.b64encode(
        operator.sign(owner.REVOCATION_APPROVAL_DOMAIN+
                      owner.canonical(body))).decode("ascii")}
    pub=operator.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    assert protected.revoke_signed(
        owner.scope_from_request(request),grant,
        externally_pinned_operator_key=pub,
        expected_approval_id="a"*32,now=400)==2
    with pytest.raises(owner.OperationDenied):
        protected.submit_once(request)
    assert ledger.revoked and len(sent)==1


def test_selected_gateway_code_has_no_unprotected_preflight_or_send():
    source=inspect.getsource(generic.advance)
    assert "producer_runtime_preflight(host, stage_binding)" not in source
    assert "host.submit_command(" not in source
    assert source.index("_selected_protected_owner_sender(")<source.index(
        "protected_preflight()")
    # This module still has a host.inspect_command read, which isn't SendCommand.
    assert "host.inspect_command" in source


def test_complete_python_ssm_sendcommand_callsite_inventory_is_explicit():
    """Detect new SDK/method SSM write paths which bypass review.

    This inventory is not an IAM security boundary: approved nongraphical
    sender APIs still require separate native principal permissions.
    """
    import ast
    root=ROOT/"src/zog/host_deploy"
    seen={}
    for file in root.rglob("*.py"):
        tree=ast.parse(file.read_text())
        for node in ast.walk(tree):
            if (isinstance(node,ast.Call) and
                    isinstance(node.func,ast.Attribute) and
                    node.func.attr in {"send_command","submit_command"}):
                relative=str(file.relative_to(root))
                seen.setdefault(relative,[]).append(node.func.attr)
    assert {k:sorted(v) for k,v in seen.items()} == {
        "runner.py":["send_command","submit_command"],
        "station.py":["send_command"],
        "gateway/adoption.py":["submit_command"],
        "gateway/image_build_execution.py":["submit_command"],
        "gateway/toolchain_supervisor.py":["submit_command"],
    }
    # Explicitly reviewed boundary: none of the selected graphical stage
    # transitions may invoke a gateway Host command or SSM sender.
    assert "gateway/generic_pipeline.py" not in seen
    # Two additional SSM entry points are distinct fixed-purpose operations:
    # adoption writes a fixed ownership marker; station deployment selects
    # its reviewed packaged station_remote.py. They are NOT authority to
    # submit a graphical build. Actual AWS principal isolation still needed.
    adoption=(root/"gateway/adoption.py").read_text()
    station=(root/"station.py").read_text()
    assert "host.submit_command(_marker_write_script(marker), seconds=60)" in adoption
    assert "with_name('station_remote.py')" in station

