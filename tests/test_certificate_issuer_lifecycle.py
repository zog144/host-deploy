"""Selected renew/stage broker compatibility without privileged project access."""
from types import SimpleNamespace
import pytest

from zog.host_deploy.certificate_renewal import RenewalBlocked
from zog.host_deploy.certificate_issuer_lifecycle import SelectedIssuerController


class Broker:
    def __init__(self, socket):
        assert socket == "/run/zog/certify-lifecycle.sock"
        self.issued = 0
        self.launched = []
        self.replies = {}

    def issue_application_request_id(self):
        self.issued += 1
        return "r1-1-" + format(self.issued, "032x") + "-" + "a"*64

    def launch_application(self, application, *, program_name, request_id):
        self.launched.append((application, program_name, request_id))
        return SimpleNamespace(application=application, selected_program=program_name,
                               runtime_id="RUNTIME01")

    def application_request_result(self, request_id):
        return self.replies.get(request_id, {
            "request_id": request_id, "status": "unknown",
            "program": None, "runtime_id": None,
        })


def test_direct_selected_start_and_result_are_bound_to_original_request():
    broker = Broker("/run/zog/certify-lifecycle.sock")
    ctrl = SelectedIssuerController("/run/zog/certify-lifecycle.sock",
                                    client_factory=lambda path: broker)
    rid = ctrl.issue_application_request_id()
    assert ctrl.direct_selected_launch is True
    assert ctrl.application_request_result(rid) is None
    ctrl.request_application_launch("certify-manage", program_name="renew", request_id=rid)
    assert broker.launched == [("certify-manage", "renew", rid)]
    broker.replies[rid] = {"request_id": rid, "status": "satisfied",
                           "program": "renew", "runtime_id": "RUNTIME01"}
    outcome = ctrl.application_request_result(rid)
    assert outcome.request_id == rid and outcome.program_name == "renew"
    assert outcome.status == "satisfied" and outcome.operation == "launch"
    assert outcome.updated_at is None  # independent trusted journal required


def test_only_exact_selected_programs_are_allowed():
    broker = Broker("/run/zog/certify-lifecycle.sock")
    ctrl = SelectedIssuerController("/run/zog/certify-lifecycle.sock",
                                    client_factory=lambda _: broker)
    rid = ctrl.issue_application_request_id()
    for app, program in (
        ("station-access", "renew"), ("certify-manage", "issue"),
        ("certify-manage", "inspect"), ("certify-manage", "shell"),
    ):
        with pytest.raises(RenewalBlocked, match="selection-rejected"):
            ctrl.request_application_launch(app, program_name=program, request_id=rid)
    assert not broker.launched
    ctrl.request_application_launch("certify-manage", program_name="stage", request_id=rid)
    assert broker.launched[0][1] == "stage"


@pytest.mark.parametrize("invalid", [
    {"request_id": "wrong"},
    {"status": "satisfied", "program": "issue"},
    {"status": "unknown", "program": "stage"},
    {"status": "pending", "program": None},
    {"status": "served"},
    {"unexpected": "/root/private"},
])
def test_untrusted_broker_result_fails_closed(invalid):
    broker = Broker("/run/zog/certify-lifecycle.sock")
    ctrl = SelectedIssuerController("/run/zog/certify-lifecycle.sock",
                                    client_factory=lambda _: broker)
    rid = ctrl.issue_application_request_id()
    broker.replies[rid] = {**{"request_id": rid, "status": "satisfied",
                                "program": "renew", "runtime_id": "RUNTIME01"},
                           **invalid}
    with pytest.raises(RenewalBlocked):
        ctrl.application_request_result(rid)


def test_socket_lost_reply_returns_uncertainty_not_another_id():
    broker = Broker("/run/zog/certify-lifecycle.sock")
    ctrl = SelectedIssuerController("/run/zog/certify-lifecycle.sock",
                                    client_factory=lambda _: broker)
    rid = ctrl.issue_application_request_id()
    def lost(*args, **kwargs):
        raise ConnectionResetError("possibly committed")
    broker.launch_application = lost
    with pytest.raises(RenewalBlocked, match="launch-uncertain"):
        ctrl.request_application_launch("certify-manage", program_name="renew",
                                        request_id=rid)
    assert broker.issued == 1
