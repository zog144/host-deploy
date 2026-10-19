"""Host-deploy adapter for the authenticated box-control issuer lifecycle socket.

No direct Project, root-control transport, generic evaluator or arbitrary
program. The controller-owned broker accepts exact selected renew/stage only.
"""
from __future__ import annotations

from types import SimpleNamespace

from .certificate_renewal import REQUEST_ID, RenewalBlocked

class SelectedIssuerController:
    """Compatibility adapter to the original durable renewal/stage coordinator.

    The broker executes selected requests directly under the controller
    mutation lock; there is no queue evaluation API to expose to host-deploy.
    """
    direct_selected_launch = True

    def __init__(self, socket_path, *, client_factory=None):
        if client_factory is None:
            from zog.box_control.issuer_lifecycle_client import IssuerLifecycleClient
            client_factory = IssuerLifecycleClient
        try:
            self._client = client_factory(socket_path)
        except Exception:
            raise RenewalBlocked("issuer-lifecycle-broker-unavailable") from None

    def issue_application_request_id(self):
        try:
            request_id = self._client.issue_application_request_id()
        except Exception:
            raise RenewalBlocked("issuer-lifecycle-issue-unavailable") from None
        if type(request_id) is not str or not REQUEST_ID.fullmatch(request_id):
            raise RenewalBlocked("issuer-lifecycle-request-id-invalid")
        return request_id

    def request_application_launch(self, application, *, program_name, request_id):
        if (application != "certify-manage" or program_name not in ("renew", "stage")
                or type(request_id) is not str or not REQUEST_ID.fullmatch(request_id)):
            raise RenewalBlocked("issuer-lifecycle-selection-rejected")
        try:
            reply = self._client.launch_application(
                "certify-manage", program_name=program_name, request_id=request_id
            )
        except Exception:
            # Could have launched already. The caller's fsynced request ID is
            # the only permitted recovery identity; never create another.
            raise RenewalBlocked("issuer-lifecycle-launch-uncertain") from None
        if (getattr(reply, "application", None) != "certify-manage"
                or getattr(reply, "selected_program", None) != program_name
                or type(getattr(reply, "runtime_id", None)) is not str
                or not reply.runtime_id):
            raise RenewalBlocked("issuer-lifecycle-reply-mismatch")
        return reply

    def application_request_result(self, request_id):
        if type(request_id) is not str or not REQUEST_ID.fullmatch(request_id):
            raise RenewalBlocked("issuer-lifecycle-request-id-invalid")
        try:
            reply = self._client.application_request_result(request_id)
        except Exception:
            raise RenewalBlocked("issuer-lifecycle-result-unavailable") from None
        if (type(reply) is not dict or set(reply) !=
                {"request_id", "status", "program", "runtime_id"}
                or reply["request_id"] != request_id):
            raise RenewalBlocked("issuer-lifecycle-result-identity-mismatch")
        if reply["status"] == "unknown":
            if reply["program"] is not None or reply["runtime_id"] is not None:
                raise RenewalBlocked("issuer-lifecycle-result-identity-mismatch")
            return None
        if (reply["program"] not in ("renew", "stage")
                or reply["status"] not in ("pending", "satisfied", "failed",
                                          "abandoned", "cancelled")):
            raise RenewalBlocked("issuer-lifecycle-result-scope-mismatch")
        if (reply["runtime_id"] is not None
                and (type(reply["runtime_id"]) is not str
                     or not reply["runtime_id"])):
            raise RenewalBlocked("issuer-lifecycle-runtime-invalid")
        return SimpleNamespace(
            request_id=request_id, application="certify-manage",
            program_name=reply["program"], operation="launch",
            status=reply["status"], runtime_id=reply["runtime_id"],
            # Broker does not expose a terminal timestamp. The privileged
            # observer verifies the issuer journal against durable intent.
            updated_at=None,
        )
