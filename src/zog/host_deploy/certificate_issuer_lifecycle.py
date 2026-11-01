"""Host-deploy adapter for the authenticated box-control issuer lifecycle socket.

No direct Project, root-control transport, generic evaluator or arbitrary
program. The controller-owned broker accepts exact selected renew/inspect/stage only.
"""
from __future__ import annotations

from types import SimpleNamespace
import re

from .certificate_renewal import REQUEST_ID, RenewalBlocked

# Match box-control's fixed broker runtime identity contract. In particular
# do not trust a custom/testing client_factory to sanitize for this consumer.
_RUNTIME_ID = re.compile(r"[A-Za-z0-9-]{1,40}\Z")

# Source-review compatibility checkpoint for the fixed, one-shot controller
# result reader. It does NOT attest a live installed checkout: Work must
# independently verify the deployed box-control source and broker UID.
ISSUER_LIFECYCLE_BOX_CONTROL_REPOSITORY = "zog144/box-control"
ISSUER_LIFECYCLE_BOX_CONTROL_REVISION = "9111606eef306292d70fd4d941eeb73f48b33ff1"
ISSUER_LIFECYCLE_CLIENT_MODULE = (
    "box-control/src/zog/box_control/issuer_lifecycle_client.py"
)


class SelectedIssuerController:
    """Compatibility adapter to the original durable renewal/stage coordinator.

    The broker executes selected requests directly under the controller
    mutation lock; there is no queue evaluation API to expose to host-deploy.
    """
    direct_selected_launch = True

    def __init__(self, socket_path, *, controller_uid=None, client_factory=None,
                 authority_guard=None):
        # The independently installed root authority, never the RPC response,
        # chooses the expected server UID. Never construct an unpinned client.
        if (type(controller_uid) is not int or
                not 1000 <= controller_uid < 2**31):
            raise RenewalBlocked("issuer-controller-uid-required")
        if client_factory is None:
            from zog.box_control.issuer_lifecycle_client import IssuerLifecycleClient
            client_factory = IssuerLifecycleClient
        if authority_guard is not None and not callable(authority_guard):
            raise RenewalBlocked("issuer-lifecycle-authority-guard-invalid")
        self._controller_uid = controller_uid
        self._authority_guard = authority_guard
        self._require_active_authority()
        try:
            self._client = client_factory(socket_path, controller_uid=controller_uid)
        except Exception:
            raise RenewalBlocked("issuer-lifecycle-broker-unavailable") from None

    def _require_active_authority(self):
        """Reopen the root-owned projection/revocation before every broker RPC."""
        if self._authority_guard is None:
            # Only directly constructed source-test clients use no guard.
            # The protected timer always supplies its root-file rechecker.
            return
        try:
            if self._authority_guard() is not True:
                raise ValueError("inactive authority")
        except Exception:
            raise RenewalBlocked("issuer-lifecycle-root-authority-revoked") from None

    def issue_application_request_id(self):
        self._require_active_authority()
        try:
            request_id = self._client.issue_application_request_id()
        except Exception:
            raise RenewalBlocked("issuer-lifecycle-issue-unavailable") from None
        if type(request_id) is not str or not REQUEST_ID.fullmatch(request_id):
            raise RenewalBlocked("issuer-lifecycle-request-id-invalid")
        return request_id

    def request_application_launch(self, application, *, program_name, request_id):
        self._require_active_authority()
        if (application != "certify-manage" or program_name not in ("renew", "stage", "inspect")
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
                or _RUNTIME_ID.fullmatch(reply.runtime_id) is None):
            raise RenewalBlocked("issuer-lifecycle-reply-mismatch")
        return reply

    def application_request_result(self, request_id):
        self._require_active_authority()
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
        if (reply["program"] not in ("renew", "stage", "inspect")
                or reply["status"] not in ("pending", "satisfied", "failed",
                                          "abandoned", "cancelled")):
            raise RenewalBlocked("issuer-lifecycle-result-scope-mismatch")
        if (reply["runtime_id"] is not None
                and (type(reply["runtime_id"]) is not str
                     or _RUNTIME_ID.fullmatch(reply["runtime_id"]) is None)):
            raise RenewalBlocked("issuer-lifecycle-runtime-invalid")
        return SimpleNamespace(
            request_id=request_id, application="certify-manage",
            program_name=reply["program"], operation="launch",
            status=reply["status"], runtime_id=reply["runtime_id"],
            # Broker does not expose a terminal timestamp. The privileged
            # observer verifies the issuer journal against durable intent.
            updated_at=None,
        )

    def inspect_issuer_result(self, request_id):
        """Read only the controller's authenticated saved inspect invocation."""
        self._require_active_authority()
        if type(request_id) is not str or not REQUEST_ID.fullmatch(request_id):
            raise RenewalBlocked("issuer-lifecycle-request-id-invalid")
        try:
            result = self._client.inspect_issuer_result(request_id)
        except Exception:
            raise RenewalBlocked("issuer-inspection-invocation-unavailable") from None
        # The box-control client sanitizes this; validate the essential
        # structure again so an alternate injected client cannot bypass it.
        fields = {"schema", "request_id", "runtime_id", "program", "boot_id",
                  "invocation_id", "storage_id", "grant_id", "issuer_uid",
                  "issuer_gid", "host_policy_digest", "inspection",
                  "status", "tls_ready"}
        if (type(result) is not dict or set(result) != fields
                or result["schema"] != "zog-trusted-issuer-inspection-v1"
                or result["request_id"] != request_id
                or result["program"] != "inspect"
                or result["status"] != "verified"
                or result["tls_ready"] is not False
                or type(result["runtime_id"]) is not str
                or _RUNTIME_ID.fullmatch(result["runtime_id"]) is None
                or type(result["inspection"]) is not dict):
            raise RenewalBlocked("issuer-inspection-invocation-mismatch")
        return result
