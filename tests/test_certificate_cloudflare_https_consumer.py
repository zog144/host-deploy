"""Noncanonical Cloudflare request/receipt/FD transport MUST be inert."""
import inspect
import pytest
from zog.host_deploy import certificate_cloudflare_https_consumer as old


@pytest.mark.parametrize("entry", ["prepare", "check_receipt", "deliver_selected"])
def test_retired_custom_wire_never_builds_message_or_calls_transport(entry):
    called = []
    class Transport:
        def request_fd(self, *args, **kwargs):
            called.append("network")
            raise AssertionError("noncanonical transport not allowed")
    with pytest.raises(old.CloudflareDeliveryBlocked,
                       match="retired-noncanonical-cloudflare-delivery"):
        getattr(old, entry)(channel=Transport())
    assert called == []


def test_no_custom_protocol_metadata_or_alt_fd_receiver_left():
    source = inspect.getsource(old)
    assert "zog-protected-credential-delivery-request-v1" not in source
    assert "zog-protected-credential-delivery-receipt-v1" not in source
    assert "request_fd(" not in source
    assert "install_from_fd(" not in source
    assert old.PROTOCOL_SOURCE == "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
