"""Tombstone: retired incompatible 2026-10-29 HTTPS Cloudflare draft wire.

Never translate the custom draft request, metadata receipt or raw token into
canonical host-identify 0.3.5. The ONLY permitted source policy adapter is
certificate_cloudflare_canonical, and the protected network/secret-FD
producer/consumer is the independently reviewed root-control v1 receiver.

This module deliberately defines NO message schemas or HTTP transport.
"""
PROTOCOL_SOURCE = "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"


class CloudflareDeliveryBlocked(RuntimeError):
    def __init__(self):
        super().__init__("retired-noncanonical-cloudflare-delivery")


def prepare(*args, **kwargs):
    raise CloudflareDeliveryBlocked()


def check_receipt(*args, **kwargs):
    raise CloudflareDeliveryBlocked()


def deliver_selected(*args, **kwargs):
    raise CloudflareDeliveryBlocked()
