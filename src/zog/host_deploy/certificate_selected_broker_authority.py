"""Independently installed certificate lifecycle broker authority.

The timer's JSON chooses neither the broker's UID nor an alternate socket.
The protected installer must independently derive and publish a *non-secret*
root-owned 0444 attested policy from the private 0600 consumer binding.
This module is read-only and cannot enable renewal.
"""
import json
import os
from pathlib import Path
import re
import stat

from .certificate_renewal import RenewalBlocked

SCHEMA = "zog-host-deploy-selected-issuer-broker-authority-v1"
ROOT_PATH = "/etc/zog/host-deploy/certificate-issuer-broker-authority.json"
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
_TOKEN = re.compile(r"[a-f0-9]{32}\Z")
FIELDS = {
    "schema", "host_id", "installation_id", "state_volume_id",
    "certificate_id", "hostnames", "policy_sha256", "host_policy_digest",
    "issuer_lifecycle_socket", "controller_uid", "caller_uid", "issuer_uid",
    "issuer_gid", "storage_id", "grant_id", "box_control_revision",
    "consumer_binding_sha256",
}


def _deny():
    raise RenewalBlocked("selected-broker-root-authority-unverified")


def _root_file(path=ROOT_PATH):
    """Retained O_NOFOLLOW dirfd walk, root-owned readable non-secret 0444 pin."""
    if path != ROOT_PATH:
        _deny()
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in Path(path).parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022):
                _deny()
        leaf = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=descriptor)
        try:
            info = os.fstat(leaf)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o444
                    or info.st_nlink != 1 or not 0 < info.st_size <= 8192):
                _deny()
            raw = os.read(leaf, 8193)
            if len(raw) > 8192:
                _deny()
        finally:
            os.close(leaf)
    except OSError:
        _deny()
    finally:
        os.close(descriptor)
    try:
        def unique(pairs):
            d = {}
            for name, val in pairs:
                if name in d:
                    _deny()
                d[name] = val
            return d
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _deny())
    except (UnicodeError, ValueError, TypeError):
        _deny()


def verify(policy, inspection, observer, binding=None, *, root_reader=None):
    """Check immutable host-install owner binding and split-UID policy pins."""
    if root_reader is None:
        root_reader = _root_file
    record = root_reader()
    if type(record) is not dict or set(record) != FIELDS or record["schema"] != SCHEMA:
        _deny()
    from .certificate_issuer_lifecycle import ISSUER_LIFECYCLE_BOX_CONTROL_REVISION
    if (record["box_control_revision"] != ISSUER_LIFECYCLE_BOX_CONTROL_REVISION
            or type(record["controller_uid"]) is not int
            or not 1000 <= record["controller_uid"] < 2**31
            or record["controller_uid"] in (record["caller_uid"], record["issuer_uid"])
            or any(type(record[x]) is not int or record[x] < 1000 for x in
                   ("caller_uid", "issuer_uid", "issuer_gid"))
            or record["certificate_id"] != policy["certificate_id"]
            or record["policy_sha256"] != policy["policy_sha256"]
            or record["issuer_lifecycle_socket"] != policy["issuer_lifecycle_socket"]
            or record["certificate_id"] != inspection["certificate_id"]
            or record["certificate_id"] != observer["certificate_id"]
            or record["policy_sha256"] != inspection["policy_sha256"]
            or record["policy_sha256"] != observer["policy_sha256"]
            or record["hostnames"] != inspection["hostnames"]
            or record["host_policy_digest"] != observer["host_policy_digest"]
            or record["caller_uid"] != inspection["caller_uid"]
            or record["caller_uid"] != observer["caller_uid"]
            or record["issuer_uid"] != inspection["issuer_uid"]
            or record["issuer_uid"] != observer["issuer_uid"]
            or record["issuer_gid"] != observer["issuer_gid"]
            or record["storage_id"] != observer["storage_id"]
            or record["grant_id"] != observer["grant_id"]):
        _deny()
    # The installer checks the private consumer binding, then publishes this
    # immutable 0444 projection. A non-root timer cannot read the 0600
    # consumer binding; optional in-process comparison is installer-only.
    if binding is not None and (
            type(binding) is not dict
            or any(record[key] != binding.get(key) for key in (
                "host_id", "installation_id", "state_volume_id",
                "certificate_id", "hostnames", "policy_sha256"))):
        _deny()
    if (type(record["consumer_binding_sha256"]) is not str
            or not record["consumer_binding_sha256"].startswith("sha256:")
            or not _HEX.fullmatch(record["consumer_binding_sha256"][7:])):
        _deny()
    if (type(record["certificate_id"]) is not str
            or not _ID.fullmatch(record["certificate_id"])):
        _deny()
    for key in ("host_id", "installation_id", "state_volume_id"):
        if type(record[key]) is not str or not _UUID.fullmatch(record[key]):
            _deny()
    if (type(record["storage_id"]) is not str
            or not _TOKEN.fullmatch(record["storage_id"])
            or type(record["grant_id"]) is not str
            or not _TOKEN.fullmatch(record["grant_id"])
            or type(record["host_policy_digest"]) is not str
            or not record["host_policy_digest"].startswith("sha256:")
            or not _HEX.fullmatch(record["host_policy_digest"][7:])):
        _deny()
    return json.loads(json.dumps(record, sort_keys=True))
