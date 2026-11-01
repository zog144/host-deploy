"""Independently installed certificate lifecycle broker authority.

The timer's JSON chooses neither the broker's UID nor an alternate socket.
The protected installer must independently derive and publish a *non-secret*
root-owned 0444 attested policy from the private 0600 consumer binding.
This module is read-only and cannot enable renewal.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .certificate_renewal import RenewalBlocked

SCHEMA = "zog-host-deploy-selected-issuer-broker-authority-v1"
ROOT_PATH = "/etc/zog/host-deploy/certificate-issuer-broker-authority.json"
REVOCATION_NAME = "certificate-issuer-broker-revoked.json"
REVOCATION_PATH = "/etc/zog/host-deploy/" + REVOCATION_NAME
COMMIT_NAME = "certificate-issuer-broker-install-commit.json"
COMMIT_SCHEMA = "zog-host-install-selected-broker-install-commit-v1"
COMMIT_FIELDS = {
    "schema", "projection_sha256", "install_receipt_sha256",
    "host_id", "installation_id", "state_volume_id",
    "certificate_id", "policy_sha256", "consumer_binding_sha256",
    "owner_revision", "owner_operation_id", "host_deploy_source_commit",
    "box_control_revision",
}
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



def _require_not_revoked(parent_fd):
    """Any final OR pending immutable tombstone makes authority unusable.

    The root owner publishes the permanent 0444 marker with no-replacement
    hard-link staging. An unreadable, malformed or partial tombstone is a
    STOP, never an invitation to revive a retained authority projection.
    """
    for name in (REVOCATION_NAME, ".pending." + REVOCATION_NAME):
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _deny()
        _deny()




def _commit_file(parent_fd):
    """Read final immutable root commit; a pending marker always blocks.

    A 0444 commit is a root installer's attestation that the private 0600
    receipt was fsynced and read back before the last publication.
    The non-root timer must never read that private receipt itself.
    """
    try:
        os.stat(".pending." + COMMIT_NAME, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError:
        _deny()
    else:
        _deny()
    try:
        fd = os.open(COMMIT_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o444
                    or info.st_nlink != 1 or not 0 < info.st_size <= 8192):
                _deny()
            raw = os.read(fd, 8193)
            if len(raw) != info.st_size:
                _deny()
            identity = (info.st_dev, info.st_ino, info.st_size)
        finally:
            os.close(fd)
    except OSError:
        _deny()
    try:
        def unique(pairs):
            d = {}
            for key, value in pairs:
                if key in d:
                    _deny()
                d[key] = value
            return d
        record = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: _deny())
    except (UnicodeError, ValueError, TypeError):
        _deny()
    if (type(record) is not dict or set(record) != COMMIT_FIELDS
            or record.get("schema") != COMMIT_SCHEMA
            or json.dumps(record, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii") != raw
            or any(type(record.get(name)) is not str or
                   _HEX.fullmatch(record[name]) is None
                   for name in ("projection_sha256", "install_receipt_sha256"))
            or type(record["owner_revision"]) is not int
            or not 1 <= record["owner_revision"] < 2**53
            or type(record["owner_operation_id"]) is not str
            or not _UUID.fullmatch(record["owner_operation_id"])
            or type(record["host_deploy_source_commit"]) is not str
            or not re.fullmatch(r"[a-f0-9]{40}", record["host_deploy_source_commit"])):
        _deny()
    return record, raw, identity


def _commit_matches_projection(commit, record, raw):
    if (commit["projection_sha256"] != hashlib.sha256(raw).hexdigest()
            or any(commit.get(key) != record.get(key) for key in (
                "host_id", "installation_id", "state_volume_id",
                "certificate_id", "policy_sha256", "consumer_binding_sha256",
                "box_control_revision"))):
        _deny()

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
        _require_not_revoked(descriptor)
        committed, committed_raw, committed_identity = _commit_file(descriptor)
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
        # A revocation raced with the read: refuse the projection rather
        # than returning a stale authorized broker identity.
        _require_not_revoked(descriptor)
        # A replacement/partial marker or revocation racing with projection
        # read cannot be treated as the originally committed identity.
        rechecked, rechecked_raw, rechecked_identity = _commit_file(descriptor)
        if (rechecked != committed or rechecked_raw != committed_raw
                or rechecked_identity != committed_identity):
            _deny()
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
        projection = json.loads(raw, object_pairs_hook=unique,
                                parse_constant=lambda _: _deny())
        if type(projection) is not dict or set(projection) != FIELDS:
            _deny()
        _commit_matches_projection(committed, projection, raw)
        return projection
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
