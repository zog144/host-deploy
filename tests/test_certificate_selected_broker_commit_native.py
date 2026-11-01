"""Ephemeral root-owned commit/consumer integration, no native certificate state."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

import pytest

from zog.host_deploy import certificate_selected_broker_authority as authority
from zog.host_deploy.certificate_renewal import RenewalBlocked
from test_certificate_selected_broker_authority import identities


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned immutable files required")
def test_real_consumer_requires_last_committed_installation(monkeypatch):
    fixture = Path(tempfile.mkdtemp(prefix="zog-broker-commit-", dir="/root"))
    parent = fixture / "etc/zog/host-deploy"
    parent.mkdir(parents=True, mode=0o755)
    for part in (fixture, fixture/"etc", fixture/"etc/zog", parent):
        part.chmod(0o755)
    projection_path = parent / Path(authority.ROOT_PATH).name
    commit_path = parent / authority.COMMIT_NAME
    monkeypatch.setattr(authority, "ROOT_PATH", str(projection_path))
    record, policy, inspector, observer, binding = identities()
    raw = _canonical(record)
    projection_path.write_bytes(raw)
    projection_path.chmod(0o444)
    marker = {
        "schema": authority.COMMIT_SCHEMA,
        "projection_sha256": hashlib.sha256(raw).hexdigest(),
        "install_receipt_sha256": "b"*64,
        "host_id": record["host_id"],
        "installation_id": record["installation_id"],
        "state_volume_id": record["state_volume_id"],
        "certificate_id": record["certificate_id"],
        "policy_sha256": record["policy_sha256"],
        "consumer_binding_sha256": record["consumer_binding_sha256"],
        "box_control_revision": record["box_control_revision"],
        "owner_revision": 6,
        "owner_operation_id": "22222222-2222-4222-8222-222222222222",
        "host_deploy_source_commit": "a"*40,
    }
    try:
        # Fully visible 0444 projection, but no committed receipt: DENY.
        with pytest.raises(RenewalBlocked):
            authority._root_file(str(projection_path))
        commit_path.write_bytes(_canonical(marker))
        commit_path.chmod(0o444)
        assert authority._root_file(str(projection_path)) == record
        assert authority.verify(policy, inspector, observer,
                                binding, root_reader=lambda:
                                authority._root_file(str(projection_path)))
        # A different generation/receipt cannot bootstrap the old projection.
        for change in ({"projection_sha256": "0"*64},
                       {"installation_id": "f"*36},
                       {"policy_sha256": "0"*64},
                       {"install_receipt_sha256": "garbage"},
                       {"owner_revision": 0}):
            commit_path.chmod(0o600)
            commit_path.write_bytes(_canonical({**marker, **change}))
            commit_path.chmod(0o444)
            with pytest.raises(RenewalBlocked):
                authority._root_file(str(projection_path))
        commit_path.chmod(0o600)
        commit_path.write_bytes(_canonical(marker))
        commit_path.chmod(0o444)
        pending = parent / (".pending." + authority.COMMIT_NAME)
        pending.write_bytes(b"partial")
        pending.chmod(0o444)
        with pytest.raises(RenewalBlocked):
            authority._root_file(str(projection_path))
        pending.unlink()
        revoked = parent / authority.REVOCATION_NAME
        revoked.write_bytes(b"revoked")
        revoked.chmod(0o444)
        with pytest.raises(RenewalBlocked):
            authority._root_file(str(projection_path))
    finally:
        commit_path.chmod(0o600) if commit_path.exists() else None
        projection_path.chmod(0o600) if projection_path.exists() else None
        shutil.rmtree(fixture)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned immutable files required")
def test_missing_and_partial_commit_marker_are_fail_closed(monkeypatch):
    root = Path(tempfile.mkdtemp(prefix="zog-broker-torn-", dir="/root"))
    root.chmod(0o755)
    marker = root / authority.COMMIT_NAME
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(RenewalBlocked):
            authority._commit_file(fd)
        for data in (b"{", b"{}", b""):
            marker.write_bytes(data)
            marker.chmod(0o444)
            with pytest.raises(RenewalBlocked):
                authority._commit_file(fd)
            marker.chmod(0o600)
            marker.unlink()
        marker.symlink_to(root / "nonexistent")
        with pytest.raises(RenewalBlocked):
            authority._commit_file(fd)
    finally:
        os.close(fd)
        shutil.rmtree(root)
