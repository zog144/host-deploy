"""The installer, not fresh host-discover, owns state directory setup.

No real Host identity, command-center, system account or AWS resource is
created. Privileged tests use disposable root-owned paths only.
"""
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile

import pytest

from zog.host_deploy import beacon_install as beacon


CLOUD = {"account_id": "123456789012", "instance_id": "i-0123456789abcdef0",
         "region": "us-east-1"}
SERVER = "https://registry.example.test"
CUSTOM = "/state/host-discover/identity"


def request(**settings):
    return {
        "cloud": CLOUD, "server": SERVER, "settings": settings,
        "migrate": False, "system_ca": True, "python": "python3.12",
    }


def test_fresh_custom_identity_directory_is_selected_without_mount_requirement():
    chosen = beacon.candidate({}, request(identity_directory=CUSTOM))
    assert chosen["identity_directory"] == CUSTOM
    assert chosen["credential_directory"] == beacon.CREDENTIALS
    assert chosen["provider"] == "aws"
    assert chosen["server"] == SERVER


@pytest.mark.parametrize("path", (
    "state/host-discover/identity", "", "/", "/state/../another",
    "/state/./host-discover/identity", "/state//host-discover/identity",
    "/state/host-discover/identity/", None, 17, [],
))
def test_invalid_identity_directory_shape_denied_without_state_mutation(path):
    with pytest.raises(ValueError, match="absolute normalized"):
        beacon.candidate({}, request(identity_directory=path))


def test_independent_credential_directory_is_allowed():
    chosen = beacon.candidate({}, request(
        identity_directory=CUSTOM,
        credential_directory="/state/host-discover/credentials"))
    assert chosen["identity_directory"] == CUSTOM
    assert chosen["credential_directory"] == "/state/host-discover/credentials"


@pytest.mark.parametrize("credential", (
    CUSTOM, CUSTOM + "/credentials", "/state/host-discover",
))
def test_overlapping_credential_directory_denied(credential):
    with pytest.raises(ValueError, match="must be separate"):
        beacon.candidate({}, request(
            identity_directory=CUSTOM, credential_directory=credential))


def test_reinstall_preserves_identity_and_never_changes_state_path():
    old = beacon.candidate({}, request(identity_directory=CUSTOM))
    assert beacon.candidate(old, request())["identity_directory"] == CUSTOM
    assert beacon.candidate(old, request(identity_directory=CUSTOM))["identity_directory"] == CUSTOM
    with pytest.raises(ValueError, match="Cannot replace existing identity"):
        beacon.candidate(old, request(identity_directory="/state/other-identity"))
    with pytest.raises(ValueError, match="Cannot replace existing identity"):
        beacon.candidate(
            {"provider": "aws", "cloud": CLOUD, "server": SERVER},
            request(identity_directory=CUSTOM))


@pytest.fixture
def native(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root-owned native filesystem acceptance")
    root = Path(tempfile.mkdtemp(prefix="zog-beacon-paths-", dir="/root"))
    root.chmod(0o700)
    # Synthetic service ownership: real chown/stat/mkdir on disposable root
    # directories, never modify the system's user/group databases.
    uid, gid, share = 24567, 24567, 24568
    monkeypatch.setattr(beacon.pwd, "getpwnam", lambda name: SimpleNamespace(
        pw_uid=uid, pw_gid=gid))
    monkeypatch.setattr(beacon.grp, "getgrnam", lambda name: SimpleNamespace(
        gr_gid=share))
    monkeypatch.setattr(beacon, "CONFIG", root / "etc/configuration.json")
    monkeypatch.setattr(beacon, "UNIT", root / "system/host-discover.service")
    monkeypatch.setattr(beacon, "BASE", root / "opt")
    (root / "opt").mkdir(mode=0o755)
    yield root, uid, gid, share
    shutil.rmtree(root)


def test_installer_creates_unmounted_state_and_identity_before_key_bootstrap(native):
    root, uid, gid, share = native
    identity = root / "state/host-discover/identity"
    credentials = root / "state/host-discover/credentials"
    chosen = beacon.candidate({}, request(
        identity_directory=str(identity), credential_directory=str(credentials)))
    assert not (root / "state").exists()
    assert not identity.exists()
    # Fresh parent directories must remain traversable by the service even
    # when the root install process has a restrictive 077 umask.
    previous_umask = os.umask(0o077)
    try:
        beacon.state_directories(chosen)
    finally:
        os.umask(previous_umask)
    assert (root / "state").stat().st_mode & 0o777 == 0o755
    assert (root / "state/host-discover").stat().st_mode & 0o777 == 0o755
    assert identity.is_dir()
    assert (root / "state/host-discover").is_dir()
    assert credentials.is_dir()
    assert identity.stat().st_uid == uid and identity.stat().st_gid == gid
    assert credentials.stat().st_uid == uid and credentials.stat().st_gid == share
    assert identity.stat().st_mode & 0o777 == 0o700
    assert credentials.stat().st_mode & 0o777 == 0o750
    assert beacon.CONFIG.parent.is_dir()
    assert beacon.CONFIG.parent.stat().st_mode & 0o777 == 0o750
    # Retry doesn't reinitialize or change a legitimate existing key.
    key = identity / "identity.pem"
    key.write_bytes(b"persistent-test-key")
    os.chown(key, uid, gid)
    key.chmod(0o600)
    beacon.state_directories(chosen)
    assert key.read_bytes() == b"persistent-test-key"


def test_symlinked_parent_is_denied_without_following_it(native):
    root, uid, gid, share = native
    outside = root / "outside"
    outside.mkdir(mode=0o700)
    (root / "state").symlink_to(outside, target_is_directory=True)
    chosen = beacon.candidate({}, request(
        identity_directory=str(root / "state/host-discover/identity"),
        credential_directory=str(root / "credentials")))
    with pytest.raises(ValueError, match="Symlink installation path"):
        beacon.state_directories(chosen)
    assert list(outside.iterdir()) == []


def test_unsafe_writable_parent_is_denied(native):
    root, uid, gid, share = native
    state = root / "state"
    state.mkdir(mode=0o777)
    state.chmod(0o777)
    chosen = beacon.candidate({}, request(
        identity_directory=str(state / "host-discover/identity"),
        credential_directory=str(root / "credentials")))
    with pytest.raises(ValueError, match="Unsafe installation ownership/mode"):
        beacon.state_directories(chosen)
    assert list(state.iterdir()) == []


def test_existing_unbound_identity_at_custom_path_is_refused(native, monkeypatch):
    root, uid, gid, share = native
    identity = root / "state/host-discover/identity"
    credentials = root / "credentials"
    selected = beacon.candidate({}, request(
        identity_directory=str(identity), credential_directory=str(credentials)))
    beacon.state_directories(selected)
    secret = identity / "identity.pem"
    secret.write_bytes(b"orphan-test-key")
    os.chown(secret, uid, gid)
    secret.chmod(0o600)
    monkeypatch.setattr(beacon, "run", lambda *a, **kw: "")
    monkeypatch.setattr(beacon.shutil, "disk_usage", lambda p:
                        SimpleNamespace(free=2 * 1024**3))
    monkeypatch.setattr(beacon, "_release_versions", lambda release: {
        name: "0.0.1" for name in beacon.PACKAGES})
    with pytest.raises(ValueError, match="Unbound existing identity"):
        beacon.install(request(
            identity_directory=str(identity),
            credential_directory=str(credentials)), root / "release")
    assert secret.read_bytes() == b"orphan-test-key"
    assert not (beacon.BASE / "identity-owner.json").exists()
