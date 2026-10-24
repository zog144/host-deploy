"""Root authority openat/no-follow path guard regression.

Ownership is simulated at fstat for unprivileged GitHub CI; actual Linux
O_NOFOLLOW and dir_fd traversals operate on a disposable real filesystem.
No issuer, nginx or root-installed files are touched.
"""
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from zog.host_deploy import certificate_hostname_authority as authority
from zog.host_deploy import certificate_managed_authority as managed
from test_certificate_hostname_authority import authority as example_authority, NOW


def _simulate_root_ownership(monkeypatch):
    real = os.fstat

    def root_stat(fd):
        original = real(fd)
        # Do not emulate path traversal: real kernel O_NOFOLLOW must still
        # enforce the no-symlink directory and leaf decisions.
        mode = original.st_mode
        if stat.S_ISDIR(mode):
            mode &= ~0o022
        return SimpleNamespace(
            st_mode=mode, st_uid=0, st_nlink=original.st_nlink,
            st_size=original.st_size,
        )

    monkeypatch.setattr(os, "fstat", root_stat)


def test_managed_root_records_use_anchored_directory_descriptors(tmp_path, monkeypatch):
    holder = tmp_path / "root" / "installed"
    holder.mkdir(parents=True)
    payload = {"schema": 1, "kind": managed.PIN_KIND}
    final = holder / "authority.json"
    final.write_text(json.dumps(payload))
    final.chmod(0o600)
    with monkeypatch.context() as scope:
        scope.setattr(os, "geteuid", lambda: 0)
        _simulate_root_ownership(scope)
        scope.setattr(managed, "ROOT_OBSERVATION_PATH", str(final))
        assert managed._read_root_json(str(final), mode=0o600, limit=65536) == payload
        # The final filename may not resolve via a symlink.
        link = holder / "redirect.json"
        link.symlink_to(final)
        scope.setattr(managed, "ROOT_OBSERVATION_PATH", str(link))
        with pytest.raises(OSError):
            managed._read_root_json(str(link), mode=0o600, limit=65536)
        # Nor may any ancestor become a symlink to another tree.
        alias = tmp_path / "alias"
        alias.symlink_to(holder, target_is_directory=True)
        moved = alias / final.name
        scope.setattr(managed, "ROOT_OBSERVATION_PATH", str(moved))
        with pytest.raises(OSError):
            managed._read_root_json(str(moved), mode=0o600, limit=65536)


def test_owner_authority_is_opened_against_same_anchored_parent(tmp_path, monkeypatch):
    holder = tmp_path / "root" / "approved"
    holder.mkdir(parents=True)
    payload = example_authority()
    final = holder / "owner.json"
    final.write_text(json.dumps(payload))
    final.chmod(0o600)
    with monkeypatch.context() as scope:
        _simulate_root_ownership(scope)
        assert authority.read_owned(final, now=NOW) == payload
        link = holder / "redirect.json"
        link.symlink_to(final)
        with pytest.raises(OSError):
            authority.read_owned(link, now=NOW)
        alias = tmp_path / "alias"
        alias.symlink_to(holder, target_is_directory=True)
        with pytest.raises(OSError):
            authority.read_owned(alias / final.name, now=NOW)


def test_managed_root_rejects_untrusted_owning_mode(tmp_path, monkeypatch):
    holder = tmp_path / "root"
    holder.mkdir()
    final = holder / "authority.json"
    final.write_text('{"schema": 1}')
    final.chmod(0o644)
    with monkeypatch.context() as scope:
        scope.setattr(os, "geteuid", lambda: 0)
        _simulate_root_ownership(scope)
        scope.setattr(managed, "ROOT_OBSERVATION_PATH", str(final))
        with pytest.raises(authority.AuthorityBlocked, match="unsafe-root-file"):
            managed._read_root_json(str(final), mode=0o600, limit=65536)
        final.chmod(0o600)
        assert managed._read_root_json(str(final), mode=0o600, limit=65536) == {"schema": 1}
