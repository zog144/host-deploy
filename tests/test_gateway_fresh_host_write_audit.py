"""Fixed read-only shared-host accounting witness; never a quota grant."""
import builtins
import io
import inspect
import stat
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import fresh_host_write_audit as audit
from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_native_owner as owner


PID1 = (
    b"20 1 259:1 / / rw,relatime - xfs /dev/nvme0n1p1 rw\n"
    b"21 20 0:33 / /run rw,nosuid - tmpfs tmpfs rw\n"
    b"22 20 7:8 / /var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external rw - ext4 /dev/loop8 rw\n"
)


def test_pid1_mount_covering_and_kernel_device_boundaries():
    mounts = audit._mounts(PID1)
    assert audit._covering(mounts, "/etc/cron.d")["source"] == "/dev/nvme0n1p1"
    assert audit._covering(mounts, "/var/log/journal")["fstype"] == "xfs"
    assert audit._covering(mounts, "/run/systemd")["fstype"] == "tmpfs"
    assert audit._covering(mounts, "/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external/owner-state")["source"] == "/dev/loop8"


@pytest.mark.parametrize("bad", [
    b"", b"invalid\n", b"1 2 8:1 / relative rw - ext4 dev rw\n",
    b"1 2 8:1 / / rw - ext4 dev rw\n",
    b"0" * (audit._MAX_MOUNTINFO_BYTES + 1),
])
def test_missing_root_and_invalid_mountinfo_fail_closed(bad):
    with pytest.raises(RuntimeError):
        audit._mounts(bad)


def _mock_pid1(monkeypatch, *, missing=None, linked=None, namespace_equal=True):
    missing = set(missing or [])
    linked = set(linked or [])
    real_open = builtins.open
    def fake_open(file, mode="r", *args, **kwargs):
        if str(file) == "/proc/1/mountinfo" and mode == "rb":
            return io.BytesIO(PID1)
        return real_open(file, mode, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(audit.os, "readlink", lambda path: (
        "mnt:[888]" if namespace_equal or path == "/proc/1/ns/mnt"
        else "mnt:[999]"
    ))
    def fake_lstat(path):
        if path in missing:
            raise FileNotFoundError(path)
        mode = stat.S_IFLNK if path in linked else stat.S_IFDIR
        return SimpleNamespace(st_mode=mode | 0o700, st_dev=2049,
                               st_ino=311, st_uid=0)
    monkeypatch.setattr(audit.os, "lstat", fake_lstat)


def test_audit_is_explicitly_evidence_only_even_if_paths_look_expected(monkeypatch):
    _mock_pid1(monkeypatch, missing={"/var/log/syslog"},
               linked={"/etc/cron.d"})
    evidence = audit.inspect()
    assert evidence["status"] == "evidence-only-no-aggregate-admission"
    assert evidence["additional_shared_host_write_limit_verified"] is False
    assert evidence["outstanding_classes"] == list(aggregate.UNVERIFIED_WRITERS)
    for cls, rows in evidence["samples"].items():
        assert cls in aggregate.UNVERIFIED_WRITERS
        assert len(rows) == len(audit.SURFACES[cls])
        assert all("pid1_mount" in r for r in rows)
        assert all(r["status"] != "verified" for r in rows)
    assert next(r for r in evidence["samples"][
        "pid1-default-journald-unverified"] if r["path"] == "/var/log/syslog"
    )["status"] == "missing-is-not-no-writes"
    assert next(r for r in evidence["samples"][
        "cron-schedule-and-daemon-unverified"] if r["path"] == "/etc/cron.d"
    )["status"] == "symlink-destination-not-attested"
    # Audit data cannot masquerade as the strict native aggregate inspection.
    with pytest.raises(RuntimeError):
        aggregate.validate({
            "image_bytes": aggregate.BUILD_BYTES,
            "capacity_bytes": aggregate.BUILD_BYTES,
            "kernel_enforced": True,
            "mount": "/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work",
        }, evidence, host_owner_verified=True)


def test_audit_rejects_different_pid1_mount_namespace(monkeypatch):
    _mock_pid1(monkeypatch, namespace_equal=False)
    with pytest.raises(RuntimeError, match="does not share PID1"):
        audit.inspect()


def test_diagnostic_entrypoint_has_no_generic_path_or_grant():
    code = inspect.getsource(owner.main)
    assert '"inspect-host-write-surfaces"' in code
    assert "inspect_host_write_surfaces()" in code
    assert "aggregate.validate" not in inspect.getsource(owner.inspect_host_write_surfaces)
    assert "additional_shared_host_write_limit_verified" in inspect.getsource(audit.inspect)
    assert set(audit.SURFACES).issubset(set(aggregate.UNVERIFIED_WRITERS))
