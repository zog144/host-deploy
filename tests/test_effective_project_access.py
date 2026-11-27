"""Only effective process permissions matter; no passwd/worker account lookup."""
import os
from pathlib import Path
import pytest
from zog.host_deploy import effective_project_access as access


def test_effective_existing_and_new_project_access_without_named_users(tmp_path, monkeypatch):
    monkeypatch.setattr(access.os, "geteuid", lambda: 1080)
    monkeypatch.setattr(access.os, "getegid", lambda: 1081)
    root = tmp_path / "different" / "gateway-first-fonts-runtime"
    root.parent.mkdir()
    result = access.inspect(str(root))
    assert result["principal"] == "effective-process"
    assert result["status"] == "can-create"
    assert result["effective_uid"] == 1080
    root.mkdir()
    assert access.inspect(str(root))["status"] == "accessible"


def test_root_access_probe_only_reports_actual_effective_root_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(access.os, "geteuid", lambda: 0)
    monkeypatch.setattr(access.os, "getegid", lambda: 0)
    record = access.inspect(str(tmp_path))
    assert (record["effective_uid"], record["effective_gid"]) == (0, 0)
    assert record["identity_override"] is False
    assert "execution_authorized" not in record
    monkeypatch.setattr(access.os, "getegid", lambda: 10)
    with pytest.raises(PermissionError, match="exactly 0:0"):
        access.inspect(str(tmp_path))


def test_actual_filesystem_access_failure_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(access.os, "geteuid", lambda: 1080)
    monkeypatch.setattr(access.os, "getegid", lambda: 1081)
    root=tmp_path/"gateway-first-fonts-runtime"
    root.mkdir()
    original=access.os.access
    monkeypatch.setattr(access.os,"access",lambda path,mode,**kw: False if Path(path)==root else original(path,mode,**kw))
    with pytest.raises(PermissionError,match="cannot traverse compiler Project ancestor"):
        access.inspect(str(root))


def test_no_implicit_user_or_group_switching_source():
    source=Path(access.__file__).read_text()
    for forbidden in ("pwd.getpwuid(", "grp.getgrgid(", "os.setuid(", "os.setgid(", "subprocess.run(", "runuser", "setpriv"):
        assert forbidden not in source


@pytest.mark.parametrize("path",["relative", "/tmp/../bad", "/", "//tmp/foo"])
def test_invalid_project_paths_rejected(tmp_path, monkeypatch,path):
    monkeypatch.setattr(access.os,"geteuid",lambda:1080)
    monkeypatch.setattr(access.os,"getegid",lambda:1081)
    with pytest.raises(ValueError):
        access.inspect(path)
