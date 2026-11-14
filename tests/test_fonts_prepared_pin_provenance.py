"""Original Git blob retrieval with no historical project or fabricated source."""
import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from zog.host_deploy import fonts_pin_retention as pin, image_build_lanes as lanes


def git(repo,*args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def init_repo(path, origin):
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    git(path,"config","user.email","test@example.invalid")
    git(path,"config","user.name","Test")
    git(path,"remote","add","origin",origin)


def fixture(tmp_path, monkeypatch):
    raw=(repr({"schema":1,"date":"2026-10-01","packages":{}})+"\n").encode()
    monkeypatch.setattr(pin,"PIN_SHA256",hashlib.sha256(raw).hexdigest())
    original=tmp_path/"original-git-source"  # external original Git provenance, NEVER Project/source
    init_repo(original,"https://github.com/zog144/image-build.git")
    historical=original/pin.RELATIVE_PIN
    historical.parent.mkdir(parents=True)
    historical.write_bytes(raw)
    git(original,"add",".")
    git(original,"commit","-qm","historical commit")
    rev=git(original,"rev-parse","HEAD")
    mirror=tmp_path/"original-provenance.git"
    subprocess.run(["git","clone","--bare","-q",str(original),str(mirror)],check=True)
    subprocess.run(["git","--git-dir="+str(mirror),"remote","set-url","origin",
                    "https://github.com/zog144/image-build.git"],check=True)
    project=tmp_path/pin.PROJECT.lstrip("/")
    source=project/"source"
    init_repo(source,"https://github.com/zog144/image-build.git")
    (source/"new.txt").write_text("new producer\n")
    git(source,"add",".")
    git(source,"commit","-qm","identity-free revision")
    monkeypatch.setattr(lanes,"FIRST_FONTS_INHERITED_PRODUCER_REVISION",git(source,"rev-parse","HEAD"))
    (project/"state").mkdir()
    return mirror,project,raw,rev


def test_exact_original_pin_from_bare_provenance_no_old_project(tmp_path,monkeypatch):
    mirror,project,raw,revision=fixture(tmp_path,monkeypatch)
    assert not (tmp_path/"home/certbot-build-owner/gateway-first-fonts-runtime").exists()
    result=pin.operation("retain-from-provenance",filesystem_root=tmp_path,
                         source_revision=revision,provenance_git_dir=mirror)
    artifact=Path(result["artifact_path"])
    assert artifact.read_bytes()==raw and raw.endswith(b"\n")
    assert artifact.stat().st_mode & 0o777==0o600
    assert result["acquisition_mode"]=="original-git-object"
    assert result["compilation_authorized"] is False
    assert pin.operation("retain-from-provenance",filesystem_root=tmp_path,
                         source_revision=revision,provenance_git_dir=mirror)["already_present"]
    assert not (project/"source"/pin.RELATIVE_PIN).exists()


def test_wrong_history_or_unsafe_provenance_never_writes_pin(tmp_path,monkeypatch):
    mirror,project,raw,revision=fixture(tmp_path,monkeypatch)
    with pytest.raises(RuntimeError,match="revision|unavailable"):
        pin.operation("retain-from-provenance",filesystem_root=tmp_path,
                      source_revision="0"*40,provenance_git_dir=mirror)
    target=project.joinpath(*pin.ARTIFACT_PARTS)/pin.PIN_SHA256
    assert not target.exists()
    subprocess.run(["git","--git-dir="+str(mirror),"remote","set-url","origin",
                    "https://github.com/unreviewed/other.git"],check=True)
    with pytest.raises(RuntimeError,match="repository differs"):
        pin.operation("retain-from-provenance",filesystem_root=tmp_path,
                      source_revision=revision,provenance_git_dir=mirror)
    assert not target.exists()


def test_provenance_mode_does_not_treat_active_project_as_old_source(tmp_path,monkeypatch):
    mirror,project,raw,revision=fixture(tmp_path,monkeypatch)
    (project/"source"/"untracked-file").write_text("dirty")
    with pytest.raises(RuntimeError,match="corrected producer checkout differs"):
        pin.operation("retain-from-provenance",filesystem_root=tmp_path,
                      source_revision=revision,provenance_git_dir=mirror)
    assert not (project.joinpath(*pin.ARTIFACT_PARTS)/pin.PIN_SHA256).exists()
