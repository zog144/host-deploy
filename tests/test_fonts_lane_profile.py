"""Historical first-Fonts lane remains readable but cannot select a worker."""
import copy
import json
import pytest

from zog.host_deploy import fonts_lane_profile as fonts
from zog.host_deploy import fonts_lane_runtime as runtime
from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import runner
from zog.host_deploy.workspace import initialize, save


def workspace(tmp_path, monkeypatch):
    root=tmp_path/"owner"
    w=initialize(root,"image-build-toolchain","zog-development","us-east-1")
    host={"region":w["region"],"profile":w["profile"],"account_id":"123456789012",
          "workspace_id":w["workspace_id"],"instance_id":fonts.COMPILER_INSTANCE}
    save(root/"host.json",host)
    spec=lanes.specification(fonts.LANE,mode="managed",project_root=fonts.RETAINED_PROJECT_ROOT,
      source_repository=fonts.fonts.REPOSITORY,source_revision=fonts.fonts.SOURCE,
      monthly_pin_repository_path=fonts.fonts.PIN_PATH,
      monthly_pin_identity="sha256:"+fonts.fonts.PIN_SHA256,
      provenance_host_id="original-host",provenance_project_id="original-project",
      memory_maximum_bytes=100000,thread_count_maximum=4,cpu_weight=100,disk_reservation_bytes=100000,
      execution_user_id=24202,execution_group_id=24202,python_executable="/usr/bin/python3.12")
    digest=lanes.specification_sha256(spec)
    monkeypatch.setattr(fonts,"RETAINED_SPECIFICATION_SHA256",digest)
    path=root/"image-build-lanes"/(fonts.LANE+".json")
    save(path,{"schema":4,"lane":fonts.LANE,"specification":spec,"state":"prepared"})
    return root,w,host,path,spec,digest


def test_reviewed_historical_source_and_accepted_digest_are_unchanged():
    assert fonts.profile()["source_revision"] == "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert fonts.profile()["retained_specification_sha256"] == "sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2"
    assert fonts.profile()["retained_project_root"] == "/home/certbot-build-owner/gateway-first-fonts-runtime"


def test_historical_verify_and_prepare_only_read_the_original_record(tmp_path,monkeypatch):
    root,w,host,path,spec,digest=workspace(tmp_path,monkeypatch)
    bytes_before=path.read_bytes()
    monkeypatch.setattr(runner,"Host",lambda *a,**kw: pytest.fail("no Host or SSM"))
    report=fonts.verify(root)
    assert report["migration_required"] is True
    assert report["execution_authorized"] is False
    assert report["historical_specification_sha256"]==digest
    assert report["project_root"]==fonts.RETAINED_PROJECT_ROOT
    assert fonts.prepare(root)==json.loads(bytes_before)
    assert path.read_bytes()==bytes_before
    assert not (root/fonts.FACTS_FILE).exists()


@pytest.mark.parametrize("alter",[
  lambda record:record["specification"]["controller"].update(execution_user_id=2000),
  lambda record:record["specification"].update(project_root="/srv/other/gateway-first-fonts-runtime"),
  lambda record:record["specification"].update(source_revision="a"*40),
  lambda record:record["specification"].update(provenance_project_id="changed"),
])
def test_altered_historical_identity_is_not_accepted(tmp_path,monkeypatch,alter):
    root,w,host,path,spec,digest=workspace(tmp_path,monkeypatch)
    record=json.loads(path.read_text())
    alter(record)
    save(path,record)
    with pytest.raises(RuntimeError):
        fonts.verify(root)


def test_old_uid_selection_cannot_activate_even_with_matching_digest(tmp_path,monkeypatch):
    root,w,host,path,spec,digest=workspace(tmp_path,monkeypatch)
    monkeypatch.setattr(lanes,"Host",lambda *a,**kw:pytest.fail("no Host on rejected legacy record"))
    before=path.read_bytes()
    with pytest.raises(RuntimeError,match="legacy first Fonts worker UID/GID"):
        lanes.activate(root,fonts.LANE,expected_specification_sha256=digest)
    assert path.read_bytes()==before


def test_old_home_and_user_lookup_removed_from_supported_controller_runtime(tmp_path,monkeypatch):
    root,w,host,path,spec,digest=workspace(tmp_path,monkeypatch)
    candidate={**spec,"schema":5,"project_root":"/srv/zog/gateway-first-fonts-runtime",
               "controller":{**spec["controller"]}}
    candidate["controller"].pop("execution_user_id")
    candidate["controller"].pop("execution_group_id")
    candidate["controller"]["execution_identity"]="inherit"
    code=runtime.script(candidate)
    assert "pwd.getpwuid" not in code
    assert "grp.getgrgid" not in code
    assert "os.chown" not in code
    assert "os.geteuid" in code and "os.getegid" in code
    with pytest.raises(ValueError,match="schema-5"):
        runtime.script(spec)


def test_foreign_compiler_host_holds_without_host_contact(tmp_path,monkeypatch):
    root,w,host,path,spec,digest=workspace(tmp_path,monkeypatch)
    host["instance_id"]="i-aaaaaaaaaaaaaaaaa"
    save(root/"host.json",host)
    monkeypatch.setattr(runner,"Host",lambda *a,**kw:pytest.fail("foreign Host should not be contacted"))
    with pytest.raises(RuntimeError,match="original workspace-owned compiler Host"):
        fonts.verify(root)
