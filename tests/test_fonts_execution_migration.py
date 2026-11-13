"""No identity-switch path: the former spec remains evidence, never executable."""
import copy
import json

import pytest

from zog.host_deploy import fonts_lane_profile as fonts
from zog.host_deploy import fonts_execution_migration as migration
from zog.host_deploy import image_build_lanes as lanes
from zog.host_deploy import runner
from zog.host_deploy.workspace import initialize, save


def owner(tmp_path, monkeypatch):
    root = tmp_path / "owner"
    w = initialize(root, "image-build-toolchain", "zog-development", "us-east-1")
    save(root / "host.json", {"region":w["region"], "profile":w["profile"],
        "workspace_id":w["workspace_id"], "account_id":"123456789012",
        "instance_id":fonts.COMPILER_INSTANCE})
    previous = lanes.specification(fonts.LANE,
        source_repository=fonts.fonts.REPOSITORY,source_revision=fonts.fonts.SOURCE,
        monthly_pin_repository_path=fonts.fonts.PIN_PATH,
        monthly_pin_identity="sha256:"+fonts.fonts.PIN_SHA256,
        provenance_host_id="host-bound", provenance_project_id="old-project",
        project_root=fonts.RETAINED_PROJECT_ROOT,
        memory_maximum_bytes=1000000,thread_count_maximum=2,cpu_weight=100,
        disk_reservation_bytes=2000000,execution_user_id=24202,
        execution_group_id=24202,python_executable="/usr/bin/python3")
    digest = lanes.specification_sha256(previous)
    monkeypatch.setattr(fonts,"RETAINED_SPECIFICATION_SHA256",digest)
    path=root/"image-build-lanes"/(fonts.LANE+".json")
    save(path,{"schema":4,"lane":fonts.LANE,"state":"prepared","specification":previous})
    return root, path, previous, digest


def test_preview_has_no_named_account_selection_or_remote_access(tmp_path,monkeypatch):
    root,path,old,digest=owner(tmp_path,monkeypatch)
    monkeypatch.setattr(runner,"Host",lambda *a,**kw: pytest.fail("never call SSM"))
    original=path.read_bytes()
    m=migration.preview(root,project_root="/srv/zog/gateway-first-fonts-runtime")
    assert m["historical_specification_sha256"]==digest
    assert m["original_record_unchanged"] is True
    assert m["status"]=="review-required-not-executable"
    assert m["runtime_compatibility"]=="blocked-pinned-image-build-requires-uid-gid"
    new=m["candidate_specification"]
    assert new["schema"]==5
    assert new["controller"]["execution_identity"]=="inherit"
    assert "execution_user_id" not in new["controller"]
    assert "execution_group_id" not in new["controller"]
    assert new["project_root"]=="/srv/zog/gateway-first-fonts-runtime"
    assert lanes.specification_sha256(new)==m["candidate_specification_sha256"]
    assert m["candidate_specification_sha256"]!=digest
    assert not any(x in lanes._controller(new) for x in ("execution_user_id","execution_group_id"))
    assert path.read_bytes()==original
    assert not (root/migration.FILE).exists()


def test_identical_stage_is_idempotent_and_cannot_change_evidence(tmp_path,monkeypatch):
    root,path,old,_=owner(tmp_path,monkeypatch)
    previous=path.read_bytes()
    result=migration.stage(root,project_root="/srv/zog/gateway-first-fonts-runtime")
    staged=(root/migration.FILE).read_bytes()
    assert migration.stage(root,project_root="/srv/zog/gateway-first-fonts-runtime")==result
    assert (root/migration.FILE).read_bytes()==staged
    assert path.read_bytes()==previous
    with pytest.raises(RuntimeError,match="already staged"):
        migration.stage(root,project_root="/var/lib/zog/gateway-first-fonts-runtime")
    assert path.read_bytes()==previous


@pytest.mark.parametrize("location",["relative/path", "../gateway-first-fonts-runtime", "/", "/tmp/../gateway-first-fonts-runtime", "/home/certbot-build-owner/gateway-first-fonts-runtime", "/srv/another"])
def test_bad_or_old_project_roots_refused(tmp_path,monkeypatch,location):
    root,*_=owner(tmp_path,monkeypatch)
    with pytest.raises(ValueError):
        migration.preview(root,project_root=location)


def test_inherited_schema_refuses_arbitrary_identity_override(tmp_path,monkeypatch):
    root,*_=owner(tmp_path,monkeypatch)
    spec=migration.preview(root,project_root="/srv/zog/gateway-first-fonts-runtime")["candidate_specification"]
    for change in ({"execution_user_id":24202},{"execution_group_id":24202},
                   {"execution_identity":"uid:24202"}):
        modified=copy.deepcopy(spec)
        modified["controller"].update(change)
        with pytest.raises(ValueError):
            lanes.validate(modified)
    with pytest.raises(ValueError):
        lanes.validate({**spec,"schema":4})


def test_legacy_approved_lane_cannot_be_activated_with_uid_override(tmp_path,monkeypatch):
    root,path,old,digest=owner(tmp_path,monkeypatch)
    monkeypatch.setattr(lanes,"Host",lambda *a,**kw:pytest.fail("must not contact Host"))
    with pytest.raises(RuntimeError,match="legacy first Fonts worker UID/GID"):
        lanes.activate(root,fonts.LANE,expected_specification_sha256=digest)
    assert json.loads(path.read_text())["state"]=="prepared"


def test_staged_candidate_cannot_be_activated_as_new_runtime(tmp_path,monkeypatch):
    root,path,old,_=owner(tmp_path,monkeypatch)
    preview=migration.preview(root,project_root="/srv/zog/gateway-first-fonts-runtime")
    # Staging is separate evidence; a v5 record would still need the revised
    # pinned image-build/box-control/root-control contract before activation.
    new=preview["candidate_specification"]
    save(path,{"schema":5,"lane":fonts.LANE,"specification":new,"state":"prepared"})
    monkeypatch.setattr(lanes,"Host",lambda *a,**kw: pytest.fail("must not contact Host"))
    with pytest.raises(RuntimeError,match="inherited execution requires a reviewed"):
        lanes.activate(root,fonts.LANE,expected_specification_sha256=preview["candidate_specification_sha256"])


def test_old_active_lane_cannot_bypass_migration_through_gateway(tmp_path,monkeypatch):
    from zog.host_deploy.gateway.image_build_dispatch import _load_lane_locked
    root,path,old,_=owner(tmp_path,monkeypatch)
    save(path,{"schema":4,"lane":fonts.LANE,"specification":old,"state":"active",
               "source_root":old["project_root"]+"/source",
               "package_dir":old["project_root"]+"/source/project/package",
               "state_dir":old["project_root"]+"/state",
               "controller_config":old["project_root"]+"/controller.json"})
    with pytest.raises(RuntimeError,match="requires a reviewed inherited-identity"):
        _load_lane_locked(root,fonts.LANE)


def test_migration_stage_rechecks_source_under_write_lock(tmp_path,monkeypatch):
    root,path,old,digest=owner(tmp_path,monkeypatch)
    real_preview=migration.preview
    def raced(*args,**kwargs):
        candidate=real_preview(*args,**kwargs)
        changed=json.loads(path.read_text())
        changed["state"]="active"
        save(path,changed)
        return candidate
    monkeypatch.setattr(migration,"preview",raced)
    with pytest.raises(RuntimeError,match="changed before migration staging"):
        migration.stage(root,project_root="/srv/zog/gateway-first-fonts-runtime")
    assert not (root/migration.FILE).exists()
