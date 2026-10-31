"""First graphical catalogue: exact producer/pins, no fabricated native inputs."""
from copy import deepcopy
import json

import pytest
from zog.host_deploy import image_build_lanes
from zog.host_deploy.gateway import task_catalogue
from zog.host_deploy.gateway import graphics_catalogue_owner as graphics

GEN = "e" * 64  # purely synthetic: NEVER production accepted base
RECEIPT = "sha256:" + "f" * 64
HOST = "host-source-fixture"
LANE = "graphics-protected-fixture"


def example():
    a = {
        "schema": graphics.APPROVAL_SCHEMA, "host_id": HOST,
        "installation_id": "fixture-installation", "lane": LANE,
        "lane_owner": HOST, "project_root": "/home/owner/"+LANE,
        "accepted_base_generation_id": GEN,
        "accepted_base_receipt_sha256": RECEIPT,
        "source_revision": graphics.SOURCE,
        "monthly_pin_identity": "sha256:"+graphics.PIN_SHA256,
        "task_allowlist": [graphics.TASK],
        "dedicated_storage_bytes": 32*1024**3,
        "work_bytes": 30*1024**3, "external_bytes": 2*1024**3,
        "execution_limit_seconds": 21600,
    }
    lane = image_build_lanes.specification(
        LANE, source_repository=graphics.REPOSITORY,
        source_revision=graphics.SOURCE,
        monthly_pin_repository_path=graphics.PIN_PATH,
        monthly_pin_identity="sha256:"+graphics.PIN_SHA256,
        provenance_host_id=HOST,
        provenance_project_id="test-project",
        project_root=a["project_root"],
        memory_maximum_bytes=2*1024**3,
        thread_count_maximum=16, cpu_weight=100,
        disk_reservation_bytes=32*1024**3,
        execution_user_id=24302, execution_group_id=24302,
        python_executable="/usr/bin/python3")
    base = {
        "schema": graphics.EVIDENCE_SCHEMA, "generation_id": GEN,
        "kind": "toolchain", "acceptance_receipt_sha256": RECEIPT,
        "source_repository": graphics.REPOSITORY,
        "verified_source_revision": "c"*40,
    }
    reservation = {
        "scope": graphics.aggregate.BUDGET_SCOPE,
        "work_bytes": 30*1024**3, "external_bytes": 2*1024**3,
    }
    return a, lane, base, reservation


def accepted_pin_bytes():
    """Fixed fixture cannot forge pin hash; real pin verified separately in CI."""
    import pathlib
    pin = pathlib.Path("dependencies/image-build/project/pins/2026-10-01/commit-pin.py")
    if not pin.is_file():
        pytest.skip("immutable image-build October file not checked out")
    return pin.read_bytes()


def test_source_and_october_pin_are_exact():
    assert graphics.SOURCE == "b0f53dbdec0e88b9b37feb5317398db3d20507dd"
    assert graphics.PIN_SHA256 == "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert graphics.PIN_PATH == "project/pins/2026-10-01/commit-pin.py"
    assert graphics.TASK == "graphics-fonts-image-v1"
    assert graphics.RECEIPT.name != graphics.CATALOGUE.name
    assert graphics.CATALOGUE.parent == graphics.RECEIPT.parent


def test_exact_pin_bytes_match_frozen_image_build_source():
    import hashlib
    b = accepted_pin_bytes()
    assert hashlib.sha256(b).hexdigest() == graphics.PIN_SHA256


def test_fonts_only_candidate_is_canonical_and_not_dispatch_admission():
    a,l,b,r = example()
    data = graphics.prepare(
        approval=a, lane_record=l, accepted_base=b,
        installed_pin_bytes=accepted_pin_bytes(), actual_reservation=r)
    assert data["compiler_authorized"] is False
    assert data["sha256"] == graphics._sha(data["bytes"])
    assert set(data["catalogue"]["tasks"]) == {graphics.TASK}
    cat = task_catalogue.loads(data["bytes"])
    assert cat == data["catalogue"]
    task = cat["tasks"][graphics.TASK]
    assert task["source_revision"] == graphics.SOURCE
    assert task["monthly_pin_identity"] == "sha256:"+graphics.PIN_SHA256
    assert task["lane_owner"] == HOST
    assert task["arguments"] == {
        "mode": "image", "selection": GEN,
        "targets": ["libpng-final", "freetype-final", "fontconfig-final"]}
    assert all(x not in cat["tasks"] for x in (
        "graphics-xcb-core-image-v1", "graphics-x11-core-image-v1",
        "xcb-support-image-v1"))


@pytest.mark.parametrize("part,key,value", [
    ("a","accepted_base_generation_id","0"*64),
    ("a","accepted_base_receipt_sha256","sha256:"+"0"*64),
    ("a","source_revision","a"*40),
    ("a","monthly_pin_identity","sha256:"+"0"*64),
    ("a","task_allowlist",["graphics-fonts-image-v1","graphics-xcb-core-image-v1"]),
    ("a","dedicated_storage_bytes",31*1024**3),
    ("a","execution_limit_seconds",21601),
    ("a","lane_owner","attacker"),
    ("a","accepted_base_generation_id","REPLACE-WITH-BASE"),
    ("l","source_revision","a"*40),
    ("l","provenance_host_id","attacker"),
    ("l","monthly_pin_identity","sha256:"+"0"*64),
    ("b","kind","image"),
    ("b","generation_id","d"*64),
    ("b","acceptance_receipt_sha256","sha256:"+"0"*64),
    ("r","work_bytes",29*1024**3),
    ("r","scope","other"),
])
def test_rejects_changed_pin_base_owner_allowlist_reservation(
        part,key,value):
    a,l,b,r = example()
    subject={"a":a,"l":l,"b":b,"r":r}[part]
    subject[key]=value
    with pytest.raises((graphics.GraphicalCatalogueBlocked, ValueError)):
        graphics.prepare(
            approval=a, lane_record=l, accepted_base=b,
            installed_pin_bytes=accepted_pin_bytes(), actual_reservation=r)


def test_rejects_wrong_original_pin_bytes():
    a,l,b,r = example()
    with pytest.raises(graphics.GraphicalCatalogueBlocked):
        graphics.prepare(approval=a, lane_record=l, accepted_base=b,
                         installed_pin_bytes=b"wrong source pin",
                         actual_reservation=r)


def test_root_only_native_install_cannot_be_called_by_regular_chat(monkeypatch):
    a,_,_,_ = example()
    monkeypatch.setattr(graphics.os, "geteuid", lambda: 1000)
    invoked=[]
    def forbidden(*args):
        invoked.append(True)
        raise AssertionError("native proof bypass")
    with pytest.raises(PermissionError):
        graphics.install_native(
            read_managed_lane=forbidden,
            read_accepted_base=forbidden, read_installed_pin=forbidden,
            attest_installed_source=forbidden, attest_host_identity=forbidden)
    assert not invoked


def test_no_automatic_native_install_or_compiler_dispatch():
    import inspect
    source=inspect.getsource(graphics)
    assert "toolchain.submit(" not in source
    assert "build.submit(" not in source
    assert "StartTransientUnit" not in source
    assert "os.O_EXCL" in source
    assert "require_root_owned=True" in source
    assert '"compiler_authorized": False' in source
    assert "attest_installed_source(SOURCE)" in source
    assert "read_accepted_base(" in source


def test_host_attestation_blocks_root_install_before_catalogue_write(monkeypatch):
    from zog.host_deploy.gateway import fresh_budget_guard, fresh_native_owner
    a, l, b, r = example()
    seen=[]
    monkeypatch.setattr(graphics.os,"geteuid",lambda: 0)
    monkeypatch.setattr(graphics.quota,"inspect",
                        lambda: {"capacity_bytes": 30*1024**3 - 4096})
    monkeypatch.setattr(graphics.aggregate,"inspect_external_pool_native",
                        lambda: {"limit_bytes": 2*1024**3 - 4096,
                                 "mount_verified":True,
                                 "allocation_verified":True,
                                 "budget_scope":graphics.aggregate.BUDGET_SCOPE})
    monkeypatch.setattr(fresh_budget_guard,"_protected_root",lambda p: True)
    monkeypatch.setattr(fresh_native_owner,"_read_json",lambda p:a)
    with pytest.raises(graphics.GraphicalCatalogueBlocked):
        graphics.install_native(
            read_managed_lane=lambda _: seen.append("lane"),
            read_accepted_base=lambda _: seen.append("base"),
            read_installed_pin=lambda *_: seen.append("pin"),
            attest_installed_source=lambda _:True,
            attest_host_identity=lambda *_:False)
    assert seen == []
