"""Source-only deployment selection and kernel-child admission regressions.

A fake /proc tree tests child identity without starting a compiler. The
root-owned installed-file test runs only on disposable CI paths as root.
"""
import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from zog.host_deploy import fonts_versioned_runtime as runtime


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture_selection(tmp_path, monkeypatch):
    versions = tmp_path / "versions"
    rollbacks = tmp_path / "rollback"
    units = tmp_path / "units"
    for name, path in (("RELEASES", versions), ("ROLLBACK", rollbacks),
                       ("UNIT_DIR", units)):
        monkeypatch.setattr(runtime, name, str(path))
    release = "a" * 32
    folder = versions / release
    original = rollbacks / release / "original"
    original.mkdir(parents=True)
    (original / "retained-controller.py").write_bytes(b"old unchanged controller")
    (original / "retained-producer.py").write_bytes(b"old unchanged producer")
    old_bytes = b"[Service]\nExecStart=/old/accepted/controller\n"
    selected_exec = folder / "bin" / "controller-server"
    selected_exec.parent.mkdir(parents=True)
    selected_exec.write_bytes(b"#!/bin/sh\nexit 0\n")
    service_name = "zog-root-control.service"
    staged = folder / "systemd" / service_name
    staged.parent.mkdir(parents=True)
    new_bytes = ("[Service]\nExecStart=" + str(selected_exec) + "\n").encode()
    staged.write_bytes(new_bytes)
    current = units / service_name
    current.parent.mkdir(parents=True)
    current.write_bytes(old_bytes)
    saved = rollbacks / release / service_name
    saved.write_bytes(old_bytes)
    files = [{
        "role": "controller-executable", "path": str(selected_exec),
        "sha256": _sha(selected_exec.read_bytes()), "size": selected_exec.stat().st_size
    }]
    site = folder / "lib/python3.12/site-packages"
    for role in sorted(runtime.REQUIRED_FILES | runtime.SEPARATE_RECORD_ROLES):
        if role in runtime.MODULE_PATH_SUFFIXES:
            path = site / runtime.MODULE_PATH_SUFFIXES[role].lstrip("/")
        else:
            path = site / (role.replace("-record", "").replace("-", "_")
                           + "-0.1.0.dist-info/RECORD")
        path.parent.mkdir(parents=True, exist_ok=True)
        body = (role + "-installed-immutable").encode()
        path.write_bytes(body)
        files.append({"role": role, "path": str(path),
                      "sha256": _sha(body), "size": len(body)})
    selected = {
        "schema": runtime.SCHEMA, "contract": runtime.CONTRACT,
        "release_id": release,
        "sources": copy.deepcopy(runtime.SELECTED_SOURCES),
        "service": {
            "name": service_name,
            "staged_unit": str(staged),
            "active_unit": str(current),
            "staged_sha256": _sha(new_bytes), "exec_start": str(selected_exec),
        },
        "rollback": {
            "saved_unit": str(saved), "unit_sha256": _sha(old_bytes),
            "saved_runtime_root": str(original),
            "runtime_tree_sha256": (runtime._retained_tree_sha256(original)
                                    if os.geteuid() == 0 else "f" * 64),
        },
        "files": files,
        "installed_tree_sha256": (runtime._retained_tree_sha256(folder)
                                  if os.geteuid() == 0 else "e" * 64),
        "lane": {"name": "gateway-first-fonts-runtime",
                 "specification_sha256": "e" * 64, "enabled": False},
    }
    return selected, original, current, saved, new_bytes


def fake_proc(tmp_path, *, uid=1234, gid=1235, cgroup="/system.slice/zog-build-test.service"):
    proc = tmp_path / "proc"
    child = proc / "123"
    child.mkdir(parents=True, exist_ok=True)
    (child / "status").write_text(
        "Name:\tpython\nUid:\t{0}\t{0}\t{0}\t{0}\n"
        "Gid:\t{1}\t{1}\t{1}\t{1}\n".format(uid, gid))
    (child / "cgroup").write_text("0::" + cgroup + "\n")
    # 3..21 fields before field 22 (starttime) after the closing ')'.
    (child / "stat").write_text("123 (python) " + " ".join(
        ["S"] + ["0"] * 18 + ["1234567", "0", "0"]) + "\n")
    return proc, cgroup


def test_source_selection_is_immutable_hash_and_rollback_bound(tmp_path, monkeypatch):
    selection, _, _, _, _ = fixture_selection(tmp_path, monkeypatch)
    assert len(runtime.selection_sha256(selection)) == 64
    candidates = (
        ("lane", "enabled", True),
        ("service", "exec_start", "/usr/bin/python3"),
        ("service", "active_unit", "/tmp/foreign.service"),
        ("rollback", "saved_runtime_root", selection["service"]["exec_start"]),
        ("sources", "root-control", {"revision": "f"*40, "source_tree_sha256": "not-a-hash"}),
    )
    for group, key, value in candidates:
        modified = copy.deepcopy(selection)
        modified[group][key] = value
        with pytest.raises(runtime.RuntimeHold):
            runtime.validate(modified)
    modified = copy.deepcopy(selection)
    modified["files"][0]["execution_user_id"] = 24202
    with pytest.raises(runtime.RuntimeHold):
        runtime.validate(modified)
    modified = copy.deepcopy(selection)
    modified["contract"] = "legacy-with-user-selectors"
    with pytest.raises(runtime.RuntimeHold):
        runtime.validate(modified)


def test_missing_component_byte_or_duplicate_role_holds(tmp_path, monkeypatch):
    selection, _, _, _, _ = fixture_selection(tmp_path, monkeypatch)
    missing = copy.deepcopy(selection)
    missing["files"] = [f for f in missing["files"]
                        if f["role"] != "root-control-record"]
    with pytest.raises(runtime.RuntimeHold, match="incomplete"):
        runtime.validate(missing)
    duplicate = copy.deepcopy(selection)
    duplicate["files"].append(duplicate["files"][0])
    with pytest.raises(runtime.RuntimeHold, match="duplicate"):
        runtime.validate(duplicate)


def test_kernel_child_euid_egid_cgroup_bound_to_inherited_peer(tmp_path, monkeypatch):
    selection, _, _, _, _ = fixture_selection(tmp_path, monkeypatch)
    proc, group = fake_proc(tmp_path)
    observed = runtime.inspect_child_identity(
        selection, pid=123, peer_uid=1234, peer_gid=1235,
        unit_cgroup=group, proc_root=proc)
    assert (observed["effective_uid"], observed["effective_gid"]) == (1234, 1235)
    assert observed["selection_sha256"] == runtime.selection_sha256(selection)
    assert observed["execution_authorized"] is False
    assert observed["root_compilation_allowed"] is False


@pytest.mark.parametrize("uid,gid,peer_uid,peer_gid", [
    (0, 1235, 1234, 1235), (1234, 0, 1234, 1235),
    (1234, 1235, 0, 1235), (1234, 1235, 1234, 0),
    (1234, 1235, 5555, 1235), (1234, 1235, 1234, 5555),
])
def test_root_or_mismatched_peer_cannot_be_admitted(
        tmp_path, monkeypatch, uid, gid, peer_uid, peer_gid):
    selection, *_ = fixture_selection(tmp_path, monkeypatch)
    proc, group = fake_proc(tmp_path, uid=uid, gid=gid)
    with pytest.raises(runtime.RuntimeHold):
        runtime.inspect_child_identity(
            selection, pid=123, peer_uid=peer_uid, peer_gid=peer_gid,
            unit_cgroup=group, proc_root=proc)


def test_missing_or_foreign_child_kernel_evidence_holds(tmp_path, monkeypatch):
    selection, *_ = fixture_selection(tmp_path, monkeypatch)
    proc, group = fake_proc(tmp_path)
    with pytest.raises(runtime.RuntimeHold, match="cgroup"):
        runtime.inspect_child_identity(selection, pid=123, peer_uid=1234,
            peer_gid=1235, unit_cgroup="/system.slice/foreign.service",
            proc_root=proc)
    (proc / "123" / "status").unlink()
    with pytest.raises(runtime.RuntimeHold, match="cannot observe"):
        runtime.inspect_child_identity(selection, pid=123, peer_uid=1234,
            peer_gid=1235, unit_cgroup=group, proc_root=proc)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned disposable installed-byte test")
def test_root_owned_installed_selection_and_rollback_remain_read_only(tmp_path, monkeypatch):
    selection, original, active, saved, new_bytes = fixture_selection(tmp_path, monkeypatch)
    old_tree = runtime._retained_tree_sha256(original)
    report = runtime.inspect_installed(selection)
    assert report["phase"] == "staged"
    assert report["execution_authorized"] is False
    assert report["rollback_preserved"] is True
    assert active.read_bytes() == saved.read_bytes()
    active.write_bytes(new_bytes)
    report = runtime.inspect_installed(selection, phase="selected")
    assert report["phase"] == "selected"
    assert original.joinpath("retained-controller.py").read_bytes() == b"old unchanged controller"
    assert runtime._retained_tree_sha256(original) == old_tree


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned disposable installed-byte test")
def test_installed_byte_tampering_and_rollback_loss_hold(tmp_path, monkeypatch):
    selection, original, active, saved, new_bytes = fixture_selection(tmp_path, monkeypatch)
    target = Path(selection["files"][0]["path"])
    target.write_bytes(b"changed")
    with pytest.raises(runtime.RuntimeHold, match="length|SHA256"):
        runtime.inspect_installed(selection)
    target.write_bytes(b"#!/bin/sh\nexit 0\n")
    (original / "retained-producer.py").write_bytes(b"overwritten")
    with pytest.raises(runtime.RuntimeHold, match="retained previous runtime"):
        runtime.inspect_installed(selection)
    (original / "retained-producer.py").write_bytes(b"old unchanged producer")
    saved.unlink()
    with pytest.raises(runtime.RuntimeHold, match="cannot verify"):
        runtime.inspect_installed(selection)


def _make_checkout(folder):
    folder.mkdir()
    subprocess.run(["git", "init", "-q", str(folder)], check=True)
    (folder / "module.py").write_bytes(b"INHERITED_PEER = True\\n")
    subprocess.run(["git", "-C", str(folder), "add", "module.py"], check=True)
    subprocess.run(["git", "-C", str(folder), "-c", "user.email=review@invalid.example",
                    "-c", "user.name=Source Review", "commit", "-qm",
                    "select inherited source"], check=True)


def test_exact_clean_git_revision_and_sha256_tree_are_both_required(
        tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    checkouts = {}
    for role in runtime.COMPONENTS:
        path = tmp_path / ("source-" + role)
        _make_checkout(path)
        selected["sources"][role] = runtime.source_tree_sha256(path)
        checkouts[role] = path
    # This isolated Git-tree unit test uses synthetic repositories. Only its
    # explicit source tuple is changed, not the production pins.
    monkeypatch.setattr(runtime, "SELECTED_SOURCES",
                        copy.deepcopy(selected["sources"]))
    assert runtime.inspect_sources(selected, checkouts)["execution_authorized"] is False
    dirty = checkouts["root-control"]
    (dirty / "module.py").write_text("changed\\n")
    with pytest.raises(runtime.RuntimeHold, match="dirty"):
        runtime.inspect_sources(selected, checkouts)
    subprocess.run(["git", "-C", str(dirty), "restore", "module.py"], check=True)
    foreign = copy.deepcopy(selected)
    foreign["sources"]["box-control"]["source_tree_sha256"] = "f" * 64
    with pytest.raises(runtime.RuntimeHold, match="pinned tuple"):
        runtime.inspect_sources(foreign, checkouts)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned source selection fixture")
def test_external_manifest_pin_is_required_for_local_root_inspection(
        tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    custody = tmp_path / "selections"
    custody.mkdir()
    monkeypatch.setattr(runtime, "SELECTIONS", str(custody))
    path = custody / (selected["release_id"] + ".json")
    data = runtime.selection_bytes(selected)
    path.write_bytes(data)
    assert runtime.load_reviewed_selection(str(path), _sha(data)) == selected
    with pytest.raises(runtime.RuntimeHold, match="externally approved"):
        runtime.load_reviewed_selection(str(path), "0" * 64)
    path.write_text("{}")
    with pytest.raises(runtime.RuntimeHold, match="differ"):
        runtime.load_reviewed_selection(str(path), _sha(data))


def test_exact_reviewed_source_tuple_is_required_by_selection(tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    assert selected["sources"] == runtime.SELECTED_SOURCES
    expected = {
        "root-control": "58b5a94311d771bb1c5f4c3e9c6191b44d6565c9",
        "box-control": "ad61fa6a4e9c3176149720868cb008e0512dbec9",
        "image-build": "ff968a431dd2067e7d0e1f17d6e547f2779f647a",
    }
    assert {k: v["revision"] for k, v in runtime.SELECTED_SOURCES.items()} == expected
    for role in sorted(expected):
        swapped = copy.deepcopy(selected)
        swapped["sources"][role]["revision"] = "f" * 40
        with pytest.raises(runtime.RuntimeHold, match="pinned tuple"):
            runtime.validate(swapped)
        corrupted_tree = copy.deepcopy(selected)
        corrupted_tree["sources"][role]["source_tree_sha256"] = "f" * 64
        with pytest.raises(runtime.RuntimeHold, match="pinned tuple"):
            runtime.validate(corrupted_tree)


def test_installed_inventory_requires_bound_complete_tree_and_record(tmp_path, monkeypatch):
    selection, *_ = fixture_selection(tmp_path, monkeypatch)
    changed = copy.deepcopy(selection)
    changed["installed_tree_sha256"] = "not-a-digest"
    with pytest.raises(runtime.RuntimeHold, match="selected version complete installed tree"):
        runtime.validate(changed)
    changed = copy.deepcopy(selection)
    changed["files"] = [f for f in changed["files"]
                        if f["role"] != "image-build-record"]
    with pytest.raises(runtime.RuntimeHold, match="incomplete"):
        runtime.validate(changed)



@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned disposable installed inventory")
def test_capture_actual_module_record_and_complete_version_tree(tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    release = selected["release_id"]
    folder = Path(runtime.RELEASES) / release
    # The version selected for this capture test is a combined 'zog' wheel,
    # not the three separate component distributions from the selection fixture.
    for item in selected["files"]:
        if item["role"] in runtime.SEPARATE_RECORD_ROLES:
            Path(item["path"]).unlink()
    modules = {
        "root-control-module": "zog/root_control/build.py",
        "box-control-module": "zog/box_control/build_jobs.py",
        "image-build-module": "zog/image_build/box_control_adapter.py",
    }
    for role, rel in modules.items():
        path = folder / "lib/python3.12/site-packages" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((role + " from selected source").encode("ascii"))
    site = folder / "lib/python3.12/site-packages"
    record = site / "zog-0.1.0.dist-info/RECORD"
    record.parent.mkdir()
    record.write_bytes(b"zog/root_control/build.py,sha256=digest,5\n")
    evidence = runtime.capture_installed_inventory(release)
    assert evidence["sources"] == runtime.SELECTED_SOURCES
    assert evidence["independently_reviewed"] is False
    assert evidence["execution_authorized"] is False
    assert evidence["fonts_lane_enabled"] is False
    assert evidence["installed_tree_sha256"] == runtime._retained_tree_sha256(folder)
    assert evidence["file_count"] >= 6
    for role, rel in modules.items():
        selected_file = evidence["modules"][role]
        assert selected_file["path"] == str(site / rel)
        assert selected_file["sha256"] == _sha((site / rel).read_bytes())
    assert evidence["records"] == [{
        "path": str(record), "size": record.stat().st_size,
        "sha256": _sha(record.read_bytes()),
    }]
    assert any(x["path"].endswith("dist-info/RECORD")
               for x in evidence["complete_runtime_inventory"])
    record.unlink()
    with pytest.raises(runtime.RuntimeHold, match="RECORD absent"):
        runtime.capture_installed_inventory(release)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned disposable installed inventory")
def test_capture_refuses_ambiguous_or_missing_critical_module(tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    folder = Path(runtime.RELEASES) / selected["release_id"]
    for item in selected["files"]:
        if item["role"] in runtime.SEPARATE_RECORD_ROLES:
            Path(item["path"]).unlink()
    site = folder / "lib/python3.12/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    record = site / "zog-0.1.0.dist-info/RECORD"
    record.parent.mkdir()
    record.write_bytes(b"zog/box_control/build_jobs.py,sha256=digest,5\n")
    for role, rel in {
        "root-control": "zog/root_control/build.py",
        "box-control": "zog/box_control/build_jobs.py",
        "image-build": "zog/image_build/box_control_adapter.py",
    }.items():
        path = site / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(role)
    first = runtime.capture_installed_inventory(selected["release_id"])
    assert len(first["records"]) == 1
    duplicate = folder / "other/zog/root_control/build.py"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_text("duplicate")
    with pytest.raises(runtime.RuntimeHold, match="missing or ambiguous"):
        runtime.capture_installed_inventory(selected["release_id"])


def test_capture_requires_root_and_immutable_release_id(tmp_path, monkeypatch):
    fixture_selection(tmp_path, monkeypatch)
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    with pytest.raises(runtime.RuntimeHold, match="trusted root"):
        runtime.capture_installed_inventory("a" * 32)
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime.os, "getegid", lambda: 0)
    with pytest.raises(runtime.RuntimeHold, match="version ID"):
        runtime.capture_installed_inventory("../selected")



def test_combined_zog_record_selection_is_accepted_but_partial_records_hold(
        tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    for role in ("root-control-record", "box-control-record", "image-build-record"):
        selected["files"] = [f for f in selected["files"] if f["role"] != role]
    aggregate = {
        "role": "zog-record",
        "path": str(Path(runtime.RELEASES) / selected["release_id"]
                    / "lib/python3.12/site-packages/zog-0.1.0.dist-info/RECORD"),
        "size": 11, "sha256": _sha(b"record-here"),
    }
    selected["files"].append(aggregate)
    assert runtime.validate(selected) is selected
    partial = copy.deepcopy(selected)
    partial["files"].pop()
    partial["files"].append({
        "role": "root-control-record", "path": aggregate["path"],
        "size": 11, "sha256": aggregate["sha256"],
    })
    with pytest.raises(runtime.RuntimeHold, match="RECORD closure"):
        runtime.validate(partial)


def test_installed_module_paths_cannot_be_forged_by_role_label(tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    item = next(x for x in selected["files"]
                if x["role"] == "box-control-module")
    item["path"] = str(Path(runtime.RELEASES) / selected["release_id"]
                       / "lib/foreign-code.py")
    with pytest.raises(runtime.RuntimeHold, match="critical module path"):
        runtime.validate(selected)
