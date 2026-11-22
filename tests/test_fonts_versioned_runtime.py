"""Source-only deployment selection and kernel-child admission regressions.

A fake /proc tree tests child identity without starting a compiler. The
root-owned installed-file test runs only on disposable CI paths as root.
"""
import base64
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
    # Deterministic test-only chain; production always inspects real /usr/bin.
    monkeypatch.setattr(runtime.legacy_rollback, "interpreter_chain",
        lambda root=Path("/"): [{"path": "/usr/bin/python3.12", "type": "file",
          "mode": 0o755, "uid": 0, "gid": 0, "size": 7,
          "sha256": _sha(b"mock-py")}])
    (original / "retained-controller.py").write_bytes(b"old unchanged controller")
    (original / "retained-producer.py").write_bytes(b"old unchanged producer")
    live = tmp_path / "old-runtime"
    live.mkdir()
    (live / "retained-controller.py").write_bytes(b"old unchanged controller")
    (live / "retained-producer.py").write_bytes(b"old unchanged producer")
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
    # RECORDs must bind actual critical-module paths, hashes and byte sizes,
    # not merely have an independently approved RECORD file hash.
    for record_role in sorted(runtime.SEPARATE_RECORD_ROLES):
        component = record_role.removesuffix("-record")
        module = next(x for x in files if x["role"] == component + "-module")
        record = next(x for x in files if x["role"] == record_role)
        relative = Path(module["path"]).relative_to(
            Path(record["path"]).parent.parent).as_posix()
        encoded = base64.urlsafe_b64encode(
            bytes.fromhex(module["sha256"])).decode("ascii").rstrip("=")
        line = (relative + ",sha256=" + encoded + "," + str(module["size"]) + chr(10)).encode()
        Path(record["path"]).write_bytes(line)
        record["sha256"], record["size"] = _sha(line), len(line)
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
            "original_runtime": str(live),
            "legacy_inventory_schema": runtime.legacy_rollback.SCHEMA,
            "runtime_tree_sha256": runtime.legacy_rollback.inventory(
                tmp_path, original)["tree_sha256"],
            "legacy_inventory_sha256": runtime.legacy_rollback.inventory(
                tmp_path, original)["inventory_sha256"],
            "python_interpreter_chain": runtime.legacy_rollback.inventory(
                tmp_path, original)["python_interpreter_chain"],
        },
        "composition": {
            "original_fragment": {
                "path": str(current), "sha256": _sha(old_bytes),
                "size": len(old_bytes), "mode": 0o644, "uid": 0, "gid": 0},
            "selected_fragment": {
                "path": str(staged), "sha256": _sha(new_bytes),
                "size": len(new_bytes), "mode": 0o644, "uid": 0, "gid": 0},
            "original_dropins": [], "selected_dropins": [],
            "original_effective": {
                **{key: "" for key in runtime.composition.KEYS
                   if key not in ("ExecStart", "ExecStartPre")},
                "ExecStart": [{"path": "/old/accepted/controller",
                               "argv": "/old/accepted/controller",
                               "flags": {"ignore_errors": "no", "flags": ""}}],
                "ExecStartPre": [],
            },
            "selected_effective": {
                **{key: "" for key in runtime.composition.KEYS
                   if key not in ("ExecStart", "ExecStartPre")},
                "ExecStart": [{"path": str(selected_exec),
                               "argv": str(selected_exec),
                               "flags": {"ignore_errors": "no", "flags": ""}}],
                "ExecStartPre": [],
            },
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



@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned disposable RECORD verification")
def test_stale_record_rejected_even_with_consistent_new_file_and_tree_hashes(
        tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    record = next(x for x in selected["files"]
                  if x["role"] == "image-build-record")
    target = Path(record["path"])
    tampered = b"zog/image_build/box_control_adapter.py,sha256=forged,5" + bytes([10])
    target.write_bytes(tampered)
    record["sha256"], record["size"] = _sha(tampered), len(tampered)
    root = Path(runtime.RELEASES) / selected["release_id"]
    selected["installed_tree_sha256"] = runtime._retained_tree_sha256(root)
    with pytest.raises(runtime.RuntimeHold, match="differs from distribution RECORD"):
        runtime.inspect_installed(selected)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned disposable RECORD verification")
def test_aggregate_zog_record_validates_all_three_exact_module_memberships(
        tmp_path, monkeypatch):
    selected, *_ = fixture_selection(tmp_path, monkeypatch)
    modules = [item for item in selected["files"]
               if item["role"] in runtime.MODULE_PATH_SUFFIXES]
    records = [item for item in selected["files"]
               if item["role"] in runtime.SEPARATE_RECORD_ROLES]
    selected["files"] = [item for item in selected["files"]
                         if item["role"] not in runtime.SEPARATE_RECORD_ROLES]
    for rec in records:
        Path(rec["path"]).unlink()
    site = Path(runtime.RELEASES) / selected["release_id"] / "lib/python3.12/site-packages"
    target = site / "zog-0.1.0.dist-info/RECORD"
    target.parent.mkdir()
    lines = []
    for module in modules:
        rel = Path(module["path"]).relative_to(site).as_posix()
        encoded = base64.urlsafe_b64encode(
            bytes.fromhex(module["sha256"])).decode("ascii").rstrip("=")
        lines.append(rel + ",sha256=" + encoded + "," + str(module["size"]))
    data = (chr(10).join(lines) + chr(10)).encode()
    target.write_bytes(data)
    selected["files"].append({
        "role": "zog-record", "path": str(target),
        "sha256": _sha(data), "size": len(data),
    })
    selected["installed_tree_sha256"] = runtime._retained_tree_sha256(
        Path(runtime.RELEASES) / selected["release_id"])
    assert runtime.inspect_installed(selected)["execution_authorized"] is False


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



def test_ordered_execstart_resets_require_final_compiler_runtime():
    c = runtime.composition
    fragment = b"[Service]\nExecStart=/opt/old/default.py\n"
    boot_a = b"[Service]\nExecStart=\nExecStart=/opt/old/boot-a.py\nReadOnlyPaths=/old/a\n"
    fonts = b"[Service]\nExecStart=\nExecStart=/opt/old/fonts.py\n"
    assert c.composed_exec(fragment, [boot_a, fonts]) == "/opt/old/fonts.py"
    with pytest.raises(c.CompositionHold, match="multiple ExecStart"):
        c.composed_exec(fragment, [b"[Service]\nExecStart=/another\n"])
    selected = b"[Service]\nExecStart=\nExecStart=/opt/new/compiler-runtime/bin/root-control\n"
    assert c.composed_exec(fragment, [boot_a, fonts, selected]).startswith("/opt/new/")


def test_dropin_set_must_be_complete_and_duplicate_free():
    c = runtime.composition
    fields = {key: "" for key in c.KEYS
              if key not in ("ExecStart", "ExecStartPre")}
    fields["ExecStart"] = [{
        "path": "/opt/reviewed/bin/controller",
        "argv": "/opt/reviewed/bin/controller",
        "flags": {"ignore_errors": "no", "flags": ""},
    }]
    fields["ExecStartPre"] = []
    fragment = {"path": "/etc/systemd/system/zog-root-control.service",
                "sha256": "a" * 64, "size": 18,
                "mode": 0o644, "uid": 0, "gid": 0}
    base = {"original_fragment": fragment, "selected_fragment": fragment,
            "original_dropins": [], "selected_dropins": [],
            "original_effective": fields, "selected_effective": fields}
    c.validate(base)
    bad = copy.deepcopy(base)
    item = {"name": "70-fonts.conf", "sha256": "a" * 64, "size": 8,
            "mode": 0o644, "uid": 0, "gid": 0}
    bad["selected_dropins"] = [item, item]
    with pytest.raises(c.CompositionHold, match="duplicate"):
        c.validate(bad)
    bad["selected_dropins"] = [dict(item, name="../foreign.conf")]
    with pytest.raises(c.CompositionHold, match="name"):
        c.validate(bad)


def _systemd_command(path, argv=None, *, pid=0, start="not set",
                     stop="not set", ignore_errors="no", flags=""):
    argv = argv if argv is not None else path
    extra = (" ; flags=" + flags) if flags else ""
    return ("{ path=" + path + " ; argv[]=" + argv
            + " ; ignore_errors=" + ignore_errors + extra
            + " ; start_time=[" + start + "]"
            + " ; stop_time=[" + stop + "]"
            + " ; pid=" + str(pid) + " ; code=(null) ; status=0 }")


def test_manager_loaded_effective_properties_and_foreign_dropins():
    c = runtime.composition
    service = "zog-certbot-seed-root.service"
    fragment = Path("/etc/systemd/system") / service
    original = {
        "ExecStart": _systemd_command("/opt/selected/bin/root-control", pid=113),
        "ExecStartPre": _systemd_command(
            "/usr/bin/test", "/usr/bin/test -d /state", pid=112),
        "ReadOnlyPaths": "/state /projects",
        "Requires": "b.mount a.mount", "After": "b.mount a.mount",
    }
    stable, observed = c.normalize_loaded_commands(original)
    assert observed["ExecStart"][0]["pid"] == "113"
    assert observed["ExecStartPre"][0]["pid"] == "112"

    def runner(args, **kwargs):
        fields = dict(original, FragmentPath=str(fragment),
                      DropInPaths=str(Path(str(fragment) + ".d") / "70-fonts.conf"),
                      LoadState="loaded")
        return type("Result", (), {"returncode": 0,
            "stdout": "".join(k + "=" + v + "\n" for k,v in fields.items())})()

    expected = {**stable, "Requires": "a.mount b.mount",
                "After": "a.mount b.mount"}
    checked = c.verify_loaded(service, fragment=fragment,
                              names=["70-fonts.conf"], expected=expected,
                              runner=runner)
    assert checked["process_metadata"] == observed
    with pytest.raises(c.CompositionHold, match="drop-ins"):
        c.verify_loaded(service, fragment=fragment, names=[],
                        expected=expected, runner=runner)
    with pytest.raises(c.CompositionHold, match="ReadOnlyPaths"):
        c.verify_loaded(service, fragment=fragment,
                        names=["70-fonts.conf"],
                        expected={**expected, "ReadOnlyPaths": "/old"},
                        runner=runner)


def test_changed_pid_or_timestamps_pass_changed_argv_and_flags_fail():
    """Both manager commands pin executable/argv/flags, not process execution."""
    c = runtime.composition
    service = "zog-certbot-seed-root.service"
    fragment = Path("/etc/systemd/system") / service
    path = str(fragment)
    baseline = {
        "ExecStart": _systemd_command(
            "/opt/staged/bin/root-control",
            "/opt/staged/bin/root-control --serve",
            pid=501, start="Sat 2026-11-21 09:00:00 AST",
            stop="Sat 2026-11-21 09:02:00 AST"),
        "ExecStartPre": _systemd_command(
            "/usr/bin/test", "/usr/bin/test -d /state",
            pid=500, start="Sat 2026-11-21 08:59:59 AST",
            stop="Sat 2026-11-21 09:00:00 AST"),
        "ReadOnlyPaths": "/state", "Requires": "state.mount",
        "After": "state.mount",
    }
    stable, original_metadata = c.normalize_loaded_commands(baseline)
    manager = dict(baseline)

    def runner(args, **kwargs):
        result = dict(manager, FragmentPath=path, DropInPaths="", LoadState="loaded")
        return type("Result", (), {
            "returncode": 0,
            "stdout": "".join(k + "=" + v + "\n" for k, v in result.items()),
        })()

    first = c.verify_loaded(service, fragment=fragment, names=[],
                            expected=stable, runner=runner)
    manager["ExecStart"] = _systemd_command(
        "/opt/staged/bin/root-control",
        "/opt/staged/bin/root-control --serve", pid=701,
        start="Sat 2026-11-21 12:00:00 AST",
        stop="Sat 2026-11-21 12:02:00 AST")
    manager["ExecStartPre"] = _systemd_command(
        "/usr/bin/test", "/usr/bin/test -d /state", pid=700,
        start="Sat 2026-11-21 11:59:59 AST",
        stop="Sat 2026-11-21 12:00:00 AST")
    second = c.verify_loaded(service, fragment=fragment, names=[],
                             expected=stable, runner=runner)
    assert second["effective"] == first["effective"] == stable
    assert second["process_metadata"] != original_metadata
    assert second["process_metadata"] != first["process_metadata"]

    manager["ExecStart"] = _systemd_command(
        "/opt/staged/bin/root-control",
        "/opt/staged/bin/root-control --different", pid=701)
    with pytest.raises(c.CompositionHold, match="ExecStart"):
        c.verify_loaded(service, fragment=fragment, names=[],
                        expected=stable, runner=runner)
    manager["ExecStart"] = baseline["ExecStart"]
    manager["ExecStartPre"] = _systemd_command(
        "/usr/bin/test", "/usr/bin/test -f /state", pid=700)
    with pytest.raises(c.CompositionHold, match="ExecStartPre"):
        c.verify_loaded(service, fragment=fragment, names=[],
                        expected=stable, runner=runner)
    manager["ExecStartPre"] = baseline["ExecStartPre"]
    manager["ExecStart"] = _systemd_command(
        "/opt/staged/bin/root-control",
        "/opt/staged/bin/root-control --serve",
        ignore_errors="yes", pid=900)
    with pytest.raises(c.CompositionHold, match="ExecStart"):
        c.verify_loaded(service, fragment=fragment, names=[],
                        expected=stable, runner=runner)
    manager["ExecStart"] = baseline["ExecStart"]
    manager["ExecStartPre"] = _systemd_command(
        "/usr/bin/test", "/usr/bin/test -d /state",
        flags="privileged", pid=900)
    with pytest.raises(c.CompositionHold, match="ExecStartPre"):
        c.verify_loaded(service, fragment=fragment, names=[],
                        expected=stable, runner=runner)


def test_source_composition_pins_prestart_argv_not_just_main_executable():
    c = runtime.composition
    fragment = b"[Service]\nExecStart=/old/controller\nExecStartPre=/usr/bin/test -d /state\n"
    dropins = [
        b"[Service]\nExecStart=\nExecStart=/opt/new/root-control --serve\n",
        b"[Service]\nExecStartPre=\nExecStartPre=/usr/bin/test -d /approved\n",
    ]
    expected = {
        "ExecStart": [{
            "path": "/opt/new/root-control",
            "argv": "/opt/new/root-control --serve",
            "flags": {"ignore_errors": "no", "flags": ""},
        }],
        "ExecStartPre": [{
            "path": "/usr/bin/test",
            "argv": "/usr/bin/test -d /approved",
            "flags": {"ignore_errors": "no", "flags": ""},
        }],
    }
    assert c.verify_composed(fragment, dropins, expected)
    altered = copy.deepcopy(expected)
    altered["ExecStartPre"][0]["argv"] = "/usr/bin/test -e /approved"
    with pytest.raises(c.CompositionHold, match="ExecStartPre"):
        c.verify_composed(fragment, dropins, altered)


def test_unit_ignore_errors_prefix_must_match_manager_flags():
    c = runtime.composition
    fragment = (b"[Service]\nExecStart=/opt/new/root-control\n"
                b"ExecStartPre=-/usr/bin/test -e /state\n")
    raw = {
        "ExecStart": _systemd_command("/opt/new/root-control"),
        "ExecStartPre": _systemd_command(
            "/usr/bin/test", "/usr/bin/test -e /state",
            ignore_errors="yes"),
        "ReadOnlyPaths": "", "Requires": "", "After": "",
    }
    stable, evidence = c.normalize_loaded_commands(raw)
    assert c.verify_composed(fragment, [], stable)
    changed = copy.deepcopy(stable)
    changed["ExecStartPre"][0]["flags"]["ignore_errors"] = "no"
    with pytest.raises(c.CompositionHold, match="execution flags"):
        c.verify_composed(fragment, [], changed)


def test_systemd_command_parser_fails_closed_on_unknown_or_missing_flags():
    c = runtime.composition
    for bad in (
        "{ path=/bin/test ; argv[]=/bin/test ; ignore_errors=no ; weird=1 ; }",
        "{ path=/bin/test ; argv[]=/bin/test ; pid=5 ; }",
        "{ path=/bin/test ; argv[]=/bin/test ; ignore_errors=no ; } { }",
    ):
        with pytest.raises(c.CompositionHold):
            c.normalize_loaded_commands({
                **{"Requires": "", "After": "", "ReadOnlyPaths": ""},
                "ExecStart": bad, "ExecStartPre": "",
            })


def test_legacy_rollback_four_literal_venv_links_and_copy(tmp_path):
    import shutil
    legacy = runtime.legacy_rollback
    old = tmp_path / "original"
    (old / "venv/bin").mkdir(parents=True)
    (old / "venv/lib").mkdir()
    (old / "venv/lib/module.py").write_bytes(b"old source stays byte-identical")
    external = tmp_path / "usr/bin/python3.12"
    external.parent.mkdir(parents=True)
    external.write_bytes(b"old external Python")
    for rel, target in legacy.LINKS.items():
        (old / rel).symlink_to(target)
    selected = legacy.inventory(tmp_path, old)
    copied = tmp_path / "copy"
    shutil.copytree(old, copied, symlinks=True)
    assert legacy.assert_copy(tmp_path, old, copied, expected=selected) == selected
    assert [r["target"] for r in selected["python_interpreter_chain"]
            if r["type"] == "symlink"] == []
    for rel, target in legacy.LINKS.items():
        assert (copied / rel).is_symlink()
        assert (copied / rel).readlink().as_posix() == target
    changed = copied / "venv/bin/python"
    changed.unlink()
    changed.symlink_to("python3")
    with pytest.raises(legacy.LegacyHold, match="target differs"):
        legacy.inventory(tmp_path, copied)


def test_legacy_rejects_unknown_links_hardlinks_and_escape(tmp_path):
    legacy = runtime.legacy_rollback
    tree = tmp_path / "original"
    (tree / "venv/bin").mkdir(parents=True)
    (tree / "base").write_bytes(b"stored object")
    ext = tmp_path / "usr/bin/python3.12"
    ext.parent.mkdir(parents=True)
    ext.write_bytes(b"external python")
    (tree / "unapproved").symlink_to("base")
    with pytest.raises(legacy.LegacyHold, match="unexpected"):
        legacy.inventory(tmp_path, tree)
    (tree / "unapproved").unlink()
    (tree / "venv/bin/python").symlink_to("../../../../outside")
    with pytest.raises(legacy.LegacyHold):
        legacy.inventory(tmp_path, tree)
    (tree / "venv/bin/python").unlink()
    os.link(tree / "base", tree / "hardlink")
    with pytest.raises(legacy.LegacyHold, match="hard-linked"):
        legacy.inventory(tmp_path, tree)


def test_legacy_external_python_chain_and_change(tmp_path):
    legacy = runtime.legacy_rollback
    external = tmp_path / "usr/bin/python3.12"
    external.parent.mkdir(parents=True)
    external.symlink_to("python3.12-real")
    actual = external.parent / "python3.12-real"
    actual.write_bytes(b"reviewed original executable")
    chain = legacy.interpreter_chain(tmp_path)
    assert [e["type"] for e in chain] == ["symlink", "file"]
    assert chain[0]["target"] == "python3.12-real"
    actual.write_bytes(b"unreviewed changed executable")
    assert legacy.interpreter_chain(tmp_path) != chain
    actual.unlink()
    actual.symlink_to("python3.12")
    with pytest.raises(legacy.LegacyHold, match="cycle"):
        legacy.interpreter_chain(tmp_path)


@pytest.mark.skipif(os.geteuid() != 0,
                    reason="selected-runtime invariant needs root-owned fixture")
def test_selected_immutable_runtime_link_still_holds(tmp_path):
    runtime_dir = tmp_path / "selected"
    runtime_dir.mkdir()
    (runtime_dir / "module.py").write_bytes(b"old")
    (runtime_dir / "python").symlink_to("module.py")
    with pytest.raises(runtime.RuntimeHold, match="linked"):
        runtime._retained_tree_sha256(runtime_dir)



@pytest.mark.skipif(os.geteuid() != 0,
                    reason="guard admission requires root-owned systemd fixture")
def test_reboot_persistent_guard_requires_exact_condition_and_absent_permit(tmp_path):
    from zog.host_deploy import fonts_unit_composition as composition
    release = "a" * 32
    target = tmp_path / "zog-certbot-seed-root.service.d"
    target.mkdir()
    contents = composition.transaction_guard_bytes(release)
    guard = target / composition.GUARD_NAME
    guard.write_bytes(contents)
    guard.chmod(0o644)
    record = composition.verify_transaction_guard(target, release)
    assert record["sha256"] == hashlib.sha256(contents).hexdigest()
    guard.write_bytes(b"[Unit]\nConditionPathExists=/tmp/unsafe-permit\n")
    with pytest.raises(composition.CompositionHold, match="startup guard differs"):
        composition.verify_transaction_guard(target, release)
    guard.write_bytes(contents)
    (target / "99-foreign.conf").write_bytes(b"[Service]\nExecStart=/foreign\n")
    expected = [record]
    with pytest.raises(composition.CompositionHold, match="drop-in set"):
        composition.verify(target, expected)



@pytest.mark.skipif(os.geteuid() != 0,
                    reason="guard admission requires root-owned systemd fixture")
def test_guard_must_be_last_dropin_to_prevent_condition_reset(tmp_path):
    from zog.host_deploy import fonts_unit_composition as composition
    release = "b" * 32
    directory = tmp_path / "root.service.d"
    directory.mkdir()
    guard = directory / composition.GUARD_NAME
    guard.write_bytes(composition.transaction_guard_bytes(release))
    guard.chmod(0o644)
    assert composition.verify_transaction_guard(directory, release)
    later = directory / "zzzzz-condition-reset.conf"
    later.write_bytes(b"[Unit]\nConditionPathExists=\n")
    with pytest.raises(composition.CompositionHold,
                       match="ordered after protective startup guard"):
        composition.verify_transaction_guard(directory, release)
