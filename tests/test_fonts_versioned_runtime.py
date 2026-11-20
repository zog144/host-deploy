"""Source-only deployment selection and kernel-child admission regressions.

A fake /proc tree tests child identity without starting a compiler. The
root-owned installed-file test runs only on disposable CI paths as root.
"""
import copy
import hashlib
import os
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
    for role in sorted(runtime.REQUIRED_FILES):
        path = folder / "lib" / (role + ".py")
        path.parent.mkdir(parents=True, exist_ok=True)
        body = (role + "-installed-immutable").encode()
        path.write_bytes(body)
        files.append({"role": role, "path": str(path),
                      "sha256": _sha(body), "size": len(body)})
    selected = {
        "schema": runtime.SCHEMA, "contract": runtime.CONTRACT,
        "release_id": release,
        "sources": {
            role: {"revision": hexchar * 40, "source_tree_sha256": hexchar * 64}
            for role, hexchar in (("root-control", "b"), ("box-control", "c"),
                                  ("image-build", "d"))
        },
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
