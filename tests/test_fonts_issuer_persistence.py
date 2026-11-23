"""Independent issuer restrictions and selected-unit verification, source-only."""
import copy
import hashlib

import pytest

from zog.host_deploy import fonts_issuer_persistence as issuer


def fixture():
    preserved = (b"[Service]\n"
                 b"ExecStartPre=/usr/bin/test -d /state/issuer\n"
                 b"ReadOnlyPaths=/state/issuer /var/lib/zog-certify-manage\n")
    original = b"[Service]\nExecStart=/old/controller\n"
    selected = b"[Service]\nExecStart=/selected/controller\n"
    metadata = {
        "name": issuer.ISSUER_DROPIN,
        "sha256": hashlib.sha256(preserved).hexdigest(),
        "size": len(preserved), "mode": 0o644, "uid": 0, "gid": 0,
    }
    effective = {
        "ExecStartPre": [{
            "path": "/usr/bin/test",
            "argv": "/usr/bin/test -d /state/issuer",
            "flags": {"ignore_errors": "no", "flags": ""},
        }],
        "ReadOnlyPaths": "/state/issuer /var/lib/zog-certify-manage",
        "Requires": "state.mount issuer-storage.mount",
        "After": "state.mount issuer-storage.mount",
    }
    selection = {
        "service": {
            "name": issuer.COMPILER_UNIT,
            "staged_sha256": hashlib.sha256(selected).hexdigest(),
        },
        "rollback": {"unit_sha256": hashlib.sha256(original).hexdigest()},
        "composition": {
            "original_dropins": [copy.deepcopy(metadata)],
            "selected_dropins": [copy.deepcopy(metadata)],
            "original_effective": copy.deepcopy(effective),
            "selected_effective": copy.deepcopy(effective),
        },
    }
    return selection, preserved


def test_independent_issuer_readback_retains_both_unit_digests_and_guard():
    selected, raw = fixture()
    before = copy.deepcopy(selected)
    report = issuer.verify(selected, raw, raw)
    assert report["applicable"] is True
    assert report["verified"] is True
    assert report["issuer_dropin_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["original_unit_sha256"] != report["selected_unit_sha256"]
    assert report["native_issuer_storage_verified"] is False
    assert report["startup_authorized"] is False
    assert selected == before


@pytest.mark.parametrize("mutation", [
    lambda s: s["composition"]["original_dropins"].clear(),
    lambda s: s["composition"]["selected_dropins"].clear(),
    lambda s: s["composition"]["selected_dropins"][0].update(mode=0o666),
    lambda s: s["composition"]["selected_dropins"][0].update(uid=1000),
    lambda s: s["composition"]["selected_dropins"][0].update(sha256="f" * 64),
    lambda s: s["composition"]["selected_effective"].update(ExecStartPre=[]),
    lambda s: s["composition"]["selected_effective"]["ExecStartPre"][0]["argv"].__class__,
    lambda s: s["composition"]["selected_effective"].update(ReadOnlyPaths="/tmp"),
    lambda s: s["composition"]["selected_effective"].update(Requires="state.mount"),
    lambda s: s["composition"]["selected_effective"].update(After="state.mount"),
])
def test_issuer_restrictions_cannot_be_removed(mutation):
    selected, raw = fixture()
    if mutation.__code__.co_consts and False:  # no side effects from condition
        raise AssertionError
    mutation(selected)
    if mutation.__code__.co_consts and False:
        raise AssertionError
    with pytest.raises(issuer.IssuerPersistenceHold):
        issuer.verify(selected, raw, raw)


@pytest.mark.parametrize("body", [
    b"[Service]\nExecStartPre=/usr/bin/true\nReadOnlyPaths=/state/issuer\n",
    b"[Service]\nExecStartPre=/usr/bin/test -d /state/issuer\n",
    b"[Service]\nReadOnlyPaths=/state/issuer\n",
    b"[Service]\nExecStartPre=\nReadOnlyPaths=/state/issuer\n",
    b"[Service]\nExecStartPre=-/usr/bin/test -d /state/issuer\nReadOnlyPaths=/state/issuer\n",
])
def test_modified_guard_bytes_or_semantics_fail(body):
    selected, raw = fixture()
    with pytest.raises(issuer.IssuerPersistenceHold):
        issuer.verify(selected, raw, body)


def test_both_manager_properties_must_contain_original_issuer_prestart():
    selected, raw = fixture()
    selected["composition"]["original_effective"]["ExecStartPre"][0]["argv"] = (
        "/usr/bin/test -f /state/issuer")
    selected["composition"]["selected_effective"]["ExecStartPre"][0]["argv"] = (
        "/usr/bin/test -f /state/issuer")
    with pytest.raises(issuer.IssuerPersistenceHold, match="prestart"):
        issuer.verify(selected, raw, raw)


def test_nonissuer_unit_cannot_silently_take_issuer_dropin():
    selected, raw = fixture()
    selected["service"]["name"] = "zog-other.service"
    with pytest.raises(issuer.IssuerPersistenceHold, match="unselected service"):
        issuer.verify(selected, raw, raw)
    selected["composition"]["original_dropins"] = []
    selected["composition"]["selected_dropins"] = []
    assert issuer.verify(selected, None, None) == {"applicable": False, "verified": False}


def test_compiler_unit_cannot_silently_omit_issuer_dropin():
    selected, raw = fixture()
    selected["composition"]["original_dropins"] = []
    selected["composition"]["selected_dropins"] = []
    with pytest.raises(issuer.IssuerPersistenceHold, match="missing"):
        issuer.verify(selected, None, None)
