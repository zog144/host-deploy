"""Disposable native-only absent-history admission.

No root, systemd, retained Host, or live installer mutation. A separate
root-protected approval, exact host/boot/plan and real PID1 not-found readback
are all mandatory. Retained bad-setting behavior remains unchanged.
"""
from copy import deepcopy

import pytest

from zog.host_deploy.gateway import fresh_native_owner as owner


def _fixture(monkeypatch):
    shared = {
        "LoadState": "loaded", "ActiveState": "active", "MainPID": "1442",
        "InvocationID": "test-frozen-shared-identity",
        "ControlGroup": "/system.slice/zog-root-control.service",
        "FragmentPath": "/run/systemd/transient/zog-root-control.service",
    }
    absent = {
        "LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0",
        "InvocationID": "", "ControlGroup": "", "FragmentPath": "",
    }
    baseline = {
        "schema": owner.ABSENT_HISTORY_SCHEMA,
        "mode": "absent-history",
        "host_id": "i-disposable-test-20261030",
        "boot_id": "disposable-boot-a",
        "shared_unit": "zog-root-control.service",
        "root_control_show": shared,
        "historical_unit": "zog-image-build-original@build.service",
        "historical_show": absent,
        "historical_not_found_sha256": owner._sha(owner._bytes(absent)),
    }
    digest = owner._sha(owner._bytes(baseline))
    plan = {
        "sha256": "sha256:" + "a"*64,
        "host_id": baseline["host_id"],
        "installed": {
            "host_id": baseline["host_id"],
            "boot_id": baseline["boot_id"],
            "legacy_baseline_sha256": digest,
        },
    }
    approval = {
        "schema": owner.ABSENT_HISTORY_APPROVAL_SCHEMA,
        "status": "operator-approved",
        "scope": owner.ABSENT_HISTORY_SCOPE,
        "allow_absent_history": True,
        "host_id": baseline["host_id"],
        "boot_id": baseline["boot_id"],
        "plan_sha256": plan["sha256"],
        "legacy_baseline_sha256": digest,
        "shared_unit": baseline["shared_unit"],
        "historical_unit": baseline["historical_unit"],
    }
    protected = {
        owner.BASELINE_PATH: baseline,
        owner.PLAN_PATH: plan,
        owner.ABSENT_HISTORY_APPROVAL: approval,
    }
    actual = {baseline["shared_unit"]: shared,
              baseline["historical_unit"]: absent}
    seen = []
    def read(path):
        seen.append(("read", path))
        return deepcopy(protected[path])
    def show(unit):
        seen.append(("show", unit))
        return deepcopy(actual[unit])
    monkeypatch.setattr(owner, "_read_json", read)
    monkeypatch.setattr(owner, "_show", show)
    monkeypatch.setattr(owner, "_boot", lambda: "disposable-boot-a")
    return protected, actual, seen, digest


def test_absent_history_explicit_mode_accepts_only_exact_disposable_context(monkeypatch):
    protected, actual, seen, digest = _fixture(monkeypatch)
    assert owner._legacy() == digest
    assert ("read", owner.ABSENT_HISTORY_APPROVAL) in seen
    assert ("show", "zog-root-control.service") in seen
    assert ("show", "zog-image-build-original@build.service") in seen
    assert owner.NativeOwner().validate_old_baseline(digest) is None
    with pytest.raises(RuntimeError, match="historical controller"):
        owner.NativeOwner().validate_old_baseline("sha256:" + "0"*64)


@pytest.mark.parametrize("name,value", [
    ("status", "not-approved"), ("scope", "generic-host"),
    ("allow_absent_history", False), ("host_id", "i-retained"),
    ("boot_id", "old-boot"), ("plan_sha256", "sha256:"+"e"*64),
    ("legacy_baseline_sha256", "sha256:"+"a"*64),
    ("historical_unit", "another.service"),
    ("shared_unit", "root-control.service"),
])
def test_absent_history_denies_missing_or_mismatched_operator_approval(
        monkeypatch, name, value):
    protected, actual, seen, _ = _fixture(monkeypatch)
    protected[owner.ABSENT_HISTORY_APPROVAL][name] = value
    with pytest.raises(PermissionError, match="independent disposable"):
        owner._legacy()
    assert not any(event == "show" for event, _ in seen)


def test_absent_history_never_infers_approval_from_not_found(monkeypatch):
    protected, actual, seen, _ = _fixture(monkeypatch)
    del protected[owner.ABSENT_HISTORY_APPROVAL]
    with pytest.raises(PermissionError, match="independent disposable"):
        owner._legacy()
    assert not any(event == "show" for event, _ in seen)


@pytest.mark.parametrize("name,value", [
    ("mode", "retained"), ("schema", "host-deploy-old-v1"),
    ("historical_unit", "unsafe/../name.service"),
    ("historical_not_found_sha256", "sha256:" + "d"*64),
])
def test_absent_history_rejects_malformed_baseline(monkeypatch, name, value):
    protected, actual, seen, _ = _fixture(monkeypatch)
    protected[owner.BASELINE_PATH][name] = value
    with pytest.raises(RuntimeError, match="baseline"):
        owner._legacy()
    assert not any(event == "show" for event, _ in seen)


@pytest.mark.parametrize("name,value", [
    ("LoadState", "bad-setting"), ("ActiveState", "active"),
    ("MainPID", "10"), ("InvocationID", "unexpected-active"),
    ("ControlGroup", "/system.slice/x.service"),
    ("FragmentPath", "/run/systemd/transient/x.service"),
])
def test_absent_history_requires_fully_inactive_not_found_observation(
        monkeypatch, name, value):
    protected, actual, seen, _ = _fixture(monkeypatch)
    protected[owner.BASELINE_PATH]["historical_show"][name] = value
    # Even if adversary recomputes the inner SHA, signed disposable approval
    # is still tied to exact baseline and must not be accepted.
    protected[owner.BASELINE_PATH]["historical_not_found_sha256"] = owner._sha(
        owner._bytes(protected[owner.BASELINE_PATH]["historical_show"]))
    with pytest.raises((RuntimeError, PermissionError), match="baseline|approval"):
        owner._legacy()


def test_absent_history_requires_live_shared_and_historical_readback(monkeypatch):
    protected, actual, seen, _ = _fixture(monkeypatch)
    actual[protected[owner.BASELINE_PATH]["historical_unit"]]["LoadState"] = "loaded"
    with pytest.raises(RuntimeError, match="now present"):
        owner._legacy()
    actual[protected[owner.BASELINE_PATH]["historical_unit"]]["LoadState"] = "not-found"
    actual[protected[owner.BASELINE_PATH]["shared_unit"]]["InvocationID"] = "changed"
    with pytest.raises(RuntimeError, match="shared controller"):
        owner._legacy()


def test_retained_baseline_cannot_downgrade_automatically(monkeypatch):
    protected, actual, seen, _ = _fixture(monkeypatch)
    baseline = {
        "shared_unit": "zog-root-control.service",
        "root_control_show": deepcopy(actual["zog-root-control.service"]),
        "historical_unit": "zog-image-build-original@build.service",
        "historical_show": {
            "LoadState": "bad-setting", "ActiveState": "inactive",
            "MainPID": "0", "InvocationID": "",
        },
    }
    baseline["historical_bad_setting_sha256"] = owner._sha(
        owner._bytes(baseline["historical_show"]))
    protected[owner.BASELINE_PATH] = baseline
    actual["zog-image-build-original@build.service"] = deepcopy(
        baseline["historical_show"])
    assert owner._legacy() == owner._sha(owner._bytes(baseline))
    assert ("read", owner.ABSENT_HISTORY_APPROVAL) not in seen
    actual["zog-image-build-original@build.service"]["LoadState"] = "not-found"
    with pytest.raises(RuntimeError, match="bad-setting PID1 evidence"):
        owner._legacy()


def test_absent_disposable_mode_is_boot_and_plan_bound(monkeypatch):
    protected, actual, seen, digest = _fixture(monkeypatch)
    monkeypatch.setattr(owner, "_boot", lambda: "next-boot")
    with pytest.raises(PermissionError, match="approval"):
        owner._legacy()
    monkeypatch.setattr(owner, "_boot", lambda: "disposable-boot-a")
    protected[owner.PLAN_PATH]["installed"]["legacy_baseline_sha256"] = (
        "sha256:" + "3"*64)
    with pytest.raises(PermissionError, match="approval"):
        owner._legacy()
