"""Selected broker root pin and native-disabled postflight source regressions."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json
import os

import pytest

from zog.host_deploy import certificate_selected_broker_authority as authority
from zog.host_deploy import certificate_renewal_timer as timer
from zog.host_deploy.certificate_renewal import RenewalBlocked


def identities():
    from zog.host_deploy.certificate_issuer_lifecycle import ISSUER_LIFECYCLE_BOX_CONTROL_REVISION
    record = {
        "schema": authority.SCHEMA,
        "host_id": "55555555-5555-4555-8555-555555555555",
        "installation_id": "11111111-1111-4111-8111-111111111111",
        "state_volume_id": "22222222-2222-4222-8222-222222222222",
        "certificate_id": "station-web", "hostnames": ["candidate.example.org"],
        "policy_sha256": "a" * 64,
        "host_policy_digest": "sha256:" + "b" * 64,
        "issuer_lifecycle_socket": "/run/zog/certify-lifecycle.sock",
        "controller_uid": 23001, "caller_uid": 23002,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "storage_id": "c" * 32, "grant_id": "d" * 32,
        "box_control_revision": ISSUER_LIFECYCLE_BOX_CONTROL_REVISION,
        "consumer_binding_sha256": "sha256:" + "9" * 64,
    }
    policy = {
        "certificate_id": "station-web", "policy_sha256": "a" * 64,
        "issuer_lifecycle_socket": "/run/zog/certify-lifecycle.sock",
    }
    inspector = {
        "certificate_id": "station-web", "policy_sha256": "a" * 64,
        "caller_uid": 23002, "issuer_uid": 24001,
        "hostnames": ["candidate.example.org"],
    }
    observer = {
        "certificate_id": "station-web", "policy_sha256": "a" * 64,
        "caller_uid": 23002, "issuer_uid": 24001, "issuer_gid": 24002,
        "host_policy_digest": "sha256:" + "b" * 64,
        "storage_id": "c" * 32, "grant_id": "d" * 32,
    }
    binding = {key: record[key] for key in (
        "host_id", "installation_id", "state_volume_id", "certificate_id",
        "hostnames", "policy_sha256")}
    return record, policy, inspector, observer, binding


def test_exact_root_authority_binds_uid_host_installation_and_issuer():
    record, policy, inspector, observer, binding = identities()
    assert authority.verify(policy, inspector, observer, binding,
                            root_reader=lambda: record)["controller_uid"] == 23001
    for key, replacement in (
        ("host_id", "foreign-host"), ("installation_id", "33333333-3333-4333-8333-333333333333"),
        ("state_volume_id", "44444444-4444-4444-8444-444444444444"),
        ("controller_uid", 23002), ("controller_uid", 0),
        ("controller_uid", None), ("issuer_uid", 23001),
        ("grant_id", "0" * 32), ("storage_id", "1" * 32),
        ("host_policy_digest", "sha256:" + "0" * 64),
        ("policy_sha256", "0" * 64),
        ("box_control_revision", "f" * 40),
        ("consumer_binding_sha256", "sha256:bad"),
        ("issuer_lifecycle_socket", "/tmp/foreign.sock"),
    ):
        with pytest.raises(RenewalBlocked, match="root-authority"):
            authority.verify(policy, inspector, observer, binding,
                             root_reader=lambda key=key, replacement=replacement: {
                                 **record, key: replacement})
    with pytest.raises(RenewalBlocked, match="root-authority"):
        authority.verify(policy, inspector, observer, binding,
                         root_reader=lambda: dict(record, unexpected="secret"))
    with pytest.raises(RenewalBlocked, match="root-authority"):
        authority.verify(policy, inspector, observer,
                         {**binding, "host_id": "different"},
                         root_reader=lambda: record)


def test_broker_root_reader_does_not_take_caller_selected_path():
    with pytest.raises(RenewalBlocked, match="root-authority"):
        authority._root_file("/tmp/forged.json")


def test_inspection_postflight_requires_distinct_saved_selected_result(monkeypatch):
    _, policy, inspector, observer, _ = identities()
    rid = "r1-1-" + "a" * 32 + "-" + "b" * 64
    fingerprint = "e" * 64
    proof = {
        "status": "journal-ready", "request_id": rid,
        "certificate_fingerprint_sha256": fingerprint,
        "outcome": "renewed", "host_policy_digest": observer["host_policy_digest"],
        "tls_ready": False,
    }
    monkeypatch.setattr(
        __import__("zog.host_deploy.certificate_issuer_inspection",
                   fromlist=["read_policy"]), "read_policy", lambda _: inspector)
    monkeypatch.setattr(
        __import__("zog.host_deploy.certificate_issuer_observer",
                   fromlist=["read_policy"]), "read_policy", lambda _: observer)
    selected = __import__("zog.host_deploy.certificate_selected_inspection",
                          fromlist=["tick"])
    seen = []
    def tick(*args, **kwargs):
        seen.append((args, kwargs))
        return {
            "phase": "verified", "request_id": "r1-1-" + "f" * 32 + "-" + "f" * 64,
            "fingerprint": fingerprint, "outcome": "renewed",
        }
    monkeypatch.setattr(selected, "tick", tick)
    ctrl = SimpleNamespace(_controller_uid=23001,
                           inspect_issuer_result=lambda request_id: None)
    cfg = {
        **policy, "issuer_inspection_policy_file": "/etc/zog/issuer-inspect.json",
        "issuer_observer_policy_file": "/etc/zog/issuer-observer.json",
        "journal_directory": "/protected/state",
    }
    assert timer._selected_postflight(
        cfg, ctrl, renewal_id=rid, fingerprint=fingerprint,
        outcome="renewed", renewal_proof=proof) is True
    assert seen[0][1]["original_renewal_id"] == rid
    assert seen[0][1]["trusted_renewal_observation"] is proof
    assert seen[0][1]["host_policy_digest"] == observer["host_policy_digest"]

    monkeypatch.setattr(selected, "tick", lambda *a, **k: {"phase": "submitted"})
    assert timer._selected_postflight(
        cfg, ctrl, renewal_id=rid, fingerprint=fingerprint,
        outcome="renewed", renewal_proof=proof) is False
    monkeypatch.setattr(selected, "tick", tick)
    for malformed in (
        {**proof, "outcome": "unchanged"},
        {**proof, "request_id": "foreign"},
        {**proof, "host_policy_digest": "sha256:"+"0"*64},
        {**proof, "tls_ready": True},
    ):
        with pytest.raises(RenewalBlocked):
            timer._selected_postflight(
                cfg, ctrl, renewal_id=rid, fingerprint=fingerprint,
                outcome="renewed", renewal_proof=malformed)
    with pytest.raises(RenewalBlocked, match="not-authenticated"):
        timer._selected_postflight(
            cfg, SimpleNamespace(inspect_issuer_result=lambda _: None),
            renewal_id=rid, fingerprint=fingerprint,
            outcome="renewed", renewal_proof=proof)
    # A caller's arbitrary truthy pin (including bool) cannot substitute
    # for an independently approved nonroot controller UID and callable reader.
    for malicious_uid in (None, True, 0, 999, 2**31, "23001"):
        with pytest.raises(RenewalBlocked, match="not-authenticated"):
            timer._selected_postflight(
                cfg, SimpleNamespace(_controller_uid=malicious_uid,
                                     inspect_issuer_result=lambda _: None),
                renewal_id=rid, fingerprint=fingerprint,
                outcome="renewed", renewal_proof=proof)
    with pytest.raises(RenewalBlocked, match="not-authenticated"):
        timer._selected_postflight(
            cfg, SimpleNamespace(_controller_uid=23001,
                                 inspect_issuer_result="issuer-supplied-text"),
            renewal_id=rid, fingerprint=fingerprint,
            outcome="renewed", renewal_proof=proof)


def test_timer_native_selected_gate_stays_disabled():
    with pytest.raises(RenewalBlocked, match="runtime-not-approved"):
        timer._require_approved_native_inspection(
            {"controller_backend": "selected-broker"})



@pytest.mark.parametrize("name", (
    authority.REVOCATION_NAME,
    ".pending." + authority.REVOCATION_NAME,
))
@pytest.mark.parametrize("kind", ("complete", "partial", "symlink", "directory"))
def test_any_revocation_or_interrupted_revocation_denies_broker(
        tmp_path, name, kind):
    parent = tmp_path / "root-owned-simulation"
    parent.mkdir()
    marker = parent / name
    if kind == "complete":
        marker.write_bytes(b'{"schema":"revoked"}')
    elif kind == "partial":
        marker.write_bytes(b'{"schema":')
    elif kind == "symlink":
        marker.symlink_to(parent / "not-present")
    else:
        marker.mkdir()
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(RenewalBlocked, match="root-authority-unverified"):
            authority._require_not_revoked(fd)
        # The authority consumer is a read-only observer, never a cleaner.
        assert marker.is_symlink() or marker.exists()
    finally:
        os.close(fd)


def test_absent_revocation_allows_only_existing_other_authority_checks(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        authority._require_not_revoked(fd)
        (tmp_path / "unrelated-cert.json").write_text("other owner")
        authority._require_not_revoked(fd)
    finally:
        os.close(fd)


def test_revocation_checker_cannot_be_bypassed_by_forged_root_reader():
    # verify(root_reader=...) is deliberately synthetic/test-only. Production
    # _root_file must retain both pre/post tombstone checks and exact path.
    import inspect
    source = inspect.getsource(authority._root_file)
    assert source.count("_require_not_revoked(descriptor)") == 2
    assert authority.REVOCATION_PATH == (
        "/etc/zog/host-deploy/certificate-issuer-broker-revoked.json"
    )
    assert "if path != ROOT_PATH:" in source



def test_existing_broker_client_rechecks_revocation_before_every_rpc():
    from zog.host_deploy.certificate_issuer_lifecycle import SelectedIssuerController
    from types import SimpleNamespace

    touched = []
    class FakeClient:
        def issue_application_request_id(self):
            touched.append("issue")
        def launch_application(self, *a, **kw):
            touched.append("launch")
        def application_request_result(self, rid):
            touched.append("result")
        def inspect_issuer_result(self, rid):
            touched.append("inspect")

    active = [True]
    controller = SelectedIssuerController(
        "/run/zog/certify-lifecycle.sock", controller_uid=23001,
        client_factory=lambda path, *, controller_uid: FakeClient(),
        authority_guard=lambda: active[0],
    )
    active[0] = False  # Revocation after client construction.
    rid = "r1-1-" + "a"*32 + "-" + "b"*64
    for call in (
        lambda: controller.issue_application_request_id(),
        lambda: controller.request_application_launch(
            "certify-manage", program_name="renew", request_id=rid,
        ),
        lambda: controller.application_request_result(rid),
        lambda: controller.inspect_issuer_result(rid),
    ):
        with pytest.raises(RenewalBlocked, match="root-authority-revoked"):
            call()
    assert touched == []


def test_timer_selected_broker_wires_original_root_file_rechecker(monkeypatch):
    from zog.host_deploy import certificate_issuer_lifecycle as issuer
    from zog.host_deploy import certificate_selected_broker_authority as broker
    from zog.host_deploy import certificate_issuer_inspection as insp
    from zog.host_deploy import certificate_issuer_observer as observer
    from zog.host_deploy import certificate_renewal_timer as timer_mod
    import pwd

    record, policy, inspection, observed, binding = identities()
    policy = {
        **policy, "issuer_inspection_policy_file": "/etc/zog/inspect.json",
        "issuer_observer_policy_file": "/etc/zog/observer.json",
        "controller_user": "zog-controller",
        "issuer_user": "zog-certify",
    }
    monkeypatch.setattr(insp, "read_policy", lambda _: inspection)
    monkeypatch.setattr(observer, "read_policy", lambda _: observed)
    monkeypatch.setattr(broker, "verify", lambda *a: record)
    active = [True]
    def checked_reader():
        if not active[0]:
            raise RenewalBlocked("selected-broker-root-authority-unverified")
        return record
    monkeypatch.setattr(broker, "_root_file", checked_reader)
    monkeypatch.setattr(os, "geteuid", lambda: record["caller_uid"])
    monkeypatch.setattr(pwd, "getpwnam", lambda name: SimpleNamespace(
        pw_uid=record["controller_uid"] if name == "zog-controller"
        else record["issuer_uid"]
    ))
    captured = []
    def selected(socket, *, controller_uid, authority_guard):
        captured.append((socket, controller_uid, authority_guard))
        return SimpleNamespace()
    monkeypatch.setattr(issuer, "SelectedIssuerController", selected)
    timer_mod._approved_selected_broker(policy)
    assert captured[0][0] == record["issuer_lifecycle_socket"]
    assert captured[0][1] == record["controller_uid"]
    assert captured[0][2]() is True
    active[0] = False
    with pytest.raises(RenewalBlocked, match="root-authority-unverified"):
        captured[0][2]()
