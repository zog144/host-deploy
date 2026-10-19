"""Offline certificate delivery bridge tests; no nginx or network traffic."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from zog.host_deploy import certificate_delivery as bridge


def _candidate(tmp_path, *, host="candidate.example.org", uid=41951):
    if os.geteuid() != 0:
        pytest.skip("filesystem owner isolation tests require root")
    crypto = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    issuer = tmp_path / "issuer"
    consumer = tmp_path / "consumer"
    issuer.mkdir(mode=0o700)
    consumer.mkdir(mode=0o700)
    os.chown(issuer, uid, uid)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=30)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(expires)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    chain = cert.public_bytes(serialization.Encoding.PEM)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    issued = issuer / "publications" / "station-web" / fingerprint
    issued.mkdir(parents=True, mode=0o700)
    for path in (issued.parent.parent, issued.parent, issued):
        os.chown(path, uid, uid)
        path.chmod(0o700)
    receipt = {
        "schema": bridge.SOURCE_SCHEMA,
        "certificate_id": "station-web",
        "policy_sha256": "a" * 64,
        "certificate_fingerprint_sha256": fingerprint,
        "hostnames": [host], "expires_at": cert.not_valid_after_utc.isoformat(),
        "fullchain_sha256": hashlib.sha256(chain).hexdigest(),
        "key_sha256": hashlib.sha256(priv).hexdigest(),
        "state": "issuer-private-unbound",
    }
    for name, data in (("receipt.json", json.dumps(receipt).encode()),
                       ("fullchain.pem", chain), ("privkey.pem", priv)):
        destination = issued / name
        destination.write_bytes(data)
        destination.chmod(0o600)
        os.chown(destination, uid, uid)
    config = tmp_path / "candidate-nginx.conf"
    config.write_text(
        "events {}\\nhttp { server { listen 18091 ssl; "
        "ssl_certificate /etc/zog/tls/station-candidate/current/fullchain.pem; "
        "ssl_certificate_key /etc/zog/tls/station-candidate/current/privkey.pem; } }\\n"
    )
    config.chmod(0o644)
    policy = {
        "schema": bridge.SCHEMA, "service_id": "candidate-nginx",
        "certificate_id": "station-web", "hostnames": [host],
        "policy_sha256": "a" * 64, "issuer_state": str(issuer),
        "issuer_uid": uid, "peer_uid": uid,
        "consumer_root": str(consumer),
        "socket_path": str(tmp_path / "bridge.sock"),
        "socket_gid": uid, "nginx_unit": "candidate-nginx.service",
        "nginx_binary": "/usr/sbin/nginx",
        "nginx_config": str(config),
        "nginx_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "systemctl_binary": "/usr/bin/systemctl",
        "probe_host": "127.0.0.1", "probe_port": 18091,
        "probe_ca_file": "/etc/ssl/certs/ca-certificates.crt",
    }
    return policy, fingerprint, issued, consumer


def test_publish_generation_reload_probe_and_idempotent_retry(tmp_path):
    policy, fingerprint, source, consumer = _candidate(tmp_path)
    events = []
    def run(binary, argv):
        events.append((binary, tuple(argv)))
    def probe(selected, actual):
        events.append(("tls-verified", actual))
    result = bridge.publish(policy, fingerprint, execute=run, probe=probe)
    assert result["state"] == "browser-verified"
    assert result["idempotent"] is False
    assert (consumer / "current").readlink() == Path("generations") / fingerprint
    assert (consumer / "current" / "privkey.pem").read_bytes() == (source / "privkey.pem").read_bytes()
    assert (consumer / "generations" / fingerprint / "privkey.pem").stat().st_mode & 0o077 == 0
    assert (consumer / "delivery.json").exists()
    retained = json.loads((consumer / "delivery.json").read_text())
    assert retained["phase"] == "complete"
    assert retained["state"] == "browser-verified"
    assert events == [
        ("/usr/sbin/nginx", ("-t", "-q", "-c", policy["nginx_config"])),
        ("/usr/bin/systemctl", ("reload", "candidate-nginx.service")),
        ("tls-verified", fingerprint),
    ]
    assert bridge.publish(policy, fingerprint, execute=run, probe=probe)["idempotent"]
    assert events[-1] == ("tls-verified", fingerprint)
    assert len(events) == 4


def test_bad_policy_receipt_and_private_key_block_before_publication(tmp_path):
    policy, fingerprint, source, consumer = _candidate(tmp_path)
    for key, wrong in (("certificate_id", "other"), ("policy_sha256", "b"*64),
                       ("hostnames", ["different.example.org"])):
        with pytest.raises(bridge.DeliveryBlocked):
            bridge.publish({**policy, key: wrong}, fingerprint,
                           execute=lambda *args: pytest.fail("must not reload"))
        assert not (consumer / "current").exists()
    original = (source / "privkey.pem").read_bytes()
    (source / "privkey.pem").write_bytes(b"invalid private key")
    with pytest.raises(bridge.DeliveryBlocked, match="candidate-binding-mismatch"):
        bridge.publish(policy, fingerprint, execute=lambda *args: pytest.fail("must not reload"))
    assert not (consumer / "current").exists()
    (source / "privkey.pem").write_bytes(original)


def test_nginx_failure_rolls_back_pointer_and_records_evidence(tmp_path):
    policy, fingerprint, source, consumer = _candidate(tmp_path)
    def fail(binary, argv):
        if argv == ["reload", "candidate-nginx.service"]:
            # Only fail first reload; verified restoration reload can succeed.
            if not getattr(fail, "failed", False):
                fail.failed = True
                raise bridge.DeliveryBlocked("nginx-validation-or-reload-failed")
    with pytest.raises(bridge.DeliveryBlocked, match="delivery-rolled-back"):
        bridge.publish(policy, fingerprint, execute=fail, probe=lambda *args: None)
    assert not (consumer / "current").exists()
    journal = json.loads((consumer / "delivery.json").read_text())
    assert journal["phase"] == "rolled-back"
    assert journal["rollback"] == "previous-absence-restored-no-https-attestation"
    assert journal["state"] == "delivered"
    ok = bridge.publish(policy, fingerprint, execute=lambda *args: None,
                        probe=lambda *args: None)
    assert ok["state"] == "browser-verified"


def test_uncertain_journal_blocks_repeat_and_never_replays(tmp_path):
    policy, fingerprint, source, consumer = _candidate(tmp_path)
    (consumer / "delivery.json").write_text(json.dumps({
        "schema": bridge.SCHEMA, "service_id": policy["service_id"],
        "fingerprint": fingerprint, "phase": "uncertain", "previous": None,
        "state": "delivered"
    }))
    (consumer / "delivery.json").chmod(0o600)
    with pytest.raises(bridge.DeliveryBlocked, match="recovery-required"):
        bridge.publish(policy, fingerprint, execute=lambda *args: pytest.fail("no reload"))
    assert not (consumer / "current").exists()


def test_socket_request_is_only_exact_identity_not_an_ssm_or_shell_proxy():
    request = {
        "schema": bridge.REQUEST_SCHEMA, "service_id": "candidate-nginx",
        "certificate_id": "station-web", "fingerprint": "e"*64,
    }
    assert bridge.decode_request(json.dumps(request).encode()) == request
    for mutation in (
        {**request, "command": "sh -c 'id'"},
        {**request, "certificate_id": "../../other"},
        {**request, "fingerprint": "not-a-fingerprint"},
        {**request, "service_id": "/usr/bin/nginx"},
    ):
        with pytest.raises(bridge.DeliveryBlocked, match="invalid-request"):
            bridge.decode_request(json.dumps(mutation).encode())


def test_tls_service_policy_fails_closed_on_unknown_target_or_weak_identity(tmp_path):
    policy, fingerprint, source, consumer = _candidate(tmp_path)
    for change in (
        {"issuer_uid": 0}, {"peer_uid": 0},
        {"nginx_unit": "nginx.service;rm -rf /"},
        {"hostnames": ["fake.example.org", "fake.example.org"]},
        {"service_id": "../candidate"}, {"consumer_root": "/tmp/../unsafe"},
        {"probe_port": True},
        {"unknown_override": "yes"},
    ):
        with pytest.raises(bridge.DeliveryBlocked):
            bridge.policy_validate({**policy, **change})


def test_reviewed_recovery_reloads_previous_target_and_blocks_wrong_pointer(tmp_path):
    policy, fingerprint, _, consumer = _candidate(tmp_path)
    old = "b"*64
    (consumer / "generations").mkdir(mode=0o700)
    (consumer / "generations" / old).mkdir(mode=0o700)
    (consumer / "current").symlink_to("generations/" + fingerprint)
    (consumer / "delivery.json").write_text(json.dumps({
        "schema": bridge.SCHEMA, "service_id": policy["service_id"],
        "fingerprint": fingerprint, "phase": "uncertain",
        "previous": "generations/" + old, "state": "delivered",
    }))
    (consumer / "delivery.json").chmod(0o600)
    events = []
    result = bridge.recover_previous(
        policy, execute=lambda exe, argv: events.append((exe, argv)),
        probe=lambda config, sha: events.append(("probe", sha)),
    )
    assert result["state"] == "rolled-back"
    assert (consumer / "current").readlink() == Path("generations") / old
    assert events[-1] == ("probe", old)
    assert json.loads((consumer / "delivery.json").read_text())["phase"] == "rolled-back"
    with pytest.raises(bridge.DeliveryBlocked, match="recovery-not-applicable"):
        bridge.recover_previous(policy, execute=lambda *x: pytest.fail("no reload"))


def test_recovery_refuses_unrecognized_generation_without_reloading(tmp_path):
    policy, fingerprint, _, consumer = _candidate(tmp_path)
    (consumer / "current").symlink_to("generations/" + "a"*64)
    (consumer / "delivery.json").write_text(json.dumps({
        "schema": bridge.SCHEMA, "service_id": policy["service_id"],
        "fingerprint": fingerprint, "phase": "uncertain",
        "previous": "generations/" + "b"*64, "state": "delivered",
    }))
    (consumer / "delivery.json").chmod(0o600)
    with pytest.raises(bridge.DeliveryBlocked, match="unrecognized-current-generation"):
        bridge.recover_previous(policy, execute=lambda *args: pytest.fail("no changes"))


def test_issuer_source_symlink_denied(tmp_path):
    policy, fingerprint, issued, _ = _candidate(tmp_path)
    original = issued / "privkey.pem"
    redirected = issued / "redirected.pem"
    original.rename(redirected)
    original.symlink_to("redirected.pem")
    with pytest.raises((OSError, bridge.DeliveryBlocked)):
        bridge.publish(policy, fingerprint, execute=lambda *args: pytest.fail("no reload"))


def test_socketpair_peer_credentials_are_the_creating_process_identity(tmp_path):
    """A same-process socketpair cannot simulate a different issuer principal."""
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("Linux peer credential transport required")
    policy, _, _, _ = _candidate(tmp_path)
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a, b:
        # Linux socketpair captures the connecting process credentials.
        creator_uid = os.getuid()
        assert creator_uid != policy["peer_uid"]
        with pytest.raises(bridge.DeliveryBlocked, match="not-authorized"):
            bridge.authenticate_peer(a, policy)
        # This tests the primitive, not validity of a root-owned policy.
        assert bridge.authenticate_peer(a, {**policy, "peer_uid": creator_uid}) == creator_uid


def test_real_separate_process_issuer_uid_can_connect_but_wrong_uid_cannot(tmp_path):
    """Test a genuine non-root peer over a listening Unix socket."""
    if not hasattr(socket, "SO_PEERCRED") or os.geteuid() != 0:
        pytest.skip("Linux root needed to create separate UID peers")
    policy, _, _, _ = _candidate(tmp_path)
    # /tmp socket directory must be traversable by the dropped-UID child.
    with tempfile.TemporaryDirectory(prefix="zog-delivery-peer-") as directory:
        os.chmod(directory, 0o755)
        address = str(Path(directory) / "peer.sock")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.settimeout(8)
            listener.bind(address)
            os.chmod(address, 0o666)
            listener.listen(2)
            client_code = (
                "import socket,sys; s=socket.socket(socket.AF_UNIX); "
                "s.connect(sys.argv[1]); s.sendall(b'!'); s.close()"
            )
            for uid, accepted in ((policy["peer_uid"], True),
                                  (policy["peer_uid"] + 1, False)):
                child = subprocess.Popen(
                    [sys.executable, "-c", client_code, address],
                    user=uid, group=uid,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                with listener.accept()[0] as connection:
                    if accepted:
                        assert bridge.authenticate_peer(connection, policy) == uid
                    else:
                        with pytest.raises(bridge.DeliveryBlocked, match="not-authorized"):
                            bridge.authenticate_peer(connection, policy)
                _, errors = child.communicate(timeout=8)
                assert child.returncode == 0, errors.decode(errors="replace")[:300]


def test_lock_excludes_competing_publications(tmp_path):
    policy, fingerprint, _, consumer = _candidate(tmp_path)
    fd = bridge._open_dir(policy["consumer_root"], owner=0)
    try:
        locked = bridge._lock(fd)
        try:
            with pytest.raises(bridge.DeliveryBlocked, match="delivery-busy"):
                bridge.publish(
                    policy, fingerprint,
                    execute=lambda *args: pytest.fail("no nginx actions"),
                    probe=lambda *args: pytest.fail("no network"),
                )
        finally:
            os.close(locked)
    finally:
        os.close(fd)


def test_nginx_config_is_explicitly_bound_in_activation_and_recovery(tmp_path):
    policy, fingerprint, _, consumer = _candidate(tmp_path)
    commands = []
    bridge.publish(
        policy, fingerprint,
        execute=lambda exe, argv: commands.append((exe, list(argv))),
        probe=lambda *args: None,
    )
    assert (policy["nginx_binary"], [
        "-t", "-q", "-c", policy["nginx_config"]
    ]) in commands
    assert not any(argv == ["-t", "-q"] for exe, argv in commands)

    # Explicit uncertain-state recovery also checks the *same* configuration.
    journal = consumer / "delivery.json"
    retained = json.loads(journal.read_text())
    journal.write_text(json.dumps({**retained, "phase": "uncertain", "previous": None}))
    journal.chmod(0o600)
    commands.clear()
    bridge.recover_previous(
        policy, execute=lambda exe, argv: commands.append((exe, list(argv))),
        probe=lambda *args: None,
    )
    assert (policy["nginx_binary"], [
        "-t", "-q", "-c", policy["nginx_config"]
    ]) in commands


def test_nginx_config_drift_or_default_path_blocks_before_any_reload(tmp_path):
    policy, fingerprint, _, consumer = _candidate(tmp_path)
    with pytest.raises(bridge.DeliveryBlocked, match="invalid-policy"):
        bridge.policy_validate({**policy, "nginx_config": "/etc/nginx/nginx.conf"})
    with pytest.raises(bridge.DeliveryBlocked, match="invalid-policy"):
        bridge.policy_validate({**policy, "nginx_config_sha256": "wrong"})

    config = Path(policy["nginx_config"])
    config.write_text("events {}\\n# replaced after security review\\n")
    with pytest.raises(bridge.DeliveryBlocked, match="nginx-config-drift"):
        bridge.publish(
            policy, fingerprint,
            execute=lambda *args: pytest.fail("nginx must never be tested or reloaded"),
            probe=lambda *args: pytest.fail("no TLS probe"),
        )
    assert not (consumer / "current").exists()
    assert not (consumer / "delivery.json").exists()


def test_nginx_config_symlink_is_refused_before_reload(tmp_path):
    policy, fingerprint, _, _ = _candidate(tmp_path)
    config = Path(policy["nginx_config"])
    moved = config.with_name("actual-nginx.conf")
    config.rename(moved)
    config.symlink_to(moved.name)
    with pytest.raises((OSError, bridge.DeliveryBlocked)):
        bridge.publish(
            policy, fingerprint,
            execute=lambda *args: pytest.fail("must not invoke nginx"),
            probe=lambda *args: pytest.fail("no probe"),
        )
