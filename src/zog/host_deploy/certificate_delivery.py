"""Root-owned certificate consumer delivery bridge (not an ACME issuer).

The Unix-socket peer can request only one pre-bound service and certificate.
No request contains a path, nginx unit, hostname, PEM bytes or shell command.
"""
from __future__ import annotations

from datetime import datetime, timezone
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
from uuid import uuid4

SCHEMA = "zog-host-deploy-cert-delivery-v1"
REQUEST_SCHEMA = "zog-host-deploy-cert-delivery-request-v1"
SOURCE_SCHEMA = "zog-certify-publication-candidate-v1"
FP = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
MAX_PEM = 1_048_576


class DeliveryBlocked(RuntimeError):
    """Only safe categories are emitted to socket peers."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _absolute(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or value == "/" or len(value) > 512 or
            any(x in ("", ".", "..") for x in value.split("/")[1:])
            or any(ord(x) < 33 for x in value)):
        raise DeliveryBlocked("invalid-policy")
    return value


def policy_validate(policy):
    required = {"schema", "service_id", "certificate_id", "hostnames",
                "policy_sha256", "issuer_state", "issuer_uid", "peer_uid",
                "consumer_root", "socket_path", "socket_gid", "nginx_unit",
                "nginx_binary", "nginx_config", "nginx_config_sha256",
                "systemctl_binary", "probe_host", "probe_port",
                "probe_ca_file"}
    if not isinstance(policy, dict) or set(policy) != required or policy["schema"] != SCHEMA:
        raise DeliveryBlocked("invalid-policy")
    if (not all(isinstance(policy[k], str) and ID.fullmatch(policy[k])
                for k in ("service_id", "certificate_id"))
            or not isinstance(policy["policy_sha256"], str)
            or not FP.fullmatch(policy["policy_sha256"])
            or not isinstance(policy["hostnames"], list)
            or not 1 <= len(policy["hostnames"]) <= 20
            or any(not isinstance(n, str) or not HOST.fullmatch(n)
                   or "." not in n or ".." in n for n in policy["hostnames"])
            or sorted(set(policy["hostnames"])) != policy["hostnames"]):
        raise DeliveryBlocked("invalid-policy")
    for name in policy["hostnames"]:
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            raise DeliveryBlocked("invalid-policy")
        if (any(not 1 <= len(label) <= 63 or label.startswith("-")
                or label.endswith("-") for label in name.split("."))):
            raise DeliveryBlocked("invalid-policy")
    for key in ("issuer_uid", "peer_uid", "socket_gid"):
        if type(policy[key]) is not int or not 0 <= policy[key] < 2**31:
            raise DeliveryBlocked("invalid-policy")
    if policy["issuer_uid"] == 0 or policy["peer_uid"] != policy["issuer_uid"]:
        raise DeliveryBlocked("invalid-policy")
    for key in ("issuer_state", "consumer_root", "socket_path", "nginx_binary",
                "nginx_config", "systemctl_binary", "probe_ca_file"):
        _absolute(policy[key])
    if (policy["issuer_state"] == policy["consumer_root"]
            or policy["nginx_config"] == "/etc/nginx/nginx.conf"
            or not isinstance(policy["nginx_config_sha256"], str)
            or FP.fullmatch(policy["nginx_config_sha256"]) is None):
        raise DeliveryBlocked("invalid-policy")
    if (not isinstance(policy["nginx_unit"], str)
            or not re.fullmatch(r"[a-zA-Z0-9_.@-]{1,128}\.service", policy["nginx_unit"])
            or not isinstance(policy["probe_host"], str)
            or not HOST.fullmatch(policy["probe_host"])
            or type(policy["probe_port"]) is not int
            or not 1 <= policy["probe_port"] <= 65535):
        raise DeliveryBlocked("invalid-policy")
    return json.loads(_canonical(policy))


def _open_dir(path, *, owner, private=True):
    """Component-by-component anchored open; no symlinks, unsafe ancestry or writable roots."""
    path = _absolute(str(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    crossed_owner = False
    try:
        for component in path.split("/")[1:]:
            nextfd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            info = os.fstat(nextfd)
            if info.st_uid not in (0, owner):
                os.close(nextfd)
                raise DeliveryBlocked("unsafe-directory")
            if info.st_uid == owner and owner != 0:
                crossed_owner = True
            if ((info.st_mode & 0o022) and
                not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                os.close(nextfd)
                raise DeliveryBlocked("unsafe-directory")
            if crossed_owner and info.st_uid == 0:
                os.close(nextfd)
                raise DeliveryBlocked("unsafe-directory")
            os.close(fd)
            fd = nextfd
        last = os.fstat(fd)
        if last.st_uid != owner or (private and last.st_mode & 0o077):
            raise DeliveryBlocked("unsafe-directory")
        return fd
    except Exception:
        os.close(fd)
        raise


def _read(fd, filename, *, owner, private=False, limit=MAX_PEM):
    descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_nlink != 1 or info.st_size > limit
                or (info.st_mode & (0o077 if private else 0o022))):
            raise DeliveryBlocked("unsafe-candidate")
        content = os.read(descriptor, limit + 1)
        if len(content) > limit:
            raise DeliveryBlocked("unsafe-candidate")
        return content
    finally:
        os.close(descriptor)


def _write(fd, name, raw, mode=0o600):
    desc = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                   mode, dir_fd=fd)
    try:
        with os.fdopen(desc, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        pass


def _replace_json(fd, name, data):
    pending = ".pending-" + uuid4().hex
    try:
        _write(fd, pending, _canonical(data))
        os.rename(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(pending, dir_fd=fd)
        except FileNotFoundError:
            pass


def _receipt_material(policy, fingerprint):
    if not isinstance(fingerprint, str) or FP.fullmatch(fingerprint) is None:
        raise DeliveryBlocked("invalid-request")
    try:
        root = _open_dir(policy["issuer_state"], owner=policy["issuer_uid"])
        try:
            # Open each child by anchored descriptor; never follow issuer symlinks.
            fd = root
            try:
                for part in ("publications", policy["certificate_id"], fingerprint):
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=fd
                    )
                    info = os.fstat(child)
                    if info.st_uid != policy["issuer_uid"] or info.st_mode & 0o077:
                        os.close(child)
                        raise DeliveryBlocked("unsafe-candidate")
                    if fd != root:
                        os.close(fd)
                    fd = child
                receipt_bytes = _read(fd, "receipt.json", owner=policy["issuer_uid"], limit=8192)
                key = _read(fd, "privkey.pem", owner=policy["issuer_uid"], private=True)
                chain = _read(fd, "fullchain.pem", owner=policy["issuer_uid"], private=True)
            finally:
                if fd != root:
                    os.close(fd)
        finally:
            os.close(root)
    except OSError:
        raise DeliveryBlocked("candidate-unavailable") from None
    try:
        receipt = json.loads(receipt_bytes)
    except (ValueError, UnicodeError):
        raise DeliveryBlocked("invalid-candidate") from None
    required = {"schema", "certificate_id", "policy_sha256",
                "certificate_fingerprint_sha256", "hostnames", "expires_at",
                "fullchain_sha256", "key_sha256", "state"}
    if (not isinstance(receipt, dict) or set(receipt) != required
            or receipt["schema"] != SOURCE_SCHEMA
            or receipt["state"] != "issuer-private-unbound"
            or receipt["certificate_id"] != policy["certificate_id"]
            or receipt["policy_sha256"] != policy["policy_sha256"]
            or receipt["certificate_fingerprint_sha256"] != fingerprint
            or receipt["hostnames"] != policy["hostnames"]
            or receipt["fullchain_sha256"] != hashlib.sha256(chain).hexdigest()
            or receipt["key_sha256"] != hashlib.sha256(key).hexdigest()):
        raise DeliveryBlocked("candidate-binding-mismatch")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import ExtensionOID
        certificates = x509.load_pem_x509_certificates(chain)
        if not certificates or len(certificates) > 12:
            raise ValueError("chain length")
        leaf = certificates[0]
        private = serialization.load_pem_private_key(key, password=None)
        pub = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_pub = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        names = sorted(leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName))
        current = datetime.now(timezone.utc)
        if (pub != key_pub or names != policy["hostnames"]
                or leaf.fingerprint(hashes.SHA256()).hex() != fingerprint
                or leaf.not_valid_before_utc > current
                or (leaf.not_valid_after_utc - current).total_seconds() < 86400
                or leaf.not_valid_after_utc.isoformat() != receipt["expires_at"]):
            raise ValueError("leaf binding")
        for child, issuer in zip(certificates, certificates[1:]):
            if child.issuer != issuer.subject:
                raise ValueError("chain order")
            child.verify_directly_issued_by(issuer)
    except Exception:
        raise DeliveryBlocked("invalid-certificate") from None
    return chain, key, receipt


def _current(fd):
    try:
        target = os.readlink("current", dir_fd=fd)
    except FileNotFoundError:
        return None
    if not re.fullmatch(r"generations/[0-9a-f]{64}", target):
        raise DeliveryBlocked("unsafe-current-pointer")
    return target


def _swap(fd, target):
    if target is None:
        try:
            os.unlink("current", dir_fd=fd)
        except FileNotFoundError:
            pass
    else:
        pending = ".current-" + uuid4().hex
        os.symlink(target, pending, dir_fd=fd)
        try:
            os.rename(pending, "current", src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            try:
                os.unlink(pending, dir_fd=fd)
            except FileNotFoundError:
                pass
    os.fsync(fd)


def _run(binary, arguments):
    result = subprocess.run([binary, *arguments], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=35, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"})
    if result.returncode != 0:
        raise DeliveryBlocked("nginx-validation-or-reload-failed")


def _check_bound_nginx_config(policy):
    """No ambient/default config: reviewed, root-owned candidate file only."""
    path = Path(policy["nginx_config"])
    try:
        parent_fd = _open_dir(str(path.parent), owner=0, private=False)
        try:
            raw = _read(parent_fd, path.name, owner=0, limit=MAX_PEM)
        finally:
            os.close(parent_fd)
    except OSError:
        raise DeliveryBlocked("nginx-config-unavailable") from None
    if hashlib.sha256(raw).hexdigest() != policy["nginx_config_sha256"]:
        raise DeliveryBlocked("nginx-config-drift")


def _test_bound_nginx_config(policy, execute):
    _check_bound_nginx_config(policy)
    execute(policy["nginx_binary"], [
        "-t", "-q", "-c", policy["nginx_config"]
    ])


def _probe(policy, fingerprint):
    context = ssl.create_default_context(cafile=policy["probe_ca_file"])
    context.check_hostname = True
    with socket.create_connection((policy["probe_host"], policy["probe_port"]), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=policy["hostnames"][0]) as tls:
            der = tls.getpeercert(binary_form=True)
            if hashlib.sha256(der).hexdigest() != fingerprint:
                raise DeliveryBlocked("active-certificate-mismatch")


def _generation(fd, fingerprint, chain, key, receipt):
    try:
        os.mkdir("generations", 0o700, dir_fd=fd)
    except FileExistsError:
        pass
    versions = os.open("generations", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        if os.fstat(versions).st_uid != 0 or os.fstat(versions).st_mode & 0o077:
            raise DeliveryBlocked("unsafe-consumer-root")
        try:
            gen = os.open(fingerprint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=versions)
        except FileNotFoundError:
            pending = ".candidate-" + uuid4().hex
            os.mkdir(pending, 0o700, dir_fd=versions)
            child = os.open(pending, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=versions)
            try:
                _write(child, "fullchain.pem", chain)
                _write(child, "privkey.pem", key)
                _write(child, "receipt.json", _canonical(receipt))
                os.fsync(child)
            finally:
                os.close(child)
            os.rename(pending, fingerprint, src_dir_fd=versions, dst_dir_fd=versions)
            os.fsync(versions)
            gen = os.open(fingerprint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=versions)
        try:
            if os.fstat(gen).st_uid != 0 or os.fstat(gen).st_mode & 0o077:
                raise DeliveryBlocked("unsafe-generation")
            for filename, expected in (("fullchain.pem", chain), ("privkey.pem", key),
                                       ("receipt.json", _canonical(receipt))):
                if _read(gen, filename, owner=0, private=True) != expected:
                    raise DeliveryBlocked("generation-conflict")
        finally:
            os.close(gen)
    finally:
        os.close(versions)


def _journal(fd):
    try:
        return json.loads(_read(fd, "delivery.json", owner=0, private=True, limit=8192))
    except FileNotFoundError:
        return None
    except (TypeError, ValueError, UnicodeError):
        raise DeliveryBlocked("invalid-delivery-journal") from None


def _lock(fd):
    descriptor = os.open(".delivery.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=fd)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o077):
        os.close(descriptor)
        raise DeliveryBlocked("unsafe-delivery-lock")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise DeliveryBlocked("delivery-busy") from None
    return descriptor


def publish(policy, fingerprint, *, execute=_run, probe=_probe):
    """Owner-only activation; crash uncertainty blocks further mutation."""
    if os.geteuid() != 0:
        raise DeliveryBlocked("not-authorized")
    policy = policy_validate(policy)
    chain, key, receipt = _receipt_material(policy, fingerprint)
    fd = _open_dir(policy["consumer_root"], owner=0)
    try:
        lock = _lock(fd)
    except Exception:
        os.close(fd)
        raise
    try:
        old = _journal(fd)
        if old is not None and old.get("phase") not in ("complete", "rolled-back"):
            raise DeliveryBlocked("recovery-required")
        current = _current(fd)
        if (old and old.get("phase") == "complete"
                and (not isinstance(old.get("fingerprint"), str)
                     or FP.fullmatch(old["fingerprint"]) is None
                     or current != "generations/" + old["fingerprint"])):
            raise DeliveryBlocked("current-pointer-drift")
        if (old and old.get("phase") == "rolled-back"
                and current != old.get("previous")):
            raise DeliveryBlocked("current-pointer-drift")
        if (old and old.get("phase") == "complete"
                and old.get("fingerprint") == fingerprint
                and current == "generations/" + fingerprint):
            probe(policy, fingerprint)
            return {"schema": SCHEMA, "state": "browser-verified", "fingerprint": fingerprint,
                    "service_id": policy["service_id"], "idempotent": True}
        # Reject stale or redirected nginx configuration before touching the
        # current generation or writing a new delivery intent.
        _check_bound_nginx_config(policy)
        _generation(fd, fingerprint, chain, key, receipt)
        report = {"schema": SCHEMA, "service_id": policy["service_id"],
                  "fingerprint": fingerprint, "previous": current,
                  "state": "delivered", "phase": "uncertain"}
        _replace_json(fd, "delivery.json", report)
        newtarget = "generations/" + fingerprint
        pointer_changed = False
        try:
            _swap(fd, newtarget)
            pointer_changed = True
            _test_bound_nginx_config(policy, execute)
            execute(policy["systemctl_binary"], ["reload", policy["nginx_unit"]])
            report["state"] = "nginx-loaded"
            _replace_json(fd, "delivery.json", report)
            probe(policy, fingerprint)
            report["state"] = "browser-verified"
            report["phase"] = "complete"
            _replace_json(fd, "delivery.json", report)
            return {"schema": SCHEMA, "state": "browser-verified",
                    "service_id": policy["service_id"], "fingerprint": fingerprint,
                    "idempotent": False}
        except Exception:
            try:
                if pointer_changed:
                    _swap(fd, current)
                    _test_bound_nginx_config(policy, execute)
                    execute(policy["systemctl_binary"], ["reload", policy["nginx_unit"]])
                    if current is not None:
                        probe(policy, current.split("/")[1])
                report["phase"] = "rolled-back"
                report["state"] = "delivered"
                report["rollback"] = ("previous-generation-restored-and-verified"
                                      if current is not None
                                      else "previous-absence-restored-no-https-attestation")
                _replace_json(fd, "delivery.json", report)
                raise DeliveryBlocked("delivery-rolled-back") from None
            except DeliveryBlocked as error:
                if error.code == "delivery-rolled-back":
                    raise
                raise DeliveryBlocked("rollback-uncertain") from None
            except Exception:
                raise DeliveryBlocked("rollback-uncertain") from None
    finally:
        os.close(lock)
        os.close(fd)


def publish_authorized(policy, fingerprint, *, authority_path, execute=_run,
                       probe=_probe):
    """Versioned host-owner gate around the unchanged v1 root delivery bridge.

    Caller provides only a root-owned authority receipt path, not web-supplied
    authorization. The receipt binds this machine's local HTTPS service and
    exact staged issuer policy. The bridge never delivers keys to a relay.
    """
    from .certificate_hostname_authority import (
        read_owned, authorize_consumer, AuthorityBlocked,
    )
    if os.geteuid() != 0:
        raise DeliveryBlocked("not-authorized")
    policy = policy_validate(policy)
    try:
        authority = read_owned(authority_path, now=datetime.now(timezone.utc).timestamp())
        selection = authorize_consumer(authority, policy,
                    now=datetime.now(timezone.utc).timestamp())
        if selection["consumer"] != policy["service_id"]:
            raise AuthorityBlocked("not-local-consumer")
    except (AuthorityBlocked, OSError, TypeError, ValueError):
        raise DeliveryBlocked("hostname-authority-unavailable") from None
    # Time-of-check versus publication authority revocation must be handled by
    # the protected policy owner during deployment. No network/web receipt
    # is ever treated as the privileged authority.
    return publish(policy, fingerprint, execute=execute, probe=probe)


def recover_previous(policy, *, execute=_run, probe=_probe):
    """Explicit root-operator recovery of an uncertain publication.

    This never installs a new candidate. No silent replay on service restart.
    """
    if os.geteuid() != 0:
        raise DeliveryBlocked("not-authorized")
    policy = policy_validate(policy)
    fd = _open_dir(policy["consumer_root"], owner=0)
    try:
        lock = _lock(fd)
    except Exception:
        os.close(fd)
        raise
    try:
        journal = _journal(fd)
        if (not isinstance(journal, dict) or journal.get("schema") != SCHEMA
                or journal.get("service_id") != policy["service_id"]
                or journal.get("phase") != "uncertain"
                or not isinstance(journal.get("fingerprint"), str)
                or FP.fullmatch(journal["fingerprint"]) is None):
            raise DeliveryBlocked("recovery-not-applicable")
        previous = journal.get("previous")
        if previous is not None and not re.fullmatch(r"generations/[a-f0-9]{64}", previous):
            raise DeliveryBlocked("invalid-delivery-journal")
        current = _current(fd)
        if current not in (previous, "generations/" + journal["fingerprint"]):
            raise DeliveryBlocked("unrecognized-current-generation")
        _check_bound_nginx_config(policy)
        try:
            _swap(fd, previous)
            _test_bound_nginx_config(policy, execute)
            execute(policy["systemctl_binary"], ["reload", policy["nginx_unit"]])
            if previous is not None:
                probe(policy, previous.split("/")[1])
        except Exception:
            raise DeliveryBlocked("rollback-uncertain") from None
        journal["phase"] = "rolled-back"
        journal["state"] = "delivered"
        journal["rollback"] = ("previous-generation-reloaded-and-verified"
                               if previous is not None
                               else "previous-absence-restored-no-https-attestation")
        _replace_json(fd, "delivery.json", journal)
        return {"schema": SCHEMA, "service_id": policy["service_id"],
                "state": "rolled-back", "safe_to_cut_over": False}
    finally:
        os.close(lock)
        os.close(fd)


def read_policy(path):
    """Privileged owner policy: root-owned regular file with root-only trust chain."""
    if os.geteuid() != 0:
        raise DeliveryBlocked("not-authorized")
    p = Path(_absolute(str(path)))
    fd = _open_dir(str(p.parent), owner=0, private=False)
    try:
        raw = _read(fd, p.name, owner=0, private=True, limit=16384)
    finally:
        os.close(fd)
    try:
        return policy_validate(json.loads(raw))
    except (ValueError, UnicodeError, TypeError):
        raise DeliveryBlocked("invalid-policy") from None


def decode_request(raw):
    if not isinstance(raw, bytes) or len(raw) > 1024:
        raise DeliveryBlocked("invalid-request")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise DeliveryBlocked("invalid-request") from None
    if (not isinstance(data, dict) or set(data) != {"schema", "service_id", "certificate_id", "fingerprint"}
            or data["schema"] != REQUEST_SCHEMA
            or not isinstance(data["service_id"], str)
            or ID.fullmatch(data["service_id"]) is None
            or not isinstance(data["certificate_id"], str)
            or ID.fullmatch(data["certificate_id"]) is None
            or not isinstance(data["fingerprint"], str) or not FP.fullmatch(data["fingerprint"])):
        raise DeliveryBlocked("invalid-request")
    return data


def authenticate_peer(connection, policy):
    if not hasattr(socket, "SO_PEERCRED"):
        raise DeliveryBlocked("peer-auth-unavailable")
    creds = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    if len(creds) != 12:
        raise DeliveryBlocked("peer-auth-unavailable")
    _pid, uid, _gid = struct.unpack("3i", creds)
    if uid != policy["peer_uid"]:
        raise DeliveryBlocked("not-authorized")
    return uid


class _Server(socketserver.UnixStreamServer):
    allow_reuse_address = False


def serve(policy_path, *, authority_path=None):
    """Root-owned Unix socket; optional separately reviewed authority-gated mode.

    The default v1 listener remains unchanged for existing installations.
    New versioned host-owner deployments must explicitly select the protected
    authority file; per-request checks occur before certificate publication.
    """
    policy = read_policy(policy_path)
    if authority_path is not None:
        from .certificate_hostname_authority import read_owned, authorize_consumer
        selection = read_owned(authority_path, now=datetime.now(timezone.utc).timestamp())
        authorize_consumer(selection, policy, now=datetime.now(timezone.utc).timestamp())
    path = Path(policy["socket_path"])
    fd = _open_dir(str(path.parent), owner=0, private=False)
    os.close(fd)
    if path.exists() or path.is_symlink():
        raise DeliveryBlocked("socket-already-exists")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                authenticate_peer(self.request, policy)
                self.request.settimeout(10.0)
                raw = self.rfile.readline(1026)
                if len(raw) > 1024 or not raw.endswith(b"\n"):
                    raise DeliveryBlocked("invalid-request")
                message = decode_request(raw[:-1])
                if (message["service_id"] != policy["service_id"]
                        or message["certificate_id"] != policy["certificate_id"]):
                    raise DeliveryBlocked("not-authorized")
                current_policy = read_policy(policy_path)
                if current_policy != policy:
                    raise DeliveryBlocked("policy-changed-restart-required")
                if authority_path is None:
                    response = publish(current_policy, message["fingerprint"])
                else:
                    response = publish_authorized(
                        current_policy, message["fingerprint"],
                        authority_path=authority_path)
            except DeliveryBlocked as exc:
                response = {"schema": SCHEMA, "state": "blocked", "reason": exc.code}
            except Exception:
                response = {"schema": SCHEMA, "state": "blocked", "reason": "unavailable"}
            self.wfile.write(_canonical(response) + b"\n")

    class Server(_Server):
        def server_bind(self):
            super().server_bind()
            os.chown(self.server_address, 0, policy["socket_gid"])
            os.chmod(self.server_address, 0o660)
    with Server(str(path), Handler) as server:
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            # The root-owned runtime directory is not caller-replaceable.
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-policy", required=True)
    parser.add_argument("--owner-authority",
                        help="Protected, versioned hostname authority for local nginx")
    parser.add_argument("--listen", action="store_true")
    parser.add_argument("--fingerprint")
    parser.add_argument("--recover-previous", action="store_true")
    options = parser.parse_args(argv)
    try:
        if options.listen:
            if options.fingerprint is not None or options.recover_previous:
                raise DeliveryBlocked("invalid-request")
            serve(options.owner_policy, authority_path=options.owner_authority)
        elif options.recover_previous:
            if options.fingerprint is not None:
                raise DeliveryBlocked("invalid-request")
            print(_canonical(recover_previous(read_policy(options.owner_policy))).decode())
        else:
            if options.fingerprint is None:
                raise DeliveryBlocked("invalid-request")
            policy = read_policy(options.owner_policy)
            if options.owner_authority is None:
                result = publish(policy, options.fingerprint)
            else:
                result = publish_authorized(
                    policy, options.fingerprint,
                    authority_path=options.owner_authority)
            print(_canonical(result).decode())
        return 0
    except DeliveryBlocked as exc:
        print(_canonical({"schema": SCHEMA, "state": "blocked", "reason": exc.code}).decode())
        return 2
    except Exception:
        # Do not reveal private issuer paths, PEM metadata or subprocess stderr.
        print(_canonical({"schema": SCHEMA, "state": "blocked", "reason": "unavailable"}).decode())
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
