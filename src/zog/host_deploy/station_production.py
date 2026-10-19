"""Fail-closed durable station/archive production composition contract.

This is a *controller client*, not a second archive supervisor. It never adopts a
compiler, selects an archive role, edits root-owned grants, or migrates data.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import socket
import stat
import sys

from .workspace import save

SCHEMA = "zog-host-deploy-station-production-v1"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
PROGRAMS = ("station-access", "archive-mirror")
REPOSITORIES = (
    "station-access", "archive-mirror", "box-control",
    "root-control", "host-discover", "image-build",
)
MAX_MANIFEST = 32768
CONTROLLER_BINDING_SCHEMA = "zog-station-controller-runtime-v1"
_ISSUED_CONTROLLER_REQUEST = re.compile(r"r1-[0-9a-f]{1,32}-[0-9a-f]{32}-[0-9a-f]{64}\Z")
_RETAINED_CONTROLLER_REQUEST = re.compile(r"[A-Za-z0-9-]{1,200}\Z")
DEFAULT_ROOT_CONTROL_SOCKET = "/run/zog/root-control.sock"


class ProductionBlocked(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _path(value, label):
    if (not isinstance(value, str) or not value.startswith("/")
            or len(value) > 512 or value == "/"
            or any(part in {"", ".", ".."} for part in value.split("/")[1:])
            or str(PurePosixPath(value)) != value
            or any(ord(ch) < 33 for ch in value)):
        raise ValueError(label + " must be a normalized absolute path")
    return value


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("invalid " + label + " fields")
    return value


def _sha(value, label):
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError("invalid " + label)
    return value


def _id(value, label):
    if not isinstance(value, str) or IDENTITY.fullmatch(value) is None:
        raise ValueError("invalid " + label)
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def validate_manifest(value):
    """Only immutable selections and owned authority references, never credentials."""
    _exact(value, {"schema", "project", "sources", "image", "applications",
                   "host_bindings", "compiler_rpc", "services"}, "production manifest")
    if value["schema"] != SCHEMA:
        raise ValueError("unsupported production manifest")
    project = _exact(value["project"], {"root", "home", "service_user",
                                       "controller"}, "project")
    root = PurePosixPath(_path(project["root"], "project root"))
    home = PurePosixPath(_path(project["home"], "project home"))
    if (str(home) == "/root" or home not in root.parents
            or not isinstance(project["service_user"], str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", project["service_user"])
            or project["service_user"] == "root"
            or project["controller"] != "box-control/RootControlSystemdTransport"):
        raise ValueError("production project must be scoped to an unprivileged controller home")
    sources = _exact(value["sources"], REPOSITORIES, "sources")
    for name, revision in sources.items():
        if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
            raise ValueError("source revision must be an exact commit: " + name)
    image = _exact(value["image"], {"rootfs", "generation"}, "image")
    _sha(image["rootfs"], "rootfs digest")
    if not isinstance(image["generation"], str) or not image["generation"] or len(image["generation"]) > 128:
        raise ValueError("invalid image generation")
    applications = _exact(value["applications"], PROGRAMS, "applications")
    for name in PROGRAMS:
        app = _exact(applications[name], {"specification_sha256", "software_view",
                                          "storage_id", "grant", "mount", "preparation_revision"},
                     "application")
        _sha(app["specification_sha256"], "application specification")
        _sha(app["software_view"], "immutable software view")
        _id(app["storage_id"], "persistent storage ID")
        if not isinstance(app["preparation_revision"], str) or not app["preparation_revision"] or len(app["preparation_revision"]) > 128:
            raise ValueError("invalid preparation revision")
        grant = _exact(app["grant"], {"grant_id", "grant_version", "uid", "gid"}, "grant")
        _id(grant["grant_id"], "grant ID")
        if (type(grant["grant_version"]) is not int or grant["grant_version"] < 1
                or any(type(grant[k]) is not int or not 1 <= grant[k] < 2**31
                       for k in ("uid", "gid"))):
            raise ValueError("invalid unprivileged NSS grant")
        mount = _exact(app["mount"], {"path", "device", "inode"}, "mount identity")
        path = _path(mount["path"], "persistent mount path")
        if not PurePosixPath(path).is_relative_to(root) or PurePosixPath(path) == root:
            raise ValueError("persistent mount is outside the controlled project")
        if any(type(mount[k]) is not int or mount[k] < 1 for k in ("device", "inode")):
            raise ValueError("persistent mount requires exact observed device/inode")
    if (applications["station-access"]["storage_id"] == applications["archive-mirror"]["storage_id"]
            or applications["station-access"]["grant"]["uid"] ==
               applications["archive-mirror"]["grant"]["uid"]
            or applications["station-access"]["mount"]["path"] ==
               applications["archive-mirror"]["mount"]["path"]):
        raise ValueError("station and archive must have distinct storage and execution identities")
    bindings = _exact(value["host_bindings"], {"policy_sha256", "mirror_live"}, "host bindings")
    _sha(bindings["policy_sha256"], "root-owned host binding policy")
    if bindings["mirror_live"] != "/run/zog-host/mirror-live":
        raise ValueError("only scoped mirror-live export is supported")
    rpc = _exact(value["compiler_rpc"], {"config_directory", "workspace_id",
                                        "ownership_epoch", "scopes"}, "compiler RPC")
    _path(rpc["config_directory"], "compiler RPC private configuration directory")
    if rpc["config_directory"] != "/var/lib/station-access/compiler-rpc":
        raise ValueError("compiler identity must remain inside station-owned persistent state")
    _id(rpc["workspace_id"], "adopted compiler workspace")
    _id(rpc["ownership_epoch"], "adopted compiler epoch")
    if rpc["scopes"] != ["compiler.status", "dispatch.status"]:
        raise ValueError("station identity must be observer-only")
    services = _exact(value["services"], {"station", "archive", "root_control",
                                         "box_control"}, "services")
    if (services["station"] != "boot-independent"
            or services["archive"] != "host-discover-lease-selected"
            or services["root_control"] != "systemd"
            or services["box_control"] != "controller-requests"):
        raise ValueError("archive lifecycle must remain role-elected")
    try:
        data = _json(value)
    except (ValueError, TypeError):
        raise ValueError("production manifest must be finite canonical JSON") from None
    if len(data) > MAX_MANIFEST:
        raise ValueError("production manifest exceeds size limit")
    return json.loads(data)


def manifest_digest(manifest):
    return "sha256:" + hashlib.sha256(_json(validate_manifest(manifest))).hexdigest()


def _file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MANIFEST:
        raise ProductionBlocked("retained-state-unsafe")
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError, UnicodeError):
        raise ProductionBlocked("retained-state-invalid") from None


def _record_dir(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ProductionBlocked("deployment-directory-missing")
    return directory


def prepare(directory, manifest):
    """Durably commit exact inputs; interrupted retries never overwrite state."""
    manifest = validate_manifest(manifest)
    directory = _record_dir(directory)
    with (directory / ".station-production.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        path = directory / "station-production.json"
        if path.exists() or path.is_symlink():
            existing = _file(path)
            if existing.get("schema") != 1 or existing.get("manifest") != manifest or existing.get("manifest_sha256") != manifest_digest(manifest):
                raise ProductionBlocked("deployment-identity-conflict")
            return existing
        record = {"schema": 1, "manifest": manifest,
                  "manifest_sha256": manifest_digest(manifest),
                  "state": "prepared", "authorized_to_cut_over": False}
        save(path, record)
        return record


def load(directory):
    path = _record_dir(directory) / "station-production.json"
    if not path.exists():
        raise ProductionBlocked("deployment-not-prepared")
    record = _file(path)
    try:
        _exact(record, {"schema", "manifest", "manifest_sha256", "state",
                        "authorized_to_cut_over"}, "record")
        manifest = validate_manifest(record["manifest"])
        if (record["schema"] != 1 or record["manifest_sha256"] != manifest_digest(manifest)
                or record["state"] != "prepared" or record["authorized_to_cut_over"] is not False):
            raise ValueError("retained deployment differs")
    except (ValueError, TypeError, KeyError):
        raise ProductionBlocked("retained-state-invalid") from None
    return record


def _controller_grant_matches(binding, grant, *, project_root, application):
    """Match the actual root-control v1 grant, retaining public manifest aliases.

    The manifest's grant_version is the controller's version field.
    """
    if not isinstance(binding, dict):
        return False
    required = {
        "schema": "zog-execution-identity-v1",
        "project": project_root,
        "application": application,
        "grant_id": grant["grant_id"],
        "version": grant["grant_version"],
        "uid": grant["uid"],
        "gid": grant["gid"],
    }
    return all(
        (type(binding.get(key)) is int if key in {"version", "uid", "gid"}
         else isinstance(binding.get(key), str))
        and binding.get(key) == expected
        for key, expected in required.items()
    )


def preparation_gate(record, controller, *, applications=PROGRAMS):
    """Inspect authoritative controller records; never infer success from local files."""
    value = record["manifest"]
    if str(controller.project.path) != value["project"]["root"]:
        raise ProductionBlocked("controller-project-mismatch")
    for name in applications:
        expected = value["applications"][name]
        spec_path = Path(value["project"]["root"]) / "application" / name / "application.py"
        if spec_path.is_symlink() or not spec_path.is_file():
            raise ProductionBlocked("application-specification-missing")
        try:
            with spec_path.open("rb") as stream:
                digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError:
            raise ProductionBlocked("application-specification-unavailable") from None
        if digest != expected["specification_sha256"]:
            raise ProductionBlocked("application-specification-mismatch")
        try:
            actual = controller.application_preparation(name)
        except Exception:
            raise ProductionBlocked("preparation-unavailable") from None
        if not isinstance(actual, dict) or actual.get("state") != "ready":
            raise ProductionBlocked("preparation-not-ready")
        definition = actual.get("definition")
        if not isinstance(definition, dict):
            raise ProductionBlocked("preparation-definition-missing")
        binding = definition.get("execution_binding")
        if (definition.get("software_view") != expected["software_view"]
                or definition.get("name") != name):
            raise ProductionBlocked("immutable-software-selection-mismatch")
        if (actual.get("storage_id") != expected["storage_id"]
                or actual.get("revision") != expected["preparation_revision"]
                or actual.get("generation") != value["image"]["generation"]
                or not _controller_grant_matches(
                    binding, expected["grant"],
                    project_root=value["project"]["root"], application=name
                )):
            raise ProductionBlocked("persistent-identity-mismatch")
    return True


def mount_gate(record, stat_fn=os.stat, *, applications=PROGRAMS):
    """Host-path preflight only; kernel guest mount acceptance is a separate gate."""
    for name in applications:
        mount = record["manifest"]["applications"][name]["mount"]
        path = Path(mount["path"])
        if path.is_symlink():
            raise ProductionBlocked("mount-redirected")
        try:
            info = stat_fn(path, follow_symlinks=False)
        except OSError:
            raise ProductionBlocked("mount-unavailable") from None
        if info.st_dev != mount["device"] or info.st_ino != mount["inode"]:
            raise ProductionBlocked("mount-identity-mismatch")
    return True


def _controller_request_id(identity, *, newly_issued):
    """Never truncate/re-sign controller identities; producer authenticates HMAC."""
    pattern = (_ISSUED_CONTROLLER_REQUEST if newly_issued
               else _RETAINED_CONTROLLER_REQUEST)
    if not isinstance(identity, str) or pattern.fullmatch(identity) is None:
        raise ProductionBlocked("controller-request-identity-invalid")
    return identity


def validate_controller_binding(binding, manifest):
    """Bind a root-provisioned runtime selection to the immutable manifest."""
    _exact(binding, {"schema", "project_root", "service_user",
                     "generation", "manifest_sha256",
                     "root_control_socket", "python_executable"}, "controller binding")
    if binding["schema"] != CONTROLLER_BINDING_SCHEMA:
        raise ProductionBlocked("controller-binding-schema-mismatch")
    if (binding["project_root"] != manifest["project"]["root"]
            or binding["service_user"] != manifest["project"]["service_user"]
            or binding["generation"] != manifest["image"]["generation"]
            or binding["manifest_sha256"] != manifest_digest(manifest)):
        raise ProductionBlocked("controller-binding-identity-mismatch")
    _path(binding["root_control_socket"], "root-control socket")
    _path(binding["python_executable"], "bound Python interpreter")
    if binding["root_control_socket"] == DEFAULT_ROOT_CONTROL_SOCKET:
        raise ProductionBlocked("controller-socket-default-prohibited")
    if not binding["python_executable"].startswith("/usr/bin/python3."):
        raise ProductionBlocked("controller-python-not-absolute-approved")
    return json.loads(_json(binding))


def load_controller_binding(path, manifest):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise ProductionBlocked("controller-binding-file-unsafe")
    info = path.stat(follow_symlinks=False)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ProductionBlocked("controller-binding-file-untrusted")
    try:
        return validate_controller_binding(json.loads(path.read_text()), manifest)
    except (OSError, ValueError, UnicodeError, TypeError):
        raise ProductionBlocked("controller-binding-file-invalid") from None


def verify_controller_runtime(binding, *, check_socket=True):
    """Require explicit owner socket and the exact running interpreter."""
    if os.path.realpath(sys.executable) != os.path.realpath(binding["python_executable"]):
        raise ProductionBlocked("controller-python-mismatch")
    path = Path(binding["root_control_socket"])
    if check_socket:
        try:
            if path.is_symlink() or not stat.S_ISSOCK(path.stat(follow_symlinks=False).st_mode):
                raise ProductionBlocked("controller-socket-unsafe")
        except OSError:
            raise ProductionBlocked("controller-socket-unavailable") from None


def build_controller(binding):
    """Supported public BoxControl facade with two explicit producer bindings."""
    from zog.box_control import BoxControl, Project
    from zog.box_control.images import published_selection
    from zog.box_control.runtime.root_control import RootControlSystemdTransport

    class PinnedPublishedImage:
        def ensure(self, project):
            selection = published_selection(project.path, binding["generation"])
            if selection.generation != binding["generation"]:
                raise ProductionBlocked("controller-image-generation-mismatch")
            return selection

    return BoxControl(
        Project(Path(binding["project_root"])),
        systemd_transport=RootControlSystemdTransport(
            socket_path=Path(binding["root_control_socket"])
        ),
        image_provider=PinnedPublishedImage(),
    )


def evaluate_station(directory, *, controller, stat_fn=os.stat):
    """One bounded controller evaluation: the existing box-control lock is authoritative."""
    record = load(directory)
    preparation_gate(record, controller, applications=("station-access",))
    mount_gate(record, stat_fn=stat_fn, applications=("station-access",))
    try:
        outcome = controller.evaluate()
    except Exception:
        raise ProductionBlocked("controller-evaluation-unavailable") from None
    if outcome is None or outcome.ok is not True:
        raise ProductionBlocked("controller-evaluation-failed")
    return {
        "schema": SCHEMA, "state": "evaluated-not-serving",
        "manifest_sha256": record["manifest_sha256"],
        "archive_action": "none-by-host-deploy",
        "safe_to_cut_over": False,
    }


def station_boot_request(directory, *, controller, boot_id, stat_fn=os.stat):
    """Request station only; host-discover exclusively owns archive role launch.

    Persist issued request ID before making a controller mutation. Identical
    retries use the same retained request; no second idempotency ledger.
    """
    if not isinstance(boot_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise ValueError("boot_id must be the kernel boot UUID")
    record = load(directory)
    # Station boot is independent of the archive election/preparation.
    preparation_gate(record, controller, applications=("station-access",))
    mount_gate(record, stat_fn=stat_fn, applications=("station-access",))
    # Controller result/launch readiness is not implied by the request.
    directory = _record_dir(directory)
    with (directory / ".station-production.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        journal = directory / "station-boot-request.json"
        if journal.exists() or journal.is_symlink():
            current = _file(journal)
            if (current.get("schema") != 1
                    or current.get("manifest_sha256") != record["manifest_sha256"]
                    or current.get("application") != "station-access"
                    or not isinstance(current.get("boot_id"), str)
                    or not re.fullmatch(r"[0-9a-f-]{36}", current["boot_id"])):
                raise ProductionBlocked("boot-request-conflict")
            _controller_request_id(current.get("request_id"), newly_issued=False)
            if current.get("previous_request_id") is not None:
                _controller_request_id(current["previous_request_id"], newly_issued=False)
            if current.get("boot_id") != boot_id:
                # Do not discard uncertain requests from a prior boot.
                try:
                    previous = controller.application_request_result(current["request_id"])
                except Exception:
                    raise ProductionBlocked("previous-boot-reconciliation-required") from None
                previous_status = getattr(getattr(previous, "status", None), "value",
                                          getattr(previous, "status", None))
                if previous_status != "satisfied":
                    raise ProductionBlocked("previous-boot-reconciliation-required")
                try:
                    request_id = controller.issue_application_request_id()
                except Exception:
                    raise ProductionBlocked("controller-request-unavailable") from None
                _controller_request_id(request_id, newly_issued=True)
                current = {"schema": 1, "manifest_sha256": record["manifest_sha256"],
                           "boot_id": boot_id, "request_id": request_id,
                           "application": "station-access",
                           "previous_request_id": current["request_id"]}
                save(journal, current)
        else:
            try:
                request_id = controller.issue_application_request_id()
            except Exception:
                raise ProductionBlocked("controller-request-unavailable") from None
            _controller_request_id(request_id, newly_issued=True)
            current = {"schema": 1, "manifest_sha256": record["manifest_sha256"],
                       "boot_id": boot_id, "request_id": request_id,
                       "application": "station-access"}
            save(journal, current)
        try:
            result = controller.application_request_result(current["request_id"])
            if result is None:
                controller.request_application_launch(
                    "station-access", request_id=current["request_id"]
                )
        except Exception:
            # Even a lost reply may mean the request was accepted. Keep ID.
            raise ProductionBlocked("controller-launch-uncertain") from None
        return {"schema": SCHEMA, "state": "requested-not-serving",
                "request_id": current["request_id"],
                "manifest_sha256": record["manifest_sha256"],
                "archive_action": "none", "safe_to_cut_over": False}


def plan(directory):
    """Machine-readable handoff; no application mutation or false readiness."""
    record = load(directory)
    return {
        "schema": SCHEMA,
        "state": "prepared-not-launched",
        "manifest_sha256": record["manifest_sha256"],
        "safe_to_cut_over": False,
        "authority": {
            "station": "box-control durable application request",
            "archive": "host-discover role+live lease only",
            "root_control": "existing privileged service",
            "host_export": "root-owned immutable directory identity",
        },
        "gates": [
            "controller-preparation-ready", "exact-image-and-software-view",
            "root-control-grant-and-NSS", "kernel-mount-identity",
            "private-station-compiler-RPC-credentials", "station-login-and-HTTP",
            "archive-server-and-scheduler-live-lease",
            "legacy-writer-fence-and-fresh-checkpoint",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    cmd = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "inspect", "boot-request", "evaluate"):
        sub = cmd.add_parser(name)
        sub.add_argument("--directory", required=True)
        if name == "prepare":
            sub.add_argument("--manifest", required=True)
        if name in {"boot-request", "evaluate"}:
            sub.add_argument("--controller-binding", required=True)
    options = parser.parse_args(argv)
    try:
        if options.action == "prepare":
            source = Path(options.manifest)
            if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_MANIFEST:
                raise ProductionBlocked("manifest-file-unsafe")
            record = prepare(options.directory, json.loads(source.read_text()))
            result = {"schema": SCHEMA, "state": "prepared",
                      "manifest_sha256": record["manifest_sha256"],
                      "safe_to_cut_over": False}
        elif options.action in {"boot-request", "evaluate"}:
            retained = load(options.directory)
            binding = load_controller_binding(options.controller_binding, retained["manifest"])
            try:
                user = pwd.getpwnam(binding["service_user"])
            except KeyError:
                raise ProductionBlocked("controller-account-missing") from None
            if os.geteuid() != user.pw_uid or os.geteuid() == 0:
                raise ProductionBlocked("controller-account-mismatch")
            verify_controller_runtime(binding)
            controller = build_controller(binding)
            if options.action == "boot-request":
                boot = Path("/proc/sys/kernel/random/boot_id")
                if not boot.is_file():
                    raise ProductionBlocked("boot-identity-unavailable")
                result = station_boot_request(
                    options.directory, controller=controller,
                    boot_id=boot.read_text().strip()
                )
            else:
                result = evaluate_station(options.directory, controller=controller)
        else:
            result = plan(options.directory)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProductionBlocked, ValueError, OSError, KeyError, TypeError) as error:
        code = error.reason if isinstance(error, ProductionBlocked) else "invalid-contract"
        print(json.dumps({"schema": SCHEMA, "state": "blocked",
                          "reason": code, "safe_to_cut_over": False},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
