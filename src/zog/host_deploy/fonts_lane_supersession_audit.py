"""Read-only audit of the November 14 Fonts lane supersession question.

This module deliberately has no Host, boto3, SSM, installer, dispatcher,
publish, or mutable workspace dependency. The November 14 controller-present
destination and the later active certbot-seed Project are two distinct
historical subjects. This report NEVER proves a replacement writer by
examining a presently active lane alone.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from . import existing_project_runtime
from . import fonts_lane_recovery as recovery
from . import fonts_lane_migration as migration
from . import image_build_lanes as lanes

SCHEMA = "host-deploy-first-fonts-supersession-audit-v1"
EXPECTED_ORIGINAL = recovery.RETAINED_OLD_SPEC_SHA
DESTINATION = str(lanes.FIRST_FONTS_MIGRATED_ROOT)
CURRENT = recovery.EXISTING_EXECUTION_PROJECT
LANE = recovery.LANE
ARCHIVE = recovery.ARCHIVE
INTENT = recovery.INTENT
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HOST = re.compile(r"i-[0-9a-f]{17}\Z")
_MAX = 1024 * 1024


class AuditHold(RuntimeError):
    """Untrusted local evidence or contradictory immutable selection."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditHold("duplicate key in retained supersession evidence")
        result[key] = value
    return result


def _decode(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_object,
                           parse_constant=lambda name: (_ for _ in ()).throw(
                               AuditHold("nonfinite audit evidence")))
    except (ValueError, UnicodeError) as error:
        raise AuditHold("invalid retained supersession evidence") from error
    if type(value) is not dict:
        raise AuditHold("retained supersession evidence is not an object")
    return value


def _checked_dir(parent_fd, component, *, owner=None):
    if (not isinstance(component, str) or not component or
            component in {".", ".."} or "/" in component):
        raise AuditHold("invalid protected directory component")
    named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(named.st_mode):
        raise AuditHold("symlink or non-directory in protected audit ancestry")
    fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    opened = os.fstat(fd)
    if ((opened.st_dev, opened.st_ino, opened.st_mode,
         opened.st_uid, opened.st_gid) !=
        (named.st_dev, named.st_ino, named.st_mode,
         named.st_uid, named.st_gid)):
        os.close(fd)
        raise AuditHold("protected audit directory replaced during open")
    sticky_root = (opened.st_uid == 0 and
                   stat.S_IMODE(opened.st_mode) == 0o1777)
    if (opened.st_mode & 0o022 and not sticky_root):
        os.close(fd)
        raise AuditHold("writable protected audit ancestry")
    if owner is not None and opened.st_uid != owner:
        os.close(fd)
        raise AuditHold("protected audit directory owner differs")
    return fd


def _open_workspace(root):
    root = Path(root)
    if (not root.is_absolute() or str(root) != os.path.normpath(str(root))
            or str(root) == "/"):
        raise AuditHold("noncanonical absolute audit workspace")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in root.parts[1:]:
            new = _checked_dir(fd, name)
            os.close(fd)
            fd = new
        if os.fstat(fd).st_uid != os.geteuid():
            raise AuditHold("audit workspace is not owned by executing identity")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(directory, name, *, optional=False):
    """No-follow bounded regular read; caller holds opened workspace root."""
    parts = PurePosixPath(name).parts
    if not parts or any(x in {".", ".."} for x in parts) or name.startswith("/"):
        raise AuditHold("invalid fixed evidence path")
    fd = os.dup(directory)
    try:
        for component in parts[:-1]:
            try:
                new = _checked_dir(fd, component, owner=os.geteuid())
            except FileNotFoundError:
                if optional:
                    return None
                raise AuditHold("required protected evidence directory missing") from None
            os.close(fd)
            fd = new
        try:
            named = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            if optional:
                return None
            raise AuditHold("required protected evidence missing: " + name) from None
        if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                or named.st_uid != os.geteuid() or named.st_mode & 0o022
                or not 0 < named.st_size <= _MAX):
            raise AuditHold("foreign protected evidence: " + name)
        entry = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                        os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(entry)
            if ((named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                 named.st_gid, named.st_size, named.st_nlink) !=
                (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                 before.st_gid, before.st_size, before.st_nlink)):
                raise AuditHold("protected audit evidence inode replaced")
            raw = os.read(entry, _MAX + 1)
            after = os.fstat(entry)
            still = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            if (len(raw) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) or
                (still.st_dev, still.st_ino, still.st_uid,
                 still.st_mode) !=
                (before.st_dev, before.st_ino, before.st_uid,
                 before.st_mode)):
                raise AuditHold("protected audit evidence changed during read")
            return raw
        finally:
            os.close(entry)
    finally:
        os.close(fd)


def _locked_workspace(root):
    """Open an EXISTING workspace lock shared/read-only; never creates a file."""
    import contextlib

    @contextlib.contextmanager
    def held():
        directory = _open_workspace(root)
        try:
            try:
                name = os.stat("workspace.lock", dir_fd=directory,
                               follow_symlinks=False)
                lock = os.open("workspace.lock", os.O_RDONLY | os.O_NOFOLLOW |
                               os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError as error:
                raise AuditHold("existing workspace lock missing; do not initialize") from error
            try:
                found = os.fstat(lock)
                if (not stat.S_ISREG(found.st_mode) or found.st_nlink != 1
                        or found.st_uid != os.geteuid() or found.st_mode & 0o022
                        or (found.st_dev, found.st_ino) !=
                           (name.st_dev, name.st_ino)):
                    raise AuditHold("foreign protected workspace lock")
                try:
                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise AuditHold("workspace lock held; no audit during mutation") from error
                yield directory
                end = os.stat("workspace.lock", dir_fd=directory,
                              follow_symlinks=False)
                if (end.st_dev, end.st_ino) != (found.st_dev, found.st_ino):
                    raise AuditHold("workspace lock replaced during audit")
            finally:
                os.close(lock)
        finally:
            os.close(directory)
    return held()


def _expected_binding(workspace, host):
    if (workspace.get("schema") != 1 or
            type(workspace.get("workspace_id")) is not str or
            not re.fullmatch(r"[0-9a-f]{32}", workspace["workspace_id"]) or
            type(host.get("account_id")) is not str or
            not re.fullmatch(r"[0-9]{12}", host["account_id"]) or
            host.get("instance_id") != recovery.COMPILER_INSTANCE or
            not _HOST.fullmatch(host["instance_id"]) or
            host.get("workspace_id") != workspace["workspace_id"] or
            host.get("region") != workspace.get("region")):
        raise AuditHold("audit workspace/compiler target differs")
    return {key: host[key] for key in
            ("workspace_id", "account_id", "region", "instance_id")}


def _current(lane, expected_selected):
    if (type(lane) is not dict or lane.get("schema") != lanes.INHERITED_SCHEMA
            or lane.get("state") != "active" or lane.get("lane") != LANE
            or "fonts_migration" in lane):
        raise AuditHold("current selection is not the retained existing schema-5 lane")
    try:
        spec = lanes.validate(lane.get("specification"))
    except (TypeError, ValueError, KeyError) as error:
        raise AuditHold("invalid active compiler lane specification") from error
    if (lanes.specification_sha256(spec) != expected_selected or
            spec.get("schema") != lanes.INHERITED_SCHEMA or
            spec.get("mode") != "managed" or
            spec.get("lane") != LANE or
            spec.get("project_selection") != "existing" or
            spec.get("project_root") != CURRENT or
            lane.get("specification") != spec or
            lane.get("controller_config") !=
                CURRENT + "/" + existing_project_runtime.controller_file(spec) or
            lane.get("source_root") != CURRENT + "/source" or
            lane.get("state_dir") != CURRENT + "/state" or
            lane.get("package_dir") != CURRENT + "/source/project/package"):
        raise AuditHold("active lane differs from independently selected certbot-seed")
    return spec


def _intent(value, binding, expected_corrected):
    if (type(value) is not dict or value.get("schema") !=
            migration.INITIALIZATION_SCHEMA or
            value.get("phase") != "installing" or
            value.get("source_method") != "prepared-first-initialization" or
            value.get("binding") != binding or
            value.get("old_specification_sha256") != EXPECTED_ORIGINAL or
            value.get("new_specification_sha256") != expected_corrected or
            value.get("project_root") != DESTINATION or
            value.get("source_revision") !=
                lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION or
            value.get("historical_project_materialized") is not False or
            value.get("copy_performed") is not False or
            value.get("compiler_authorized") is not False or
            type(value.get("initialization_manifest_sha256")) is not str or
            not re.fullmatch("[0-9a-f]{64}",
                             value["initialization_manifest_sha256"]) or
            type(value.get("initialized_source_tree_sha256")) is not dict or
            set(value["initialized_source_tree_sha256"]) !=
                {"source", "companions/box-control", "companions/build-record"} or
            any(type(v) is not str or not re.fullmatch("[0-9a-f]{64}", v)
                for v in value["initialized_source_tree_sha256"].values())):
        raise AuditHold("prior November 14 initializer intent is not authentic")
    return value


def _archive_status(fd):
    name = ARCHIVE + "/" + EXPECTED_ORIGINAL.removeprefix("sha256:") + ".json"
    raw = _read(fd, name, optional=True)
    if raw is None:
        # Check that a foreign file/archive has not been silently substituted.
        try:
            d = _checked_dir(fd, ARCHIVE, owner=os.geteuid())
        except FileNotFoundError:
            return "missing", None
        try:
            if os.listdir(d):
                raise AuditHold("unexpected historical archive entries")
            return "missing", None
        finally:
            os.close(d)
    value = _decode(raw)
    try:
        valid = lanes.validate(value.get("specification"))
    except (TypeError, ValueError, KeyError) as error:
        raise AuditHold("historical archived lane specification invalid") from error
    if (value.get("schema") != lanes.SCHEMA or value.get("lane") != LANE
            or lanes.specification_sha256(valid) != EXPECTED_ORIGINAL):
        raise AuditHold("archived schema-4 lane does not bind original approval")
    d = _checked_dir(fd, ARCHIVE, owner=os.geteuid())
    try:
        if os.listdir(d) != [EXPECTED_ORIGINAL[7:] + ".json"]:
            raise AuditHold("historical archive has foreign contents")
    finally:
        os.close(d)
    return "archived-original-verified", _digest(raw)


def inspect(directory, *, expected_original_specification_sha256,
            expected_corrected_specification_sha256,
            expected_selected_specification_sha256):
    """Inspect local evidence only; never contacts AWS or a compiler Host.

    A genuine supersession proof needs independent preserved SSM command
    results, controller readbacks and the authenticated writer/record
    transition, which are NOT reconstructed from an active lane value.
    """
    if (expected_original_specification_sha256 != EXPECTED_ORIGINAL or
            type(expected_corrected_specification_sha256) is not str or
            not _SHA.fullmatch(expected_corrected_specification_sha256) or
            type(expected_selected_specification_sha256) is not str or
            not _SHA.fullmatch(expected_selected_specification_sha256)):
        raise AuditHold("independent supersession selection hashes required")
    with _locked_workspace(directory) as fd:
        workspace_raw = _read(fd, "workspace.json")
        host_raw = _read(fd, "host.json")
        lane_raw = _read(fd, "image-build-lanes/" + LANE + ".json")
        intent_raw = _read(fd, INTENT)
        ws, host = _decode(workspace_raw), _decode(host_raw)
        binding = _expected_binding(ws, host)
        lane = _decode(lane_raw)
        spec = _current(lane, expected_selected_specification_sha256)
        intent = _intent(_decode(intent_raw), binding,
                         expected_corrected_specification_sha256)
        archive_status, archive_digest = _archive_status(fd)
        # Repeat the immutable/local readback while the shared workspace
        # lock excludes all supported exclusive workspace operations.
        for name, raw in (
            ("workspace.json", workspace_raw), ("host.json", host_raw),
            ("image-build-lanes/" + LANE + ".json", lane_raw),
            (INTENT, intent_raw),
        ):
            if _read(fd, name) != raw:
                raise AuditHold("protected local supersession evidence changed")
        return {
            "schema": SCHEMA,
            "status": "supersession-unproven",
            "reason": "no authenticated historical transition and native controller pair",
            "workspace_id": ws["workspace_id"],
            "compiler_target": binding,
            "selected_lane": LANE,
            "selected_lane_record_sha256": _digest(lane_raw),
            "selected_specification_sha256": expected_selected_specification_sha256,
            "selected_project_root": CURRENT,
            "selected_controller_path": lane["controller_config"],
            "selected_expected_controller_sha256": hashlib.sha256(
                existing_project_runtime.expected_bytes(spec)).hexdigest(),
            "prior_initialization_project_root": DESTINATION,
            "original_schema4_specification_sha256": EXPECTED_ORIGINAL,
            "corrected_migration_specification_sha256":
                expected_corrected_specification_sha256,
            "pending_intent_sha256": _digest(intent_raw),
            "pending_intent_phase": intent["phase"],
            "prior_initialization_manifest_sha256":
                intent["initialization_manifest_sha256"],
            "original_archive_status": archive_status,
            "original_archive_raw_sha256": archive_digest,
            "historical_ssm_result_status": "not-authenticated",
            "selected_controller_observation": "not-authenticated",
            "initialized_destination_controller_observation": "not-authenticated",
            "superseding_writer": None,
            "evidence_transition_verified": False,
            "mutation": False,
            "ssm_send_authorized": False,
            "execution_authorized": False,
            "compilation_authorized": False,
        }
