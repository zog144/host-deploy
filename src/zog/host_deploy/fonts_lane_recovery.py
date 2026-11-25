"""Fail-closed first Fonts mixed-state recovery without schema-4 fabrication.

For a selected existing certbot-seed Project, an independently retained
first-Fonts initialization intent can coexist with a DIFFERENT proposed
migration Project. They must never be equated. No original schema-4 lane or
archive is manufactured. An explicit administrator inspects both native
sources and can publish a separate immutable NONAUTHORIZING provenance
receipt; normal dispatch consumes only that verified receipt, never calls
host-install or rewrites active lane JSON.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import image_build_lanes as lanes
from . import existing_project_runtime
from .workspace import locked
from .provision import configuration

LANE = "gateway-first-fonts-runtime"
COMPILER_INSTANCE = "i-00ad300038a599044"
EXISTING_EXECUTION_PROJECT = "/home/certbot-build-owner/certbot-seed"
RETAINED_OLD_SPEC_SHA = "sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2"
INTENT = "first-fonts-inherited-migration-v1.json"
RECEIPT = "first-fonts-mixed-state-recovery-v1.json"
ARCHIVE = "first-fonts-original-evidence"
RECEIPT_SCHEMA = "host-deploy-first-fonts-mixed-provenance-v1"
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
REV = re.compile(r"[0-9a-f]{40}\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _read(root, name):
    path = root / name
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("required original mixed-state evidence missing: " + name) from error
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o022
            or info.st_size <= 0 or info.st_size > 1048576):
        raise RuntimeError("untrusted mixed-state evidence custody: " + name)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (before.st_dev != info.st_dev or before.st_ino != info.st_ino
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or before.st_uid != os.geteuid()
                or before.st_mode & 0o022 or before.st_size <= 0
                or before.st_size > 1048576):
            raise RuntimeError("mixed-state evidence inode or custody differs: " + name)
        raw = os.read(fd, 1048577)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(raw) != before.st_size):
            raise RuntimeError("mixed-state evidence changed during readback: " + name)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("invalid mixed-state evidence JSON: " + name) from error
    if type(value) is not dict:
        raise RuntimeError("mixed-state evidence is not an object: " + name)
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()


def _facts(root, *, original_sha, corrected_sha, selected_sha):
    """Read-only local gate; no schema-4 record needed or synthesized."""
    if (type(original_sha) is not str or original_sha != RETAINED_OLD_SPEC_SHA
            or type(corrected_sha) is not str or not SHA.fullmatch(corrected_sha)
            or type(selected_sha) is not str or not SHA.fullmatch(selected_sha)):
        raise RuntimeError("original/corrected/selected approval digests missing or wrong")
    workspace, host = configuration(root)
    if (type(workspace) is not dict or type(host) is not dict
            or type(host.get("account_id")) is not str
            or not re.fullmatch(r"[0-9]{12}", host["account_id"])
            or host.get("instance_id") != COMPILER_INSTANCE
            or host.get("workspace_id") != workspace.get("workspace_id")
            or host.get("region") != workspace.get("region")):
        raise RuntimeError("first Fonts workspace/compiler identity differs")
    binding = {k: v for k, v in (
        ("workspace_id", workspace["workspace_id"]),
        ("account_id", host["account_id"]),
        ("region", host["region"]),
        ("instance_id", host["instance_id"]),
    )}
    lane_file = "image-build-lanes/" + LANE + ".json"
    record, record_sha = _read(root, lane_file)
    if (record.get("schema") != lanes.INHERITED_SCHEMA
            or record.get("lane") != LANE
            or record.get("state") != "active"
            or "fonts_migration" in record):
        raise RuntimeError("mixed-state recovery requires actual active schema-5 existing lane")
    try:
        spec = lanes.validate(record.get("specification"))
    except (ValueError, TypeError, KeyError) as error:
        raise RuntimeError("selected existing Project specification invalid") from error
    if (spec.get("schema") != lanes.INHERITED_SCHEMA
            or spec.get("lane") != LANE
            or spec.get("mode") != "managed"
            or spec.get("project_selection") != "existing"
            or spec.get("project_root") != EXISTING_EXECUTION_PROJECT
            or record.get("specification") != spec
            or lanes.specification_sha256(spec) != selected_sha
            or record.get("controller_config") != (
                EXISTING_EXECUTION_PROJECT + "/" +
                existing_project_runtime.controller_file(spec))
            or record.get("source_root") != EXISTING_EXECUTION_PROJECT + "/source"
            or record.get("package_dir") != (
                EXISTING_EXECUTION_PROJECT + "/source/project/package")
            or record.get("state_dir") != EXISTING_EXECUTION_PROJECT + "/state"):
        raise RuntimeError("active certbot-seed Project/root/controller/specification differs")
    for key, validator in (
        ("runtime_companion", lanes.validate_runtime_companion),
        ("controller_companion", lanes.validate_controller_companion),
    ):
        if record.get(key) is not None:
            try:
                verified = validator(record[key], project_root=EXISTING_EXECUTION_PROJECT)
            except (KeyError, TypeError, ValueError) as error:
                raise RuntimeError("selected existing Project companion is unverified") from error
            if spec.get("source_revision") is not None and (
                    verified.get("producer_revision") != spec["source_revision"]):
                raise RuntimeError("active Project companion differs from selected source")
    archive_dir = root / ARCHIVE
    if archive_dir.exists() or archive_dir.is_symlink():
        info = archive_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or any(archive_dir.iterdir())):
            raise RuntimeError("mixed-state archive contains unreviewed contents or foreign custody")
    old_path = archive_dir / (original_sha[7:] + ".json")
    if old_path.exists() or old_path.is_symlink():
        raise RuntimeError("mixed-state without-archive recovery cannot relabel retained history")
    intent, intent_sha = _read(root, INTENT)
    from . import fonts_lane_migration as migration
    # This is a DISTINCT initialization target, not certbot-seed. Its
    # current native state must be verified separately by its actual owner.
    if (intent.get("schema") != migration.INITIALIZATION_SCHEMA
            or intent.get("phase") != "installing"
            or intent.get("source_method") != "prepared-first-initialization"
            or intent.get("binding") != binding
            or intent.get("old_specification_sha256") != original_sha
            or intent.get("new_specification_sha256") != corrected_sha
            or intent.get("project_root") != str(lanes.FIRST_FONTS_MIGRATED_ROOT)
            or intent.get("source_revision") != lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION
            or intent.get("historical_project_materialized") is not False
            or intent.get("copy_performed") is not False
            or intent.get("compiler_authorized") is not False
            or type(intent.get("initialization_manifest_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", intent["initialization_manifest_sha256"])
            or type(intent.get("initialized_source_tree_sha256")) is not dict
            or set(intent["initialized_source_tree_sha256"]) != {
                "source", "companions/box-control", "companions/build-record"}
            or any(type(x) is not str or
                   not re.fullmatch(r"[0-9a-f]{64}", x)
                   for x in intent["initialized_source_tree_sha256"].values())):
        raise RuntimeError("pending first Fonts initializer intent/provenance differs")
    return {
        "binding": binding, "host": host, "spec": spec, "record_sha": record_sha,
        "intent_sha": intent_sha, "intent": intent,
        "selected_sha": selected_sha, "original_sha": original_sha,
        "corrected_sha": corrected_sha,
    }


def _native_report(facts, host_factory):
    """Re-observe BOTH compiler Projects; never trust a cached native snapshot."""
    from .runner import Host
    from . import fonts_lane_migration as migration
    host = (Host if host_factory is None else host_factory)(facts["host"])
    initial = migration._initialization_verified(host)
    if (initial["manifest_sha256"] !=
            facts["intent"]["initialization_manifest_sha256"]
            or initial["source_tree_sha256"] !=
            facts["intent"]["initialized_source_tree_sha256"]):
        raise RuntimeError("native initializer manifest/source trees differ from original intent")
    execution = existing_project_runtime.inspect(host, facts["spec"])
    if execution["status"] != "complete":
        raise RuntimeError("selected certbot-seed controller is not installed")
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "verified-read-only",
        "binding": facts["binding"],
        "selected_project_root": EXISTING_EXECUTION_PROJECT,
        "initialized_project_root": str(lanes.FIRST_FONTS_MIGRATED_ROOT),
        "original_specification_sha256": facts["original_sha"],
        "corrected_specification_sha256": facts["corrected_sha"],
        "selected_specification_sha256": facts["selected_sha"],
        "selected_lane_record_sha256": facts["record_sha"],
        "pending_intent_sha256": facts["intent_sha"],
        "initialization_manifest_sha256": initial["manifest_sha256"],
        "initialized_source_tree_sha256": initial["source_tree_sha256"],
        "selected_controller_sha256": execution["controller_sha256"],
        "selected_source_revision_observed": execution["source_revision"],
        "compiler_effective_uid_observed": execution["effective_user_id"],
        "execution_authorized": False,
        "mutation": False,
    }


def inspect(directory, *, expected_original_specification_sha256,
            expected_corrected_specification_sha256,
            expected_selected_specification_sha256, host_factory=None):
    """Read-only native evidence for both distinct compiler Projects.

    Source-only inspection never grants a new build. Native proof is repeated
    at the publication boundary and immutable receipt remains nonauthorizing.
    """
    with locked(directory) as root:
        facts = _facts(root,
                       original_sha=expected_original_specification_sha256,
                       corrected_sha=expected_corrected_specification_sha256,
                       selected_sha=expected_selected_specification_sha256)
        return _native_report(facts, host_factory)


def publish(directory, *, expected_original_specification_sha256,
            expected_corrected_specification_sha256,
            expected_selected_specification_sha256, host_factory=None):
    """Publish only a distinct create-only 0600 evidence receipt, NEVER lane JSON.

    Explicit owner action. A failed native check writes nothing, including
    no replacement for the interrupted migration intent or original archive.
    """
    report = inspect(
        directory,
        expected_original_specification_sha256=expected_original_specification_sha256,
        expected_corrected_specification_sha256=expected_corrected_specification_sha256,
        expected_selected_specification_sha256=expected_selected_specification_sha256,
        host_factory=host_factory)
    with locked(directory) as root:
        facts = _facts(root,
                       original_sha=expected_original_specification_sha256,
                       corrected_sha=expected_corrected_specification_sha256,
                       selected_sha=expected_selected_specification_sha256)
        if (facts["record_sha"] != report["selected_lane_record_sha256"]
                or facts["intent_sha"] != report["pending_intent_sha256"]):
            raise RuntimeError("mixed-state evidence changed between native readback and publication")
        # The controller can drift while the local lane and intent remain
        # identical. Reinspect the actual selected Host while holding the
        # publication lock. An old receipt is NOT an admission-time proof.
        if _native_report(facts, host_factory) != report:
            raise RuntimeError(
                "compiler controller or initialization changed before receipt publication")
        path = root / RECEIPT
        raw = _canonical(report) + b"\n"
        if path.exists() or path.is_symlink():
            prior, _ = _read(root, RECEIPT)
            if prior != report:
                raise RuntimeError("existing first Fonts recovery receipt differs")
            return prior
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if os.write(fd, raw) != len(raw):
                raise OSError("short mixed-state recovery receipt write")
            os.fsync(fd)
        finally:
            os.close(fd)
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        verified, _ = _read(root, RECEIPT)
        if verified != report:
            raise RuntimeError("mixed-state recovery receipt readback differs")
        return verified


def verify_published(root, workspace, host, record, spec):
    """Gateway-local check only; NEVER infer approval from the active lane.

    An absent protected recovery receipt is a HOLD even if the existing
    Project can be inspected. History/intent and active lane still must be
    independently consistent; the original missing archive stays missing.
    """
    receipt, _ = _read(Path(root), RECEIPT)
    if (receipt.get("schema") != RECEIPT_SCHEMA
            or receipt.get("status") != "verified-read-only"
            or receipt.get("execution_authorized") is not False
            or receipt.get("mutation") is not False
            or receipt.get("binding") != {
                "workspace_id": workspace.get("workspace_id"),
                "account_id": host.get("account_id"),
                "region": host.get("region"),
                "instance_id": host.get("instance_id"),
            }):
        raise RuntimeError("protected mixed-state recovery receipt is not the approved Host")
    facts = _facts(
        Path(root),
        original_sha=receipt.get("original_specification_sha256"),
        corrected_sha=receipt.get("corrected_specification_sha256"),
        selected_sha=receipt.get("selected_specification_sha256"))
    if (facts["record_sha"] != receipt.get("selected_lane_record_sha256")
            or facts["intent_sha"] != receipt.get("pending_intent_sha256")
            or record.get("specification") != spec
            or record != _read(Path(root), "image-build-lanes/" + LANE + ".json")[0]
            or type(receipt.get("initialization_manifest_sha256")) is not str
            or receipt["initialization_manifest_sha256"] !=
                facts["intent"]["initialization_manifest_sha256"]
            or receipt.get("initialized_source_tree_sha256") !=
                facts["intent"]["initialized_source_tree_sha256"]
            or receipt.get("selected_project_root") != EXISTING_EXECUTION_PROJECT
            or receipt.get("initialized_project_root") !=
                str(lanes.FIRST_FONTS_MIGRATED_ROOT)
            or type(receipt.get("selected_controller_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", receipt["selected_controller_sha256"])
            or receipt.get("selected_controller_sha256") !=
                hashlib.sha256(existing_project_runtime.expected_bytes(spec)).hexdigest()):
        raise RuntimeError("mixed-state receipt differs from current immutable lane/intent")
    return receipt
