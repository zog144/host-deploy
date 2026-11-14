"""Explicit first-Fonts migration, preserving the original schema-4 lane as evidence.

This is a selected-Host maintenance operation, not a build submission. Each
remote write is guarded by a durable workspace intent and read-only recovery.
No selectable account, owner-home inference, or UID/GID switch is supported.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

from . import image_build_lanes as lanes
from . import fonts_lane_profile as fonts
from . import fonts_lane_runtime as runtime
from .provision import configuration
from .runner import Host
from .workspace import locked, save

SCHEMA = "host-deploy-first-fonts-migration-intent-v1"
INITIALIZATION_SCHEMA = "host-deploy-first-fonts-initialization-intent-v1"
INTENT = "first-fonts-inherited-migration-v1.json"
HISTORY = "first-fonts-original-evidence"
_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")


def _hash(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("migration evidence missing or symlinked: " + str(path))
    return json.loads(path.read_bytes())


def _source_selection(host, spec):
    """Read-only verification of the reviewed checkout, companions and old pin.

    This is SSM-process evidence, *not* a compiler-child identity attestation.
    """
    root = Path(spec["project_root"])
    source = root / "source"
    paths = {"source": str(source), "box": str(root / "companions/box-control"),
             "record": str(root / "companions/build-record")}
    revisions = {"source": spec["source_revision"],
                 "box": lanes.expected_controller_revision(spec["source_revision"]),
                 "record": lanes.expected_build_record_revision(spec["source_revision"])}
    pin = root / "state/image-build/build-record/artifacts" / spec["monthly_pin_identity"][7:]
    script = r'''
import hashlib,json,os,stat,subprocess
from pathlib import Path
P=json.loads(PATHS)
R=json.loads(REVISIONS)
for key,path in P.items():
    directory=Path(path)
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError('selected checkout missing or linked: '+key)
    def git(*args):
        completed=subprocess.run(['git','-C',str(directory),*args],
                     capture_output=True,text=True,timeout=30,check=False)
        if completed.returncode:
            raise RuntimeError('selected checkout cannot be inspected: '+key)
        return completed.stdout.strip()
    if git('rev-parse','--verify','HEAD')!=R[key] or git('status','--porcelain=v1','--untracked-files=all'):
        raise RuntimeError('selected checkout revision or cleanliness differs: '+key)
source=Path(P['source'])
if (source/ORIGINAL_PIN).exists() or (source/ORIGINAL_PIN).is_symlink():
    raise RuntimeError('new public producer incorrectly contains historical pin')
pin=Path(PIN)
fd=os.open(pin,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>1048576:
        raise RuntimeError('retained pin artifact is unsafe')
    with os.fdopen(fd,'rb') as stream:
        fd=-1
        observed=hashlib.sha256(stream.read()).hexdigest()
finally:
    if fd>=0: os.close(fd)
if observed!=PIN_SHA:
    raise RuntimeError('retained original October pin differs')
print(json.dumps({'schema':'host-deploy-fonts-executable-source-inspection-v1',
                  'revisions':R,'pin_sha256':'sha256:'+observed,
                  'effective_uid':os.geteuid(),'effective_gid':os.getegid()},sort_keys=True))
'''
    prefix = ("PATHS=" + repr(json.dumps(paths)) + "\n"
              "REVISIONS=" + repr(json.dumps(revisions)) + "\n"
              "ORIGINAL_PIN=" + repr(lanes.FIRST_FONTS_ORIGINAL_PIN_PATH) + "\n"
              "PIN=" + repr(str(pin)) + "\n"
              "PIN_SHA=" + repr(spec["monthly_pin_identity"][7:]) + "\n")
    report = json.loads(host.command("python3 -c " + shlex.quote(prefix + script)))
    if (type(report) is not dict or set(report) != {
            "schema", "revisions", "pin_sha256", "effective_uid", "effective_gid"}
            or report["schema"] != "host-deploy-fonts-executable-source-inspection-v1"
            or report["revisions"] != revisions
            or report["pin_sha256"] != spec["monthly_pin_identity"]
            or any(type(report[key]) is not int or report[key] < 0
                   for key in ("effective_uid", "effective_gid"))):
        raise RuntimeError("selected installed Fonts source or original pin differs")
    return report


def _copy_verified(host):
    """Authenticate the owning host-install copy *before* replacing copied source."""
    report = json.loads(host.command("host-install-fonts-project-migrate --verify"))
    if (type(report) is not dict or report.get("schema") !=
            "zog-fonts-project-nondestructive-migration-v1"
            or report.get("action") != "verify"
            or report.get("old_project") != fonts.RETAINED_PROJECT_ROOT
            or report.get("new_project") != fonts.PROJECT_ROOT
            or report.get("data_verified") is not True
            or report.get("old_project_preserved") is not True
            or report.get("source_unchanged") is not True
            or report.get("controller_rebound") is not False
            or report.get("accounts_deleted") is not False
            or type(report.get("source_tree_sha256")) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", report["source_tree_sha256"])):
        raise RuntimeError("host-install copy is not the verified original Fonts Project")
    destination = report.get("destination")
    if (type(destination) is not dict or
            destination.get("read_write_traverse") is not True or
            destination.get("state_accessible") is not True or
            destination.get("source_accessible") is not True):
        raise RuntimeError("migrated Project is inaccessible to the selected inspection process")
    return report



def _initialization_verified(host):
    """Accept only a REAL owning installer initialization, never a copy receipt.

    The original retained workspace record is separately required to be prepared.
    Actual Git checkouts at the corrected Project root are individually hashed
    and authenticated by host-install. Neither OLD nor migration copy is claimed.
    """
    report = json.loads(host.command("host-install-fonts-project-init --verify"))
    expected = {
        "source": {"repository": "zog144/image-build",
                   "revision": lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION},
        "companions/box-control": {"repository": lanes.BOX_CONTROL_REPOSITORY,
                                   "revision": lanes.FIRST_FONTS_INHERITED_BOX_CONTROL_REVISION},
        "companions/build-record": {"repository": lanes.BUILD_RECORD_REPOSITORY,
                                     "revision": lanes.expected_build_record_revision(
                                         lanes.FIRST_FONTS_INHERITED_PRODUCER_REVISION)},
    }
    if (type(report) is not dict or report.get("schema") !=
            "zog-fonts-project-first-initialization-v1"
            or report.get("action") != "verify"
            or report.get("old_project") != fonts.RETAINED_PROJECT_ROOT
            or report.get("new_project") != fonts.PROJECT_ROOT
            or report.get("historical_project_materialized") is not False
            or report.get("copy_performed") is not False
            or report.get("initialized_source_verified") is not True
            or report.get("layout_complete") is not True
            or report.get("missing_layout_directories") != []
            or report.get("runtime_layout", {}).get("status") != "ready"
            or report.get("runtime_layout", {}).get("missing") != []
            or report.get("controllers_present") != []
            or report.get("controller_installed") is not False
            or report.get("compilation_authorized") is not False
            or report.get("source_checkouts") != expected
            or type(report.get("manifest_sha256")) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", report["manifest_sha256"])):
        raise RuntimeError("native first Fonts initialization is not verified")
    hashes = report.get("source_tree_sha256")
    if (type(hashes) is not dict or set(hashes) != set(expected)
            or any(type(v) is not str or not re.fullmatch(r"[a-f0-9]{64}", v)
                   for v in hashes.values())):
        raise RuntimeError("first Fonts initialized source trees differ from reviewed inputs")
    dest = report.get("destination")
    if (type(dest) is not dict or dest.get("read_write_traverse") is not True
            or dest.get("state_accessible") is not True
            or dest.get("source_accessible") is not True):
        raise RuntimeError("initialized Fonts Project is not accessible to executing process")
    return report


def _intent(root, workspace, host, old, new, evidence, *, prepared_initialize=False):
    result = {"schema": INITIALIZATION_SCHEMA if prepared_initialize else SCHEMA,
              "phase": "staged",
              "source_method": ("prepared-first-initialization" if prepared_initialize
                                else "verified-legacy-copy"),
              "binding": fonts._binding(workspace, host),
              "old_specification_sha256": lanes.specification_sha256(old),
              "new_specification_sha256": lanes.specification_sha256(new),
              "project_root": str(lanes.FIRST_FONTS_MIGRATED_ROOT),
              "source_revision": new["source_revision"],
              "compiler_authorized": False}
    if prepared_initialize:
        result["initialization_manifest_sha256"] = evidence["manifest_sha256"]
        result["initialized_source_tree_sha256"] = evidence["source_tree_sha256"]
        result["historical_project_materialized"] = False
        result["copy_performed"] = False
    else:
        result["copy_source_tree_sha256"] = evidence["source_tree_sha256"]
        result["copy_report_sha256"] = _hash(fonts._canonical(evidence))
    return result


def stage(directory, *, expected_original_specification_sha256,
          expected_corrected_specification_sha256, prepared_initialize=False,
          host_factory=Host):
    """Record reviewed copy OR explicit never-materialized initialization.

    Both cases preserve the historical prepared lane record without changing it.
    Only the explicit prepared_initialize path accepts initializer evidence.
    """
    with locked(directory) as root:
        workspace, config = fonts._owner(root)
        record, old, digest = fonts._approved(root)
        corrected = lanes.corrected_first_fonts_specification(old)
        if (digest != expected_original_specification_sha256 or
                lanes.specification_sha256(corrected) != expected_corrected_specification_sha256):
            raise RuntimeError("first Fonts migration digest differs from reviewed inputs")
        if type(prepared_initialize) is not bool:
            raise RuntimeError("explicit prepared-initialization selector must be Boolean")
        if prepared_initialize and record["state"] != "prepared":
            raise RuntimeError("only a never-activated prepared lane may be initialized")
        expected_schema = INITIALIZATION_SCHEMA if prepared_initialize else SCHEMA
        path = root / INTENT
        if path.exists() or path.is_symlink():
            current = _read(path)
            if (current.get("schema") == expected_schema and
                    current.get("source_method") ==
                    ("prepared-first-initialization" if prepared_initialize else "verified-legacy-copy") and
                    current.get("old_specification_sha256") == digest and
                    current.get("new_specification_sha256") ==
                    expected_corrected_specification_sha256 and
                    current.get("binding") == fonts._binding(workspace, config)):
                return current  # repeat is read-only; do not redo SSM copy
            raise RuntimeError("existing Fonts migration intent conflicts with approved record")
        host = host_factory(config)
        evidence = (_initialization_verified(host) if prepared_initialize
                    else _copy_verified(host))
        expected = _intent(root, workspace, config, old, corrected, evidence,
                           prepared_initialize=prepared_initialize)
        # Preserve ordinary disk admission without reinstating RAM reservations.
        capacity = lanes._capacity(host, Path(corrected["project_root"]))
        others = [record for record in lanes._active_records(root)
                  if record["lane"] != fonts.LANE]
        reserved = sum(item["specification"]["resource_policy"]["disk_reservation_bytes"]
                       for item in others)
        if reserved + corrected["resource_policy"]["disk_reservation_bytes"] > capacity["disk_free_bytes"]:
            raise RuntimeError("migrated first Fonts disk reservation exceeds free capacity")
        expected["disk_capacity"] = capacity
        save(path, expected)
        return expected


def _archive(root, record_path, spec_sha):
    """Preserve exact raw schema-4 bytes before atomically publishing schema 5."""
    raw = record_path.read_bytes()
    record = json.loads(raw)
    if record.get("schema") != lanes.SCHEMA or lanes.specification_sha256(
            record["specification"]) != spec_sha:
        raise RuntimeError("historical lane changed before archive publication")
    directory = root / HISTORY
    if directory.is_symlink():
        raise RuntimeError("history archive redirected")
    directory.mkdir(mode=0o700, exist_ok=True)
    if not directory.is_dir():
        raise RuntimeError("invalid history archive location")
    path = directory / (spec_sha[7:] + ".json")
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
            raise RuntimeError("historical evidence archive differs")
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
        finally:
            pass
        d = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(d)
        finally: os.close(d)
    return _hash(raw), str(path)


def _new_record(spec, intent, archived_sha, archived_path):
    root = Path(spec["project_root"])
    producer = spec["source_revision"]
    return {
        "schema": lanes.INHERITED_SCHEMA,
        "lane": fonts.LANE, "state": "active", "specification": spec,
        "controller_config": str(root / runtime.CONTROLLER_FILE),
        "source_root": str(root / "source"),
        "package_dir": str(root / "source/project/package"),
        "state_dir": str(root / "state"),
        "runtime_companion": {
            "schema": lanes.RUNTIME_COMPANION_SCHEMA,
            "repository": lanes.BUILD_RECORD_REPOSITORY,
            "revision": lanes.expected_build_record_revision(producer),
            "source_root": str(root / "companions/build-record"),
            "producer_revision": producer},
        "controller_companion": {
            "schema": lanes.CONTROLLER_COMPANION_SCHEMA,
            "repository": lanes.BOX_CONTROL_REPOSITORY,
            "revision": lanes.expected_controller_revision(producer),
            "source_root": str(root / "companions/box-control"),
            "producer_revision": producer},
        "fonts_migration": {
            "schema": 1,
            "original_specification_sha256": intent["old_specification_sha256"],
            "corrected_specification_sha256": intent["new_specification_sha256"],
            "original_record_sha256": archived_sha,
            "historical_record_path": archived_path,
            "source_method": intent.get("source_method", "verified-legacy-copy"),
            **({"initialization_manifest_sha256": intent["initialization_manifest_sha256"],
                "initialized_source_tree_sha256": intent["initialized_source_tree_sha256"],
                "historical_project_materialized": False, "copy_performed": False}
               if intent["schema"] == INITIALIZATION_SCHEMA else
               {"copy_source_tree_sha256": intent["copy_source_tree_sha256"],
                "copy_report_sha256": intent["copy_report_sha256"]}),
            "controller_file": runtime.CONTROLLER_FILE,
            "native_compiler_child_verified": False,
            "compilation_authorized": False,
        },
        "capacity": intent["disk_capacity"],
    }


def activate(directory, *, expected_corrected_specification_sha256, host_factory=Host):
    """Install new controller, retain old record, and publish the corrected lane.

    On an unknown remote acknowledgement, keep `phase=installing`. A later
    invocation reads the existing remote controller *without* resubmitting.
    This does not start a job or change the gateway's submission settings.
    """
    with locked(directory) as root:
        workspace, config = fonts._owner(root)
        path = lanes._path(root, fonts.LANE)
        record = _read(path)
        if record.get("schema") == lanes.INHERITED_SCHEMA:
            corrected = lanes.validate(record["specification"])
            migrated = record.get("fonts_migration")
            if (not isinstance(migrated, dict) or
                    migrated.get("corrected_specification_sha256") !=
                    expected_corrected_specification_sha256 or
                    lanes.specification_sha256(corrected) !=
                    expected_corrected_specification_sha256):
                raise RuntimeError("already migrated lane differs from reviewed digest")
            observed = runtime.inspect(host_factory(config), corrected)
            if observed["status"] != "complete":
                raise RuntimeError("active corrected controller installation is incomplete")
            _source_selection(host_factory(config), corrected)
            if not Path(migrated["historical_record_path"]).is_file():
                raise RuntimeError("historical lane archive missing")
            if _hash(Path(migrated["historical_record_path"]).read_bytes()) != migrated["original_record_sha256"]:
                raise RuntimeError("historical lane archive changed")
            return record
        _, old, old_digest = fonts._approved(root)
        corrected = lanes.corrected_first_fonts_specification(old)
        new_digest = lanes.specification_sha256(corrected)
        if new_digest != expected_corrected_specification_sha256:
            raise RuntimeError("corrected first Fonts digest differs from reviewed selection")
        intent_path = root / INTENT
        intent = _read(intent_path)
        if (intent.get("schema") not in {SCHEMA, INITIALIZATION_SCHEMA}
                or intent.get("phase") not in {"staged", "installing"}
                or intent.get("old_specification_sha256") != old_digest
                or intent.get("new_specification_sha256") != new_digest
                or intent.get("binding") != fonts._binding(workspace, config)
                or intent.get("project_root") != corrected["project_root"]
                or intent.get("source_revision") != corrected["source_revision"]
                or intent.get("compiler_authorized") is not False):
            raise RuntimeError("migration intent differs from retained reviewed lane")
        host = host_factory(config)
        _source_selection(host, corrected)
        observed = runtime.inspect(host, corrected)
        if observed["status"] == "partial":
            raise RuntimeError("partial corrected controller installation requires recovery inspection")
        if intent["phase"] == "staged":
            if observed["status"] not in {"absent", "prepared"}:
                raise RuntimeError("controller appeared before reviewed installation intent; inspect foreign files")
            intent["phase"] = "installing"
            save(intent_path, intent)  # durability before remote mutation
            runtime.install(host, corrected)
            observed = runtime.inspect(host, corrected)
        if observed["status"] != "complete":
            raise RuntimeError("remote controller write unresolved; inspect original SSM command; no resubmission")
        archive_sha, archive_path = _archive(root, path, old_digest)
        updated = _new_record(corrected, intent, archive_sha, archive_path)
        lanes.validate_runtime_companion(updated["runtime_companion"], project_root=corrected["project_root"])
        lanes.validate_controller_companion(updated["controller_companion"], project_root=corrected["project_root"])
        save(path, updated)
        return updated


def verify_existing(root, workspace, host, record):
    """Read-only proof that an active lane descends from the exact old bytes."""
    spec = lanes.validate(record.get("specification"))
    if (record.get("schema") != lanes.INHERITED_SCHEMA or
            record.get("lane") != fonts.LANE or record.get("state") != "active" or
            spec["lane"] != fonts.LANE or spec["mode"] != "managed"):
        raise RuntimeError("not an installed inherited first Fonts lane")
    meta = record.get("fonts_migration")
    if type(meta) is not dict or meta.get("schema") != 1:
        raise RuntimeError("corrected lane lacks migration provenance")
    approved = fonts.RETAINED_SPECIFICATION_SHA256
    path = (root / HISTORY / (approved[7:] + ".json"))
    if meta.get("historical_record_path") != str(path) or path.is_symlink():
        raise RuntimeError("historical first Fonts archive path differs")
    raw = path.read_bytes()
    if meta.get("original_record_sha256") != _hash(raw):
        raise RuntimeError("original preserved record bytes differ")
    original = json.loads(raw)
    old = lanes.validate(original.get("specification"))
    if (original.get("schema") != lanes.SCHEMA or original.get("lane") != fonts.LANE
            or old["schema"] != lanes.SCHEMA or old["lane"] != fonts.LANE
            or old["source_revision"] != lanes.FIRST_FONTS_PRODUCER_REVISION
            or old["project_root"] != fonts.RETAINED_PROJECT_ROOT
            or lanes.specification_sha256(old) != approved
            or meta.get("original_specification_sha256") != approved):
        raise RuntimeError("historical first Fonts archive differs from approval")
    expected = lanes.corrected_first_fonts_specification(old)
    if (spec != expected or meta.get("corrected_specification_sha256") !=
            lanes.specification_sha256(expected)
            or record.get("controller_config") != str(Path(spec["project_root"]) / runtime.CONTROLLER_FILE)
            or record.get("source_root") != str(Path(spec["project_root"]) / "source")
            or record.get("state_dir") != str(Path(spec["project_root"]) / "state")
            or record.get("package_dir") != str(Path(spec["project_root"]) / "source/project/package")
            or meta.get("compilation_authorized") is not False):
        raise RuntimeError("corrected first Fonts installed lane differs from source-owned contract")
    for name, validator in (("runtime_companion", lanes.validate_runtime_companion),
                            ("controller_companion", lanes.validate_controller_companion)):
        value = record.get(name)
        selected = validator(value, project_root=spec["project_root"])
        if selected["producer_revision"] != spec["source_revision"]:
            raise RuntimeError("installed first Fonts companion source differs: " + name)
    intent = _read(root / INTENT)
    if (meta.get("source_method") !=
            ("prepared-first-initialization" if intent.get("schema") == INITIALIZATION_SCHEMA
             else "verified-legacy-copy")):
        raise RuntimeError("first Fonts establishment method differs from retained source intent")
    if (intent.get("schema") not in {SCHEMA, INITIALIZATION_SCHEMA}
            or intent.get("phase") != "installing"
            or intent.get("binding") != fonts._binding(workspace, host)
            or intent.get("old_specification_sha256") != approved
            or intent.get("new_specification_sha256") != lanes.specification_sha256(expected)
            or ((intent.get("initialization_manifest_sha256") !=
                 meta.get("initialization_manifest_sha256") or
                 intent.get("initialized_source_tree_sha256") !=
                 meta.get("initialized_source_tree_sha256") or
                 meta.get("historical_project_materialized") is not False or
                 meta.get("copy_performed") is not False)
                if intent["schema"] == INITIALIZATION_SCHEMA else
                (intent.get("copy_source_tree_sha256") != meta.get("copy_source_tree_sha256")
                 or intent.get("copy_report_sha256") != meta.get("copy_report_sha256")))):
        raise RuntimeError("migration intent differs from installed corrected lane")
    return {
        "schema": "host-deploy-first-fonts-activated-history-inspection-v1",
        "historical_specification_sha256": approved,
        "historical_record_sha256": meta["original_record_sha256"],
        "corrected_specification_sha256": lanes.specification_sha256(expected),
        "corrected_project_root": spec["project_root"],
        "execution_authorized": False,
        "native_compiler_child_verified": False,
        "historical_archive": str(path),
        "binding": fonts._binding(workspace, host),
    }
