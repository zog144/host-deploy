"""One-shot root-owned FIRST graphics task catalogue; definition != admission.

The exact accepted base and managed lane owner MUST come from independently
verified native Work evidence. No placeholder, historical job, source commit,
or user-controlled request can stand in for those identities. No SSM, PID1,
build.submit or secret transport occurs from this module.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .. import image_build_lanes
from . import task_catalogue
from . import graphics_base_acceptance as base_acceptance

SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
REPOSITORY = "zog144/image-build"
PIN_PATH = "project/pins/2026-10-01/commit-pin.py"
PIN_SHA256 = "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
PIN_DATE = "2026-10-01"
TASK = "graphics-fonts-image-v1"
EVIDENCE_SCHEMA = "host-deploy-reviewed-compiler-base-selection-v1"
READER_SOURCE = "1616f192ef9d8964a8f37f32a86c69c0242a213c"
RECEIPT_SCHEMA = "host-deploy-graphics-catalogue-installed-v1"
STORE = Path("/var/lib/zog/fonts")
CATALOGUE = STORE / "graphics-foundation-catalogue-v1.json"
RECEIPT = STORE / "graphics-foundation-catalogue-receipt-v1.json"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class GraphicalCatalogueBlocked(RuntimeError):
    pass


def _fail():
    raise GraphicalCatalogueBlocked("graphical-catalogue-native-evidence-not-accepted")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _selection(lane_record, accepted_base, issuer):
    """Bind the installed managed lane to a signed compiler receipt.

    No separate policy file: the compiler receipt/lane and trusted installer
    selection are the sources of these identifiers.
    """
    lane = image_build_lanes.validate(lane_record)
    if (lane["schema"] != image_build_lanes.SCHEMA
            or lane["mode"] != "managed"
            or lane["source_repository"] != REPOSITORY
            or lane["source_revision"] != SOURCE
            or lane["monthly_pin_repository_path"] != PIN_PATH
            or lane["monthly_pin_identity"] != "sha256:" + PIN_SHA256):
        _fail()
    if (type(accepted_base) is not dict
            or set(accepted_base) != {
                "schema", "generation_id", "kind", "acceptance_receipt_sha256",
                "source_repository", "verified_source_revision"}
            or accepted_base["schema"] != EVIDENCE_SCHEMA
            or type(accepted_base["generation_id"]) is not str
            or _HEX64.fullmatch(accepted_base["generation_id"]) is None
            or accepted_base["kind"] not in ("toolchain", "image")
            or type(accepted_base["acceptance_receipt_sha256"]) is not str
            or re.fullmatch(r"sha256:[a-f0-9]{64}",
                            accepted_base["acceptance_receipt_sha256"]) is None
            or accepted_base["source_repository"] != REPOSITORY
            or accepted_base["verified_source_revision"] != READER_SOURCE
            or type(issuer) is not dict
            or type(issuer.get("installation_id")) is not str
            or not issuer["installation_id"]):
        _fail()
    # Transient arguments to the existing independently reviewed compiler
    # acceptance reader, which names this context 'approval'. This is NOT a
    # filesystem approval record or an additional source of authority.
    return lane, {
        "accepted_base_generation_id": accepted_base["generation_id"],
        "accepted_base_receipt_sha256": accepted_base["acceptance_receipt_sha256"],
        "host_id": lane["provenance_host_id"],
        "installation_id": issuer["installation_id"],
    }


def prepare(*, lane_record, accepted_base, installed_pin_bytes,
            compiler_base_receipt_bytes=None,
            compiler_base_issuer_policy=None, compiler_base_binding=None):
    """Pure catalogue candidate from native-selected lane and compiler evidence.

    This does not read, write, or require a Fonts approval file. The monthly
    source pin is checked against both the managed lane and actual pin bytes;
    the selected generation is checked against the signed compiler receipt.
    """
    lane, selection = _selection(
        lane_record, accepted_base, compiler_base_issuer_policy)
    # The original generation kind is immutable; only a verified Ed25519
    # acceptance plus protected canonical producer binding can select it.
    bound_base = base_acceptance.checked_base(
        compiler_base_receipt_bytes, compiler_base_issuer_policy,
        compiler_base_binding, approval=selection, lane=lane)
    if (bound_base["kind"] != accepted_base["kind"]
            or bound_base["generation_id"] != accepted_base["generation_id"]
            or bound_base["accepted_receipt_sha256"] !=
               accepted_base["acceptance_receipt_sha256"]):
        _fail()
    base_acceptance.retained_generation(
        task=TASK, generation_id=selection["accepted_base_generation_id"],
        kind=accepted_base["kind"], evidence=bound_base,
        approved_input_generation_id=selection["accepted_base_generation_id"])
    if (type(installed_pin_bytes) is not bytes
            or hashlib.sha256(installed_pin_bytes).hexdigest() != PIN_SHA256):
        _fail()
    fixed = task_catalogue.REVIEWED_IMAGE_TASKS[TASK]
    accepted_input = {
        "generation_id": bound_base["generation_id"],
        "kind": bound_base["kind"], "evidence": bound_base,
    }
    retained_identity = _sha(_canonical(accepted_input))
    task = {
        "source_repository": REPOSITORY, "source_revision": SOURCE,
        "lane": lane["lane"], "lane_owner": lane["provenance_host_id"],
        "monthly_pin_repository_path": PIN_PATH,
        "monthly_pin_identity": "sha256:" + PIN_SHA256,
        "retained_acceptance_sha256": retained_identity,
        "pin_date": PIN_DATE,
        "entries": [
            {"id": key, "project": project, "recipe": recipe}
            for key, project, recipe in fixed["entries"]],
        "arguments": {
            "mode": "image",
            "selection": selection["accepted_base_generation_id"],
            # This is a frozen *receipt identity*, not a new task approval.
            # The actual producer checks independent issuer, retained bytes
            # and original kind=image/toolchain again at pipeline submission.
            "compiler_base": bound_base["accepted_receipt_sha256"],
            "targets": list(fixed["targets"]),
        },
    }
    value = task_catalogue.validate({
        "schema": task_catalogue.SCHEMA, "tasks": {TASK: task}})
    raw = _canonical(value)
    return {"catalogue": value, "bytes": raw, "sha256": _sha(raw),
            "accepted_base_receipt_sha256": selection["accepted_base_receipt_sha256"],
            "retained_acceptance_sha256": retained_identity,
            "accepted_base_manifest_sha256": bound_base["manifest_sha256"],
            "accepted_base_inventory_sha256": bound_base["inventory_sha256"],
            "accepted_base_generation_record_sha256": bound_base["generation_record_sha256"],
            "accepted_base_kind": bound_base["kind"],
            "accepted_base_state_volume_id": bound_base["state_volume_id"],
            "accepted_base_compiler_files_sha256": bound_base["compiler_files_sha256"],
            "accepted_base_probe_sha256": bound_base["native_probe_sha256"],
            "accepted_base_environment_sha256": bound_base["execution_environment_sha256"],
            "accepted_base_historical_provenance": bound_base["historical_provenance"],
            "lane": lane["lane"], "host_id": selection["host_id"],
            "installation_id":selection["installation_id"],
            "accepted_base_generation_id":selection["accepted_base_generation_id"],
            "compiler_authorized": False}


def install_native(*, lane_name, generation_id,
                   read_managed_lane, read_accepted_base,
                   read_installed_pin, attest_installed_source,
                   attest_host_identity, read_compiler_base_receipt=None,
                   read_compiler_base_issuer=None,
                   read_compiler_base_binding=None):
    """Install the small catalogue and receipt once, without extra policy files.

    Work selects a managed lane and compiler generation through this trusted
    invocation. Their actual identities are verified by existing lane, issuer,
    receipt and producer-binding readers. Neither a 30+2 GiB budget nor any
    execution deadline is required here or by this catalogue.
    """
    if os.geteuid() != 0:
        raise PermissionError("protected graphical catalogue requires root")
    if (type(lane_name) is not str or not lane_name
            or type(generation_id) is not str
            or _HEX64.fullmatch(generation_id) is None
            or not all(callable(x) for x in (
                read_managed_lane, read_accepted_base, read_installed_pin,
                attest_installed_source, attest_host_identity,
                read_compiler_base_receipt, read_compiler_base_issuer,
                read_compiler_base_binding))):
        _fail()
    if (attest_installed_source(SOURCE) is not True
            or attest_installed_source(READER_SOURCE) is not True):
        _fail()
    root = STORE
    from .fresh_budget_guard import _protected_root
    _protected_root(root)
    # Refuse partial/replayed installations before reading further inputs.
    for target in (CATALOGUE, RECEIPT):
        if target.exists() or target.is_symlink():
            _fail()
    accepted = read_accepted_base(generation_id)
    if (type(accepted) is not dict
            or accepted.get("generation_id") != generation_id
            or type(accepted.get("acceptance_receipt_sha256")) is not str):
        _fail()
    candidate = prepare(
        lane_record=read_managed_lane(lane_name),
        accepted_base=accepted,
        compiler_base_receipt_bytes=read_compiler_base_receipt(generation_id),
        compiler_base_issuer_policy=read_compiler_base_issuer(),
        compiler_base_binding=read_compiler_base_binding(
            generation_id, accepted["acceptance_receipt_sha256"]),
        installed_pin_bytes=read_installed_pin(SOURCE, PIN_PATH),
    )
    if (candidate["lane"] != lane_name
            or candidate["accepted_base_generation_id"] != generation_id
            or attest_host_identity(
                candidate["host_id"], candidate["installation_id"]) is not True):
        _fail()
    # Existing root-owned catalogue loader verifies every ancestor is
    # non-writable and root-owned; no compiler quota evidence is read here.
    fd = os.open(CATALOGUE, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        written = os.write(fd, candidate["bytes"])
        if written != len(candidate["bytes"]):
            raise OSError("short protected graphical catalogue write")
        os.fsync(fd)
    finally:
        os.close(fd)
    st = CATALOGUE.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_dev != root.stat().st_dev):
        _fail()
    reread, digest = task_catalogue.load(CATALOGUE, require_root_owned=True)
    if reread != candidate["catalogue"] or digest != candidate["sha256"]:
        _fail()
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "catalogue_sha256": digest,
        "source_revision": SOURCE,
        "accepted_base_generation_id":candidate["accepted_base_generation_id"],
        "accepted_base_receipt_sha256":candidate["accepted_base_receipt_sha256"],
        "retained_acceptance_sha256":candidate["retained_acceptance_sha256"],
        "host_id":candidate["host_id"],
        "installation_id":candidate["installation_id"],
        "lane":candidate["lane"],
        "compiler_authorized":False,
        "status":"installed-catalogue-not-build-authorization",
    }
    raw_receipt = _canonical(receipt)
    fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.write(fd, raw_receipt) != len(raw_receipt):
            raise OSError("short protected graphics receipt write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return receipt
