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
from . import fresh_aggregate_disk as aggregate
from . import fresh_quota_volume as quota

SOURCE = "b0f53dbdec0e88b9b37feb5317398db3d20507dd"
REPOSITORY = "zog144/image-build"
PIN_PATH = "project/pins/2026-10-01/commit-pin.py"
PIN_SHA256 = "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
PIN_DATE = "2026-10-01"
TASK = "graphics-fonts-image-v1"
APPROVAL_SCHEMA = "host-deploy-graphics-catalogue-approval-v1"
EVIDENCE_SCHEMA = "image-build-self-hosted-base-acceptance-v1"
RECEIPT_SCHEMA = "host-deploy-graphics-catalogue-installed-v1"
STORE = Path(aggregate.EXTERNAL_MOUNT) / "owner-state"
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


def _checked_approval(value):
    keys = {"schema", "host_id", "installation_id", "lane", "lane_owner",
            "project_root", "accepted_base_generation_id",
            "accepted_base_receipt_sha256", "source_revision",
            "monthly_pin_identity", "task_allowlist",
            "dedicated_storage_bytes", "work_bytes", "external_bytes",
            "execution_limit_seconds"}
    if (type(value) is not dict or set(value) != keys
            or value["schema"] != APPROVAL_SCHEMA
            or value["source_revision"] != SOURCE
            or value["monthly_pin_identity"] != "sha256:" + PIN_SHA256
            or value["task_allowlist"] != [TASK]
            or value["dedicated_storage_bytes"] != 32 * 1024**3
            or value["work_bytes"] != 30 * 1024**3
            or value["external_bytes"] != 2 * 1024**3
            or value["execution_limit_seconds"] != 21600
            or type(value["accepted_base_generation_id"]) is not str
            or not _HEX64.fullmatch(value["accepted_base_generation_id"])
            or type(value["accepted_base_receipt_sha256"]) is not str
            or not re.fullmatch(r"sha256:[a-f0-9]{64}",
                                value["accepted_base_receipt_sha256"])):
        _fail()
    for k in ("host_id", "installation_id", "lane", "lane_owner", "project_root"):
        if type(value[k]) is not str or not value[k] or len(value[k]) > 512:
            _fail()
    return value


def prepare(*, approval, lane_record, accepted_base, installed_pin_bytes,
            actual_reservation):
    """Pure candidate. Does not install or attest the caller's dictionaries.

    Root Work must independently verify signed/genuine accepted generation,
    managed-lane installed Host provenance, installed image-build source and
    monthly pin, and actual 30+2 GiB kernel-backed images BEFORE calling.
    """
    a = _checked_approval(approval)
    lane = image_build_lanes.validate(lane_record)
    if (lane["schema"] != image_build_lanes.SCHEMA
            or lane["mode"] != "managed"
            or lane["lane"] != a["lane"]
            or lane["provenance_host_id"] != a["lane_owner"]
            or lane["provenance_host_id"] != a["host_id"]
            or lane["project_root"] != a["project_root"]
            or lane["source_repository"] != REPOSITORY
            or lane["source_revision"] != SOURCE
            or lane["monthly_pin_repository_path"] != PIN_PATH
            or lane["monthly_pin_identity"] != "sha256:" + PIN_SHA256
            or lane["resource_policy"]["disk_reservation_bytes"] != 32 * 1024**3):
        _fail()
    if (type(accepted_base) is not dict
            or set(accepted_base) != {
                "schema", "generation_id", "kind", "acceptance_receipt_sha256",
                "source_repository", "verified_source_revision"}
            or accepted_base["schema"] != EVIDENCE_SCHEMA
            or accepted_base["generation_id"] != a["accepted_base_generation_id"]
            or accepted_base["kind"] != "toolchain"
            or accepted_base["acceptance_receipt_sha256"] !=
                a["accepted_base_receipt_sha256"]
            or accepted_base["source_repository"] != REPOSITORY
            or not re.fullmatch(r"[a-f0-9]{40}",
                                accepted_base["verified_source_revision"])):
        _fail()
    if (type(installed_pin_bytes) is not bytes
            or hashlib.sha256(installed_pin_bytes).hexdigest() != PIN_SHA256):
        _fail()
    if (type(actual_reservation) is not dict or
            set(actual_reservation) != {"work_bytes", "external_bytes", "scope"}
            or actual_reservation != {
                "work_bytes": 30 * 1024**3, "external_bytes": 2 * 1024**3,
                "scope": aggregate.BUDGET_SCOPE}):
        _fail()
    fixed = task_catalogue.REVIEWED_IMAGE_TASKS[TASK]
    task = {
        "source_repository": REPOSITORY, "source_revision": SOURCE,
        "lane": a["lane"], "lane_owner": a["lane_owner"],
        "monthly_pin_repository_path": PIN_PATH,
        "monthly_pin_identity": "sha256:" + PIN_SHA256,
        "pin_date": PIN_DATE,
        "entries": [
            {"id": key, "project": project, "recipe": recipe}
            for key, project, recipe in fixed["entries"]],
        "arguments": {
            "mode": "image",
            "selection": a["accepted_base_generation_id"],
            "targets": list(fixed["targets"]),
        },
    }
    value = task_catalogue.validate({
        "schema": task_catalogue.SCHEMA, "tasks": {TASK: task}})
    raw = _canonical(value)
    return {"catalogue": value, "bytes": raw, "sha256": _sha(raw),
            "approval_sha256": _sha(_canonical(a)),
            "accepted_base_receipt_sha256": a["accepted_base_receipt_sha256"],
            "lane": a["lane"], "host_id": a["host_id"],
            "compiler_authorized": False}


def install_native(*, approval, read_managed_lane, read_accepted_base,
                   read_installed_pin, attest_installed_source):
    """Root owner only; one non-replacing installation into existing STATE.

    The four reader capabilities MUST be independently installed privileged
    attestations, not client-provided JSON or application callbacks. This API
    is deliberately NOT exposed in SSM/cron/watchdog/dispatch or HTTP RPC.
    """
    if os.geteuid() != 0:
        raise PermissionError("protected graphical catalogue requires root")
    # The installed owner/Work must bind actual source checkouts, immutable
    # generation acceptance and managed lane to the current Host/boot.
    if attest_installed_source(SOURCE) is not True:
        _fail()
    work = quota.inspect()
    external = aggregate.inspect_external_pool_native()
    if (work["capacity_bytes"] != 30 * 1024**3
            or external["limit_bytes"] > 2 * 1024**3
            or external.get("mount_verified") is not True
            or external.get("allocation_verified") is not True
            or external.get("budget_scope") != aggregate.BUDGET_SCOPE):
        _fail()
    root = STORE
    from .fresh_budget_guard import _protected_root
    _protected_root(root)
    for target in (CATALOGUE, RECEIPT):
        if target.exists() or target.is_symlink():
            _fail()
    a = _checked_approval(approval)
    candidate = prepare(
        approval=a, lane_record=read_managed_lane(a["lane"]),
        accepted_base=read_accepted_base(a["accepted_base_generation_id"]),
        installed_pin_bytes=read_installed_pin(SOURCE, PIN_PATH),
        actual_reservation={
            "work_bytes": work["capacity_bytes"],
            "external_bytes": 2 * 1024**3,
            "scope": external["budget_scope"],
        })
    # Existing root-owned catalogue loader verifies every ancestor is
    # non-writable and root-owned, including the backing mount and STATE.
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
        "schema": RECEIPT_SCHEMA, "catalogue_sha256": digest,
        "approval_sha256": candidate["approval_sha256"],
        "source_revision": SOURCE,
        "monthly_pin_identity": "sha256:" + PIN_SHA256,
        "accepted_base_generation_id": a["accepted_base_generation_id"],
        "accepted_base_receipt_sha256": a["accepted_base_receipt_sha256"],
        "host_id": a["host_id"], "installation_id": a["installation_id"],
        "lane": a["lane"], "lane_owner": a["lane_owner"],
        "task_allowlist": [TASK], "dedicated_storage_bytes": 32 * 1024**3,
        "work_bytes": 30 * 1024**3, "external_bytes": 2 * 1024**3,
        "execution_limit_seconds": 21600, "compiler_authorized": False,
        "status": "installed-catalogue-not-native-compiler-admission",
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
