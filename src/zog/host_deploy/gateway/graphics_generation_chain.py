"""Finite, non-dispatching graphical successor generation selector.

Source policy only. A trusted native owner MUST independently authenticate
producer completion, canonical generation acceptance, immutable source/pin,
Host/installation/lane and exclusive idle admission before installing a step.
No consumer-selected generation, SSM command, callback or network operation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import graphics_catalogue_owner as first
from . import task_catalogue

SCHEMA = "host-deploy-graphics-generation-chain-policy-v1"
EVIDENCE = "image-build-verified-graphical-predecessor-v1"
RECEIPT = "host-deploy-graphics-chain-step-installed-v1"
TASKS = (
    "graphics-fonts-image-v1",
    "graphics-xcb-core-image-v1",
    "graphics-x11-core-image-v1",
)
EXACT_HEX = re.compile(r"[a-f0-9]{64}\Z")
EXACT_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
EXACT_ID = re.compile(r"[a-f0-9]{32}\Z")
STORE = first.STORE
POLICY = STORE / "graphics-generation-chain-policy-v1.json"
FILES = {
    TASKS[1]: (STORE / "graphics-chain-xcb-catalogue-v1.json",
               STORE / "graphics-chain-xcb-receipt-v1.json"),
    TASKS[2]: (STORE / "graphics-chain-x11-catalogue-v1.json",
               STORE / "graphics-chain-x11-receipt-v1.json"),
}


class ChainBlocked(RuntimeError):
    pass


def _deny():
    raise ChainBlocked("graphical-generation-chain-not-independently-accepted")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _hash(obj):
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


def _valid_hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def validate_policy(value):
    """One-time operator approval, anchored to the installed fonts catalogue."""
    keys = {"schema", "host_id", "installation_id", "lane", "lane_owner",
            "project_root", "source_revision", "monthly_pin_identity",
            "first_catalogue_sha256", "first_receipt_sha256",
            "first_base_generation_id", "first_base_receipt_sha256",
            "task_allowlist", "work_bytes", "external_bytes",
            "dedicated_storage_bytes", "execution_limit_seconds",
            "max_generations"}
    if type(value) is not dict or set(value) != keys or value["schema"] != SCHEMA:
        _deny()
    if (value["source_revision"] != first.SOURCE
            or value["monthly_pin_identity"] != "sha256:" + first.PIN_SHA256
            or value["task_allowlist"] != list(TASKS)
            or value["max_generations"] != 3
            or value["work_bytes"] != 30 * 1024**3
            or value["external_bytes"] != 2 * 1024**3
            or value["dedicated_storage_bytes"] != 32 * 1024**3
            or value["execution_limit_seconds"] != 21600):
        _deny()
    for key in ("host_id", "installation_id", "lane", "lane_owner", "project_root"):
        if type(value[key]) is not str or not 1 <= len(value[key]) <= 512:
            _deny()
    if value["lane_owner"] != value["host_id"]:
        _deny()
    for key in ("first_catalogue_sha256", "first_receipt_sha256",
                "first_base_receipt_sha256"):
        if not _valid_hex(value[key], EXACT_SHA):
            _deny()
    if not _valid_hex(value["first_base_generation_id"], EXACT_HEX):
        _deny()
    return json.loads(_canonical(value))


def _previous(policy, previous_task, catalogue, installed_receipt):
    """Verify immutable prior binding, never a client-provided generation hint."""
    if previous_task not in TASKS[:2]:
        _deny()
    validated = task_catalogue.validate(catalogue)
    if set(validated["tasks"]) != {previous_task}:
        _deny()
    digest = _hash(validated)
    spec = validated["tasks"][previous_task]
    if (spec["source_revision"] != first.SOURCE
            or spec["source_repository"] != first.REPOSITORY
            or spec["monthly_pin_identity"] != policy["monthly_pin_identity"]
            or spec["monthly_pin_repository_path"] != first.PIN_PATH
            or spec["pin_date"] != first.PIN_DATE
            or spec["lane"] != policy["lane"]
            or spec["lane_owner"] != policy["lane_owner"]
            or spec["arguments"]["mode"] != "image"):
        _deny()
    generation = spec["arguments"]["selection"]
    if previous_task == TASKS[0]:
        expected = {"schema": first.RECEIPT_SCHEMA,
                    "catalogue_sha256": digest,
                    "accepted_base_generation_id": generation,
                    "accepted_base_receipt_sha256":
                        policy["first_base_receipt_sha256"],
                    "source_revision": first.SOURCE,
                    "monthly_pin_identity": policy["monthly_pin_identity"],
                    "host_id": policy["host_id"],
                    "installation_id": policy["installation_id"],
                    "lane": policy["lane"],
                    "lane_owner": policy["lane_owner"],
                    "task_allowlist": [previous_task],
                    "compiler_authorized": False}
        if (digest != policy["first_catalogue_sha256"]
                or _hash(installed_receipt) != policy["first_receipt_sha256"]
                or generation != policy["first_base_generation_id"]):
            _deny()
    else:
        expected = {"schema": RECEIPT, "catalogue_sha256": digest,
                    "task": previous_task,
                    "selection_generation_id": generation,
                    "source_revision": first.SOURCE,
                    "monthly_pin_identity": policy["monthly_pin_identity"],
                    "host_id": policy["host_id"],
                    "installation_id": policy["installation_id"],
                    "lane": policy["lane"], "lane_owner": policy["lane_owner"],
                    "chain_policy_sha256": _hash(policy),
                    "compiler_authorized": False,
                    "status": "installed-not-compiler-admission"}
    if (type(installed_receipt) is not dict
            or any(installed_receipt.get(k) != v for k, v in expected.items())):
        _deny()
    return digest, generation


def resolve_successor(*, policy, previous_task, previous_catalogue,
                      previous_receipt, accepted_generation):
    """Pure review candidate, NOT authorization; no per-generation manual pin.

    accepted_generation MUST be supplied only by the independently installed
    protected image-build acceptance attester in the native owner. A passed
    dict or a completed pipeline status alone is NOT acceptance evidence.
    """
    policy = validate_policy(policy)
    prev_digest, selected = _previous(
        policy, previous_task, previous_catalogue, previous_receipt)
    if type(accepted_generation) is not dict or set(accepted_generation) != {
            "schema", "task", "host_id", "installation_id", "lane",
            "lane_owner", "project_root", "source_revision",
            "monthly_pin_identity", "request_id", "pipeline_id",
            "predecessor_catalogue_sha256", "input_generation_id",
            "output_generation_id", "output_kind", "generation_manifest_sha256",
            "acceptance_receipt_sha256", "producer_receipt_sha256",
            "status", "terminal_outcome", "uncertainty",
            "missing_evidence_count"}:
        _deny()
    ev = accepted_generation
    for k, expected in (("schema", EVIDENCE), ("task", previous_task),
                        ("host_id", policy["host_id"]),
                        ("installation_id", policy["installation_id"]),
                        ("lane", policy["lane"]),
                        ("lane_owner", policy["lane_owner"]),
                        ("project_root", policy["project_root"]),
                        ("source_revision", first.SOURCE),
                        ("monthly_pin_identity", policy["monthly_pin_identity"]),
                        ("predecessor_catalogue_sha256", prev_digest),
                        ("input_generation_id", selected),
                        ("output_kind", "image"), ("status", "accepted"),
                        ("terminal_outcome", "success"),
                        ("uncertainty", False),
                        ("missing_evidence_count", 0)):
        if type(ev[k]) is not type(expected) or ev[k] != expected:
            _deny()
    if not all(_valid_hex(ev[k], EXACT_ID) for k in ("request_id", "pipeline_id")):
        _deny()
    if (not _valid_hex(ev["output_generation_id"], EXACT_HEX)
            or ev["output_generation_id"] in {
                selected, policy["first_base_generation_id"]}):
        _deny()
    for k in ("generation_manifest_sha256", "acceptance_receipt_sha256",
              "producer_receipt_sha256"):
        if not _valid_hex(ev[k], EXACT_SHA):
            _deny()
    successor = TASKS[TASKS.index(previous_task) + 1]
    reviewed = task_catalogue.REVIEWED_IMAGE_TASKS[successor]
    task = {
        "source_repository": first.REPOSITORY,
        "source_revision": first.SOURCE,
        "lane": policy["lane"], "lane_owner": policy["lane_owner"],
        "monthly_pin_repository_path": first.PIN_PATH,
        "monthly_pin_identity": policy["monthly_pin_identity"],
        "pin_date": first.PIN_DATE,
        "entries": [
            {"id": name, "project": project, "recipe": recipe}
            for name, project, recipe in reviewed["entries"]],
        "arguments": {"mode": "image",
                      "selection": ev["output_generation_id"],
                      "targets": list(reviewed["targets"])},
    }
    cat = task_catalogue.validate({
        "schema": task_catalogue.SCHEMA, "tasks": {successor: task}})
    digest = _hash(cat)
    receipt = {
        "schema": RECEIPT, "task": successor, "catalogue_sha256": digest,
        "selection_generation_id": ev["output_generation_id"],
        "chain_policy_sha256": _hash(policy),
        "previous_catalogue_sha256": prev_digest,
        "predecessor_evidence_sha256": _hash(ev),
        "predecessor_generation_manifest_sha256":
            ev["generation_manifest_sha256"],
        "predecessor_acceptance_receipt_sha256":
            ev["acceptance_receipt_sha256"],
        "predecessor_request_id": ev["request_id"],
        "predecessor_pipeline_id": ev["pipeline_id"],
        "source_revision": first.SOURCE,
        "monthly_pin_identity": policy["monthly_pin_identity"],
        "host_id": policy["host_id"],
        "installation_id": policy["installation_id"],
        "lane": policy["lane"], "lane_owner": policy["lane_owner"],
        "compiler_authorized": False,
        "status": "installed-not-compiler-admission",
    }
    return {"catalogue": cat, "catalogue_sha256": digest,
            "catalogue_bytes": _canonical(cat), "receipt": receipt,
            "receipt_bytes": _canonical(receipt),
            "next_task": successor, "compiler_authorized": False}


def _read_locked(path):
    """Read exact root-only 0600 no-symlink record; reject duplicate keys."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_dev != STORE.stat().st_dev or st.st_size > 65536):
            _deny()
        raw = os.read(fd, 65537)
    finally:
        os.close(fd)
    if len(raw) > 65536:
        _deny()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _deny()
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _deny())
    except (ValueError, UnicodeError):
        _deny()


def _exclusive_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise OSError("short protected graphical step write")
        os.fsync(fd)
    finally:
        os.close(fd)


def install_next_native(*, previous_task, attest_native_owner,
                        attest_accepted_predecessor):
    """Protected single-step promotion. Does not start/schedule a compiler.

    Both attestations MUST be independently installed root-only capabilities,
    not caller-provided JSON, SSH/SSM task arguments or generic RPC callbacks.
    The native owner has to verify the producer's accepted generation and
    provenance, no competing writer, budget, boot and source before invoking.
    """
    if os.geteuid() != 0:
        raise PermissionError("root-only graphical generation owner required")
    if previous_task not in TASKS[:2]:
        _deny()
    from .fresh_budget_guard import _protected_root
    _protected_root(STORE)
    policy = validate_policy(_read_locked(POLICY))
    if attest_native_owner(policy) is not True:
        _deny()
    previous_path, previous_receipt_path = (
        (first.CATALOGUE, first.RECEIPT)
        if previous_task == TASKS[0] else FILES[previous_task])
    previous, observed_digest = task_catalogue.load(
        previous_path, require_root_owned=True)
    previous_receipt = _read_locked(previous_receipt_path)
    if previous_receipt.get("catalogue_sha256") != observed_digest:
        _deny()
    successor = TASKS[TASKS.index(previous_task) + 1]
    next_path, next_receipt_path = FILES[successor]
    # Preserve any partial write indefinitely. Never automatically delete,
    # replace, repair or attempt a second predecessor generation.
    if (next_path.exists() or next_path.is_symlink()
            or next_receipt_path.exists() or next_receipt_path.is_symlink()):
        _deny()
    verified = attest_accepted_predecessor(
        previous_task, observed_digest, previous["tasks"][previous_task][
            "arguments"]["selection"])
    candidate = resolve_successor(
        policy=policy, previous_task=previous_task,
        previous_catalogue=previous, previous_receipt=previous_receipt,
        accepted_generation=verified)
    _exclusive_write(next_path, candidate["catalogue_bytes"])
    saved, digest = task_catalogue.load(next_path, require_root_owned=True)
    if digest != candidate["catalogue_sha256"] or saved != candidate["catalogue"]:
        _deny()
    _exclusive_write(next_receipt_path, candidate["receipt_bytes"])
    receipt = _read_locked(next_receipt_path)
    if receipt != candidate["receipt"]:
        _deny()
    fd = os.open(STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return receipt


def load_installed_step(task, *, policy_sha256):
    """Read only immutable root-installed step; no generation supplied by caller.

    A supervisor may opt into ONE pinned chain-policy hash on startup.
    Successor catalogues can then be used for separate admitted GitHub
    requests without operator/manual generation-specific repins. This does
    not authorize any request, producer execution, or native worker launch.
    """
    if task not in TASKS or not _valid_hex(policy_sha256, EXACT_SHA):
        _deny()
    from .fresh_budget_guard import _protected_root
    _protected_root(STORE)
    policy = validate_policy(_read_locked(POLICY))
    if _hash(policy) != policy_sha256:
        _deny()

    catalogue, first_digest = task_catalogue.load(
        first.CATALOGUE, require_root_owned=True)
    receipt = _read_locked(first.RECEIPT)
    if first_digest != receipt.get("catalogue_sha256"):
        _deny()
    _previous(policy, TASKS[0], catalogue, receipt)
    if task == TASKS[0]:
        return catalogue, first_digest

    previous_digest = first_digest
    for successor in TASKS[1:]:
        path, receipt_path = FILES[successor]
        current, digest = task_catalogue.load(
            path, require_root_owned=True)
        installed = _read_locked(receipt_path)
        expected_keys = {
            "schema", "task", "catalogue_sha256",
            "selection_generation_id", "chain_policy_sha256",
            "previous_catalogue_sha256", "predecessor_evidence_sha256",
            "predecessor_generation_manifest_sha256",
            "predecessor_acceptance_receipt_sha256",
            "predecessor_request_id", "predecessor_pipeline_id",
            "source_revision", "monthly_pin_identity", "host_id",
            "installation_id", "lane", "lane_owner", "compiler_authorized",
            "status",
        }
        if (type(installed) is not dict or set(installed) != expected_keys
                or set(current["tasks"]) != {successor}
                or installed["schema"] != RECEIPT
                or installed["task"] != successor
                or installed["catalogue_sha256"] != digest
                or installed["previous_catalogue_sha256"] != previous_digest
                or installed["chain_policy_sha256"] != policy_sha256
                or installed["selection_generation_id"] !=
                    current["tasks"][successor]["arguments"]["selection"]
                or installed["source_revision"] != first.SOURCE
                or installed["monthly_pin_identity"] !=
                    policy["monthly_pin_identity"]
                or installed["host_id"] != policy["host_id"]
                or installed["installation_id"] != policy["installation_id"]
                or installed["lane"] != policy["lane"]
                or installed["lane_owner"] != policy["lane_owner"]
                or installed["status"] != "installed-not-compiler-admission"
                or installed["compiler_authorized"] is not False):
            _deny()
        for key in ("predecessor_evidence_sha256",
                    "predecessor_generation_manifest_sha256",
                    "predecessor_acceptance_receipt_sha256"):
            if not _valid_hex(installed[key], EXACT_SHA):
                _deny()
        for key in ("predecessor_request_id", "predecessor_pipeline_id"):
            if not _valid_hex(installed[key], EXACT_ID):
                _deny()
        spec = current["tasks"][successor]
        if (spec["source_revision"] != first.SOURCE
                or spec["source_repository"] != first.REPOSITORY
                or spec["monthly_pin_identity"] != policy["monthly_pin_identity"]
                or spec["monthly_pin_repository_path"] != first.PIN_PATH
                or spec["pin_date"] != first.PIN_DATE
                or spec["lane"] != policy["lane"]
                or spec["lane_owner"] != policy["lane_owner"]):
            _deny()
        if task == successor:
            return current, digest
        previous_digest = digest
    _deny()
