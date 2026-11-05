"""Read-only canonical compiler base evidence and typed retained-image binding.

A producer observation is NOT a native approval. Both the observed immutable
generation and an independent installed acceptance must agree exactly.
Subsequent graphical outputs are kind=image and require distinct predecessor
evidence; no blanket kind=toolchain rule applies to retained images.
"""
import hashlib
import json
import re

OBSERVATION_SCHEMA = "image-build-first-fonts-base-observation-v1"
ACCEPTANCE_SCHEMA = "image-build-self-hosted-base-acceptance-v1"
OUTPUT_SCHEMA = "image-build-verified-graphical-predecessor-v1"
SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
PIN = "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
REPOSITORY = "zog144/image-build"
TASK = "graphics-fonts-image-v1"
H64 = re.compile(r"[a-f0-9]{64}\Z")
H40 = re.compile(r"[a-f0-9]{40}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
BASE_FIELDS = frozenset((
    "schema", "task", "source_repository", "source_revision",
    "monthly_pin_identity", "host_id", "project_id", "base_generation_id",
    "base_generation_kind", "base_generation_stage",
    "base_manifest_sha256", "base_inventory_sha256",
    "base_generation_record_sha256", "status", "catalogue_installed",
    "native_compiler_authorized",
))
# Native acceptance is a separate protected capability, not an extension of
# image-build's observational record. It is never derived from these bytes.
NATIVE_FIELDS = frozenset((
    "host_id", "installation_id", "lane", "project_id",
    "base_generation_id", "base_manifest_sha256",
    "base_inventory_sha256", "base_generation_record_sha256",
    "accepted_base_receipt_sha256", "source_revision",
    "monthly_pin_identity", "status",
))

class BaseAcceptanceDenied(ValueError):
    pass

def deny():
    raise BaseAcceptanceDenied("compiler base or retained image lacks independent native acceptance")

def checked_base(observation, native, *, approval, lane):
    """Bind independently supplied native acceptance to PR18 producer record.

    The caller MUST ensure native came from an immutable independently
    installed trusted capability. A syntactically matching forged dictionary
    is never authorization to start a task.
    """
    if (type(observation) is not dict or set(observation) != BASE_FIELDS
            or observation["schema"] != OBSERVATION_SCHEMA
            or observation["task"] != TASK
            or observation["source_repository"] != REPOSITORY
            or observation["source_revision"] != SOURCE
            or observation["monthly_pin_identity"] != PIN
            or observation["base_generation_kind"] != "toolchain"
            or type(observation["base_generation_stage"]) is not int
            or observation["base_generation_stage"] != 2
            or observation["status"] != "canonical-base-observed-not-native-admission"
            or observation["catalogue_installed"] is not False
            or observation["native_compiler_authorized"] is not False
            or not all(type(observation[k]) is str and observation[k] for k in
                       ("host_id", "project_id"))
            or not isinstance(observation["base_generation_id"], str)
            or not H64.fullmatch(observation["base_generation_id"])
            or any(type(observation[k]) is not str or
                   SHA.fullmatch(observation[k]) is None for k in
                   ("base_manifest_sha256", "base_inventory_sha256",
                    "base_generation_record_sha256"))
            or type(native) is not dict or set(native) != NATIVE_FIELDS
            or native["status"] != "independently-native-accepted"
            or not isinstance(approval, dict) or not isinstance(lane, dict)):
        deny()
    for key in ("host_id", "project_id", "base_generation_id",
                "base_manifest_sha256", "base_inventory_sha256",
                "base_generation_record_sha256", "source_revision",
                "monthly_pin_identity"):
        if native[key] != observation[key]:
            deny()
    if (native["host_id"] != approval["host_id"]
            or native["installation_id"] != approval["installation_id"]
            or native["lane"] != approval["lane"]
            or native["project_id"] != lane["provenance_project_id"]
            or native["base_generation_id"] != approval["accepted_base_generation_id"]
            or native["accepted_base_receipt_sha256"] !=
               approval["accepted_base_receipt_sha256"]
            or native["source_revision"] != SOURCE
            or native["monthly_pin_identity"] != PIN
            or not isinstance(native["accepted_base_receipt_sha256"], str)
            or SHA.fullmatch(native["accepted_base_receipt_sha256"]) is None):
        deny()
    return {"generation_id": observation["base_generation_id"],
            "kind": "toolchain", "stage": 2,
            "manifest_sha256": observation["base_manifest_sha256"],
            "inventory_sha256": observation["base_inventory_sha256"],
            "generation_record_sha256": observation["base_generation_record_sha256"],
            "accepted_receipt_sha256": native["accepted_base_receipt_sha256"]}


def retained_generation(*, task, generation_id, kind, evidence,
                        approved_input_generation_id):
    """Check selected kind without turning predecessor success into task grant.

    First Fonts must use the independently accepted stage-two compiler.
    A later image batch may retain an accepted kind=image predecessor only
    when the dedicated graphical predecessor attester supplies its original
    accepted provenance, and the approved input ID matches. It does not
    authorize a task, dependency edge, source pin, worker or new generation.
    """
    if (type(generation_id) is not str or H64.fullmatch(generation_id) is None
            or generation_id != approved_input_generation_id
            or type(evidence) is not dict):
        deny()
    if task == TASK:
        if (kind != "toolchain" or
                evidence.get("kind") != "toolchain" or
                evidence.get("stage") != 2 or
                evidence.get("generation_id") != generation_id or
                not isinstance(evidence.get("accepted_receipt_sha256"), str) or
                SHA.fullmatch(evidence["accepted_receipt_sha256"]) is None):
            deny()
    else:
        # Native graphical generation attester validates original request,
        # accepted pipeline, source/Host/STATE, dependencies and receipts.
        if (kind != "image" or evidence.get("schema") != OUTPUT_SCHEMA
                or evidence.get("output_kind") != "image"
                or evidence.get("output_generation_id") != generation_id
                or evidence.get("status") != "accepted"
                or evidence.get("terminal_outcome") != "success"
                or evidence.get("uncertainty") is not False
                or evidence.get("missing_evidence_count") != 0):
            deny()
        for name in ("generation_manifest_sha256",
                     "acceptance_receipt_sha256", "producer_receipt_sha256"):
            if (type(evidence.get(name)) is not str or
                    SHA.fullmatch(evidence[name]) is None):
                deny()
    return generation_id
