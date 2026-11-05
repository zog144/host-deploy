"""Independently pinned signed compiler-base acceptance consumer (PR18 v2).

A valid signature is NOT a task/SSM grant. The inputs must be read by an
independently installed native owner, not from GitHub/SQS request JSON.
"""
import base64
import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ACCEPTANCE_SCHEMA = "image-build-compiler-base-acceptance-v1"
BINDING_SCHEMA = "image-build-compiler-base-binding-v1"
ISSUER_SCHEMA = "zog-protected-compiler-base-issuer-v1"
OUTPUT_SCHEMA = "image-build-verified-graphical-predecessor-v1"
DOMAIN = b"ZOG_IMAGE_BUILD_COMPILER_BASE_ACCEPTANCE_V1\x00"
SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
PIN = "sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
REPOSITORY = "zog144/image-build"
TASK = "graphics-fonts-image-v1"
H64 = re.compile(r"[a-f0-9]{64}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
ABI = frozenset(("x86_64-linux-gnu", "x86_64-pc-linux-gnu",
                  "x86_64-unknown-linux-gnu", "x86_64-zog-linux-gnu"))
ROLES = ("compiler", "linker", "assembler", "libc_header", "abi_header", "crt", "libc")
CLAIM_FIELDS = frozenset((
    "schema", "status", "generation_id", "generation_kind",
    "generation_manifest_sha256", "generation_inventory_sha256",
    "generation_record_sha256", "host_id", "installation_id",
    "state_volume_id", "project_id", "execution_environment_sha256",
    "target_abi", "installed_paths", "historical_provenance",
    "native_probe", "required_probe_command_sha256",
))
BINDING_FIELDS = frozenset((
    "schema", "generation_id", "generation_kind",
    "generation_manifest_sha256", "generation_inventory_sha256",
    "generation_record_sha256", "host_id", "installation_id",
    "state_volume_id", "project_id", "execution_environment_sha256",
    "target_abi", "compiler_files_sha256", "native_probe_sha256",
    "historical_provenance", "acceptance_receipt_sha256", "status",
))
ISSUER_FIELDS = frozenset((
    "schema", "host_id", "installation_id", "state_volume_id", "project_id",
    "key_id", "ed25519_public_key", "receipt_directory",
    "execution_environment_sha256",
))

class BaseAcceptanceDenied(ValueError):
    pass

def deny():
    raise BaseAcceptanceDenied("compiler base lacks independently pinned signed native acceptance")

def canonical(row):
    return json.dumps(row,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def digest(raw):
    return "sha256:"+hashlib.sha256(raw).hexdigest()

def match(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None

def _unique(pairs):
    out={}
    for key,value in pairs:
        if key in out: deny()
        out[key]=value
    return out

def valid_history(row,kind):
    if type(row) is not dict or set(row)!={
            "status","missing","retained_evidence_sha256"}:
        return False
    if kind=="toolchain":
        return row=={"status":"complete","missing":[],
                     "retained_evidence_sha256":None}
    return (row["status"]=="historical-gap-declared"
            and type(row["missing"]) is list
            and 1<=len(row["missing"])<=32
            and all(type(x) is str and 0<len(x)<256 for x in row["missing"])
            and match(row["retained_evidence_sha256"],SHA))

def checked_base(receipt_bytes, issuer_policy, producer_binding, *,
                 approval, lane):
    """Consume exact signed receipt bytes and independently verified producer binding.

    The installed issuer policy and producer binding MUST originate from
    protected native readers, never from a gateway request or mutable STATE.
    Native Work must attest policy selection, issuer revocation and generation
    byte/probe verification independently before this pure consumer is used.
    """
    if (type(receipt_bytes) is not bytes or not 0<len(receipt_bytes)<=65536
            or type(issuer_policy) is not dict
            or set(issuer_policy)!=ISSUER_FIELDS
            or issuer_policy["schema"]!=ISSUER_SCHEMA
            or not match(issuer_policy["ed25519_public_key"],H64)
            or not match(issuer_policy["execution_environment_sha256"],SHA)
            or type(producer_binding) is not dict
            or set(producer_binding)!=BINDING_FIELDS
            or producer_binding["schema"]!=BINDING_SCHEMA
            or producer_binding["status"]!=
                "independent-compiler-capability-observed-not-job-authorization"
            or type(approval) is not dict or type(lane) is not dict):
        deny()
    try:
        envelope=json.loads(receipt_bytes,object_pairs_hook=_unique,
                            parse_constant=lambda _:deny())
        if (type(envelope) is not dict or
                set(envelope)!={"schema","key_id","claim","signature"}
                or canonical(envelope)!=receipt_bytes
                or envelope["schema"]!=ACCEPTANCE_SCHEMA
                or envelope["key_id"]!=issuer_policy["key_id"]):
            deny()
        claim=envelope["claim"]
        if (type(claim) is not dict or set(claim)!=CLAIM_FIELDS
                or claim["schema"]!=ACCEPTANCE_SCHEMA
                or claim["status"]!="independently-accepted-for-compiler-use"
                or not match(envelope["signature"],
                             re.compile(r"[A-Za-z0-9+/]{86}==\Z"))):
            deny()
        sig=base64.b64decode(envelope["signature"],validate=True)
        if len(sig)!=64: deny()
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(issuer_policy["ed25519_public_key"])
        ).verify(sig,DOMAIN+canonical(claim))
        if (digest(receipt_bytes)!=approval["accepted_base_receipt_sha256"]
                or producer_binding["acceptance_receipt_sha256"]!=
                   digest(receipt_bytes)
                or claim["generation_id"]!=approval["accepted_base_generation_id"]
                or not match(claim["generation_id"],H64)
                or claim["generation_kind"] not in ("toolchain","image")
                or not valid_history(claim["historical_provenance"],
                                     claim["generation_kind"])
                or claim["target_abi"] not in ABI
                or not match(claim["generation_manifest_sha256"],SHA)
                or not match(claim["generation_inventory_sha256"],SHA)
                or (claim["generation_record_sha256"] is not None and
                    not match(claim["generation_record_sha256"],SHA))
                or (claim["generation_kind"]=="toolchain" and
                    claim["generation_record_sha256"] is None)
                or type(claim["installed_paths"]) is not dict
                or set(claim["installed_paths"])!=set(ROLES)
                or not match(claim["required_probe_command_sha256"],SHA)):
            deny()
        for role in ROLES:
            item=claim["installed_paths"][role]
            if (type(item) is not dict or set(item)!={"path","sha256"}
                    or type(item["path"]) is not str
                    or not item["path"].startswith("usr/")
                    or ".." in item["path"].split("/")
                    or not match(item["sha256"],SHA)):
                deny()
        for name in ("host_id","installation_id","state_volume_id",
                     "project_id","execution_environment_sha256"):
            if (claim[name]!=issuer_policy[name]
                    or producer_binding[name]!=claim[name]):
                deny()
        if (claim["host_id"]!=approval["host_id"]
                or claim["installation_id"]!=approval["installation_id"]
                or claim["project_id"]!=lane["provenance_project_id"]
                or claim["host_id"]!=lane["provenance_host_id"]):
            deny()
        mapping={
            "generation_id":"generation_id",
            "generation_kind":"generation_kind",
            "generation_manifest_sha256":"generation_manifest_sha256",
            "generation_inventory_sha256":"generation_inventory_sha256",
            "generation_record_sha256":"generation_record_sha256",
            "target_abi":"target_abi",
            "execution_environment_sha256":"execution_environment_sha256",
            "historical_provenance":"historical_provenance",
        }
        if any(producer_binding[k]!=claim[v] for k,v in mapping.items()):
            deny()
        if (producer_binding["compiler_files_sha256"]!=
                digest(canonical(claim["installed_paths"]))
                or producer_binding["native_probe_sha256"]!=
                digest(canonical(claim["native_probe"]))):
            deny()
        return {
            "schema":BINDING_SCHEMA,
            "generation_id":claim["generation_id"],
            "kind":claim["generation_kind"],
            "manifest_sha256":claim["generation_manifest_sha256"],
            "inventory_sha256":claim["generation_inventory_sha256"],
            "generation_record_sha256":claim["generation_record_sha256"],
            "accepted_receipt_sha256":digest(receipt_bytes),
            "state_volume_id":claim["state_volume_id"],
            "execution_environment_sha256":claim["execution_environment_sha256"],
            "target_abi":claim["target_abi"],
            "compiler_files_sha256":producer_binding["compiler_files_sha256"],
            "native_probe_sha256":producer_binding["native_probe_sha256"],
            "historical_provenance":claim["historical_provenance"],
            "status":producer_binding["status"],
        }
    except (ValueError,TypeError,KeyError,UnicodeError,InvalidSignature,
            OverflowError,base64.binascii.Error):
        deny()


def retained_generation(*, task, generation_id, kind, evidence,
                        approved_input_generation_id):
    """Check selected kind without turning predecessor success into task grant.

    First Fonts retains the signed original compiler generation kind (toolchain
    or image); a later batch may retain an accepted kind=image predecessor only
    when the dedicated graphical predecessor attester supplies its original
    accepted provenance, and the approved input ID matches. It does not
    authorize a task, dependency edge, source pin, worker or new generation.
    """
    if (type(generation_id) is not str or H64.fullmatch(generation_id) is None
            or generation_id != approved_input_generation_id
            or type(evidence) is not dict):
        deny()
    if task == TASK:
        if (kind not in ("toolchain", "image") or
                evidence.get("schema") != BINDING_SCHEMA or
                evidence.get("kind") != kind or
                evidence.get("generation_id") != generation_id or
                evidence.get("status") !=
                    "independent-compiler-capability-observed-not-job-authorization" or
                not match(evidence.get("accepted_receipt_sha256"), SHA) or
                (kind == "toolchain" and
                 evidence.get("historical_provenance") !=
                    {"status": "complete", "missing": [],
                     "retained_evidence_sha256": None}) or
                (kind == "image" and
                 not valid_history(evidence.get("historical_provenance"), kind))):
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
