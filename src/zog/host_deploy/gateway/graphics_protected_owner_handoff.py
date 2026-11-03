"""Source-only Host-deploy -> independent root-control graphical send owner handoff.

Builds one exact original operation claim from PR18's frozen stage binding,
without sending SSM or inventing root/Host/installation/STATE authority.
This is intentionally NOT wired to generic_pipeline.advance until protected
native root-control owner and generation-selection receipts are installed.
"""
import hashlib
import json
import re

from . import graphics_operation_send_intent as gateway_intent

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ProtectedSendOwnerHold(ValueError):
    pass


def _hold():
    raise ProtectedSendOwnerHold("independently protected graphical send owner not installed or source selection uncertain")


def _hash(value):
    return hashlib.sha256(gateway_intent._canonical(value)).hexdigest()


def _sha256_identity(value):
    if type(value) is not str or not value.startswith("sha256:") or not HEX64.fullmatch(value[7:]):
        _hold()
    return value[7:]


def original_operation_claim(binding, request_id, step, *,
                             protected_generation_sha256):
    """Construct the immutable owner claim; *never* grant send authority.

    protected_generation_sha256 must come from an independently installed
    owner/source-generation provenance witness, not gateway journal data.
    An absent receipt cannot be replaced with a self-consistent local hash.
    """
    if type(protected_generation_sha256) is not str or not HEX64.fullmatch(protected_generation_sha256):
        _hold()
    selected = gateway_intent._expected(binding, request_id, step)
    source = selected["source"]
    if (type(source) is not dict or set(source) != {"repository","revision"}
            or source["repository"] != "zog144/image-build"
            or type(source["revision"]) is not str
            or not HEX40.fullmatch(source["revision"])):
        _hold()
    if (type(binding.get("target")) is not dict
            or set(binding["target"]) != {"instance_id","region"}
            or not binding["target"]["instance_id"]
            or not binding["target"]["region"]
            or type(binding.get("lane")) is not str
            or not binding["lane"]):
        _hold()
    if (type(step.get("request")) is not dict
            or step["request"].get("operation_id") != step["operation_id"]
            or step["request"].get("operation") !=
                {"capabilities":"capabilities.inspect","snapshot":"recipes.snapshot",
                 "submit":"pipeline.submit","inspect":"pipeline.inspect"}[step["name"]]
            or step["request"].get("source") != source
            or _hash(step["request"]) != selected["remote_request_sha256"]):
        _hold()
    operation = step["request"]["operation"]
    return {
        "request_id": request_id,
        "operation_id": selected["operation_id"],
        "stage": selected["stage"],
        "ordinal": selected["ordinal"],
        "remote_request_sha256": selected["remote_request_sha256"],
        "binding_sha256": selected["binding_sha256"],
        "task_catalogue_sha256": _sha256_identity(selected["task_catalogue_sha256"]),
        "source_revision": source["revision"],
        "source_generation": protected_generation_sha256,
        "lane": selected["lane"],
        "target": gateway_intent._canonical(selected["target"]).decode("ascii"),
        "monthly_pin_identity": _sha256_identity(selected["monthly_pin_identity"]),
        "operation": operation,
    }


def inspect_only_source_boundary(binding, request_id, step, *,
                                 protected_generation_sha256):
    """Preflight shape only; never a proof the external owner accepted a send."""
    return original_operation_claim(binding, request_id, step,
                                    protected_generation_sha256=protected_generation_sha256)

# No code in this module calls SendCommand, creates root claims, or issues
# operator approvals. The protected native gateway admission operation must
# select the signed root-control owner with authenticated exact Host/
# installation/STATE and commit an irrevocable claim BEFORE any SSM call.
