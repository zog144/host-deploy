"""Validate the typed compiler's completed immutable artifact evidence.

This is a structural receipt gate, not an independent filesystem attestation.
Never claim publication solely from a successful SSM exit.
"""
import re

ARTIFACT = "image-build-toolchain-artifact-v1"
EXECUTION = "image-build-toolchain-remote-execution-v1"
PROFILE = "self-hosted-c-cxx-toolchain-v1"
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
GENERATION = re.compile(r"[0-9a-f]{64}\Z")


class ToolchainReceiptError(ValueError):
    pass


def validate_final_result(result, specification_identity):
    if not isinstance(result, dict) or result.get("status") != "completed":
        raise ToolchainReceiptError("final compiler phase is not completed")
    if result.get("terminal_outcome") != "success" or result.get("uncertainty") is not False:
        raise ToolchainReceiptError("final compiler completion is not authoritative")
    artifacts = result.get("artifacts")
    execution = artifacts.get("toolchain_execution") if isinstance(artifacts, dict) else None
    if (not isinstance(execution, dict) or execution.get("contract") != EXECUTION
            or execution.get("phase") != "final-compiler"
            or not isinstance(execution.get("operation_id"), str)
            or not execution["operation_id"]):
        raise ToolchainReceiptError("missing bound final compiler execution")
    spec = execution.get("specification")
    if (not isinstance(spec, dict)
            or spec.get("contract") != "image-build-toolchain-specification-v1"
            or spec.get("identity") != specification_identity
            or not SHA.fullmatch(specification_identity)
            or spec.get("profile") != PROFILE):
        raise ToolchainReceiptError("toolchain specification identity differs")
    outputs = execution.get("outputs")
    if not isinstance(outputs, dict):
        raise ToolchainReceiptError("toolchain generation output unavailable")
    generation = outputs.get("generation")
    if not isinstance(generation, str) or not GENERATION.fullmatch(generation):
        raise ToolchainReceiptError("invalid immutable toolchain generation")
    artifact = outputs.get("toolchain_artifact")
    if (not isinstance(artifact, dict)
            or set(artifact) != {"contract", "profile", "specification",
                                "verification", "activation"}
            or artifact["contract"] != ARTIFACT
            or artifact["profile"] != PROFILE
            or artifact["specification"] != specification_identity
            or artifact["activation"] != "toolchain-active"
            or not isinstance(artifact["verification"], str)
            or not SHA.fullmatch(artifact["verification"])):
        raise ToolchainReceiptError("final toolchain artifact contract is incomplete")
    if result.get("selected_generation") != generation:
        raise ToolchainReceiptError("selected generation differs from published generation")
    return {"contract": ARTIFACT, "generation": generation,
            "specification": specification_identity,
            "verification": artifact["verification"],
            "operation_id": execution["operation_id"]}
