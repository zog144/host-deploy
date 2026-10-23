"""Acceptance boundary for the immutable toolchain artifact receipt."""
import copy

import pytest

from zog.host_deploy.gateway.toolchain_receipt import (
    ToolchainReceiptError, validate_final_result,
)

SPEC = "sha256:" + "a" * 64
VERIFY = "sha256:" + "b" * 64
GEN = "c" * 64


def final_result():
    return {
        "status": "completed", "terminal_outcome": "success", "uncertainty": False,
        "selected_generation": GEN,
        "artifacts": {"toolchain_execution": {
            "contract": "image-build-toolchain-remote-execution-v1",
            "phase": "final-compiler", "operation_id": "d" * 32,
            "specification": {
                "contract": "image-build-toolchain-specification-v1",
                "identity": SPEC, "profile": "self-hosted-c-cxx-toolchain-v1",
            },
            "outputs": {
                "generation": GEN,
                "toolchain_artifact": {
                    "contract": "image-build-toolchain-artifact-v1",
                    "profile": "self-hosted-c-cxx-toolchain-v1",
                    "specification": SPEC,
                    "verification": VERIFY,
                    "activation": "toolchain-active",
                },
            },
        }},
    }


def test_completed_final_compiler_receipt():
    evidence = validate_final_result(final_result(), SPEC)
    assert evidence["generation"] == GEN
    assert evidence["verification"] == VERIFY


@pytest.mark.parametrize("mutation", [
    ("status", "pending"),
    ("selected_generation", "0" * 64),
    ("terminal_outcome", "failure"),
    ("uncertainty", True),
])
def test_nonfinal_receipt_rejected(mutation):
    result = final_result()
    result[mutation[0]] = mutation[1]
    with pytest.raises(ToolchainReceiptError):
        validate_final_result(result, SPEC)


def test_contract_and_generation_mismatch_rejected():
    for field, value in [
        ("contract", "unreviewed-artifact"),
        ("verification", "bogus"),
        ("activation", "inactive"),
        ("specification", "sha256:" + "f" * 64),
    ]:
        r = final_result()
        r["artifacts"]["toolchain_execution"]["outputs"]["toolchain_artifact"][field] = value
        with pytest.raises(ToolchainReceiptError):
            validate_final_result(r, SPEC)
    assert final_result() == copy.deepcopy(final_result())
