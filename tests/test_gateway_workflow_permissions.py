"""Public migration: GitHub workflows must never dispatch AWS from issues."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CHECKOUT = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP_PYTHON = "ece7cb06caefa5fff74198d8649806c4678c61a1"


def test_gateway_workflow_is_inert_regardless_of_old_variables():
    text = (WORKFLOWS / "gateway-issue-dispatch.yml").read_text()
    # This file is deliberately a manual, nonprivileged explanatory workflow;
    # the gateway's strict parser remains source-only until owner activation.
    assert re.search(r"(?m)^on:\s*$", text)
    assert re.search(r"(?m)^  workflow_dispatch:\s*$", text)
    assert not re.search(r"(?m)^\s*issues\s*:", text)
    assert not re.search(r"(?m)^\s*id-token\s*:", text)
    assert not re.search(r"(?m)^  submit\s*:", text)
    assert "configure-aws-credentials" not in text
    assert "github_dispatch submit" not in text
    assert "ZOG_GATEWAY_SUBMIT_ENABLED" not in text
    assert "secrets." not in text
    assert "sqs:SendMessage" not in text


def test_source_ci_is_credential_free_and_does_not_install_private_pins():
    text = (WORKFLOWS / "pytest.yml").read_text()
    for forbidden in ("ZOG_PRIVATE_REPOSITORY_TOKEN", "sudo ", "id-token:",
                      "secrets.", "aws-actions/",
                      "steps.pins", "repository: zog144/host-"):
        assert forbidden not in text
    assert "persist-credentials: false" in text
    assert "tests/test_gateway_workflow_permissions.py" in text
    assert "pip wheel" in text
    assert "timeout-minutes:" in text
    assert "contents: read" in text


def test_node24_actions_are_pinned_to_reviewed_immutable_shas():
    for filename in ("pytest.yml", "certificate-renewal-contract.yml"):
        text = (WORKFLOWS / filename).read_text()
        checkout = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*actions/checkout@([^\s#]+)", text)
        python = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*actions/setup-python@([^\s#]+)", text)
        assert checkout and all(ref == CHECKOUT for ref in checkout)
        assert python and all(ref == SETUP_PYTHON for ref in python)
        assert "persist-credentials: false" in text


def test_public_source_ci_never_triggers_gateway_dispatch():
    text = (WORKFLOWS / "pytest.yml").read_text()
    assert "github_dispatch submit" not in text
    assert "github_dispatch prepare" not in text
    assert "configure-aws-credentials" not in text
    assert "sqs:" not in text
