"""Public dispatcher authorization remains separate from credential-free source CI."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CHECKOUT = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP_PYTHON = "ece7cb06caefa5fff74198d8649806c4678c61a1"


def test_gateway_submission_requires_prior_validation_and_explicit_configuration():
    text = (WORKFLOWS / "gateway-issue-dispatch.yml").read_text()
    validate, submit = text.split("  submit:")
    assert "issues:" in validate and "types: [opened]" in validate
    assert "id-token:" not in validate
    assert "needs: validate" in submit
    assert "vars.ZOG_GATEWAY_SUBMIT_ENABLED == 'true'" in submit
    assert "id-token: write" in submit
    assert "github.run_attempt == 1" in validate and "github.run_attempt == 1" in submit
    assert "github_configuration --event" in validate and "github_configuration --event" in submit
    assert submit.index("github_configuration --event") < submit.index("aws-actions/configure-aws-credentials@")
    assert "fromJSON(vars.ZOG_GATEWAY_AUTHORIZED_ACTORS || '[]')" in validate
    assert "secrets." not in text
    assert "arn:aws:" not in text and "amazonaws.com" not in text
    assert "${{ github.event.issue.body }}" not in text
    assert "pull_request" not in text
    assert "ref: ${{ vars.ZOG_GATEWAY_DISPATCH_REVISION }}" in text
    assert "configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd" in text


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
    for filename in ("pytest.yml", "certificate-renewal-contract.yml", "gateway-issue-dispatch.yml"):
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
