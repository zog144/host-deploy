"""Selected shared-Host model: route and limited GitHub Actions dispatch, not root isolation.

All evidence here is source-only. Effective AWS IAM belongs to native Work.
"""
import json
from pathlib import Path
import inspect

from zog.host_deploy.gateway import github_dispatch
from zog.host_deploy.gateway import generic_pipeline

ROOT = Path(__file__).resolve().parents[1]


def policy():
    return json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())


def test_admin_is_trusted_but_normal_graphical_path_uses_owner():
    m = policy()
    assert m["schema"] == "zog-graphical-shared-host-trust-model-v1"
    assert m["root_admin_inaccessibility_proof_required"] is False
    assert m["administrator_can_access_local_ssm_authority"] is True
    assert m["normal_owner_path_bypass_permitted"] is False
    assert m["owner_claims_required"] is True
    assert m["revocation_required"] is True
    assert m["original_s3_history_and_genesis_required"] is True
    selected = inspect.getsource(generic_pipeline._selected_protected_owner_sender)
    assert "No automatic fallback to Host.submit_command" in selected
    assert "protected" in selected.lower()


def test_oidc_source_only_dispatches_to_sqs_not_ssm():
    m = policy()
    assert m["actions_oidc_permissions"] == "sqs_dispatch_only"
    dispatch = inspect.getsource(github_dispatch)
    assert 'boto3.client("sqs"' in dispatch
    assert ".send_message(" in dispatch
    assert 'boto3.client("ssm"' not in dispatch
    assert "submit_command(" not in dispatch
    workflow=(ROOT/".github/workflows/gateway-issue-dispatch.yml").read_text()
    assert "id-token: write" in workflow
    assert "role-to-assume: ${{ vars.ZOG_GATEWAY_ROLE_ARN }}" in workflow
    assert "sqs:SendMessage" not in workflow  # AWS permission is externally bound, not granted by workflow.
    assert "ssm:SendCommand" not in workflow
    assert "configure-aws-credentials@" in workflow
    assert "persist-credentials: false" in workflow
    assert m["synthetic_source_test_is_native_acceptance"] is False


def test_graphical_source_contains_selected_owner_fence_not_admin_iam_claim():
    src = inspect.getsource(generic_pipeline)
    assert "_selected_protected_owner_preflight" in src
    assert "_selected_protected_owner_sender" in src
    assert "No gateway-owned direct SendCommand fallback" in src
    assert policy()["gateway_service_direct_ssm_denial"] == (
        "optional_defense_in_depth_not_admin_isolation")
