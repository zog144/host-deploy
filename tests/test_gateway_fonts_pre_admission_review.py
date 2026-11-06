"""Source-only first Fonts pre-admission audit of immutable producer and GitHub queue.

Runs against separately checked out exact Git refs. It does not read native
STATE, AWS IAM, real S3 receipts, accepted rights, or authorize submission.
"""
import ast
import json
from pathlib import Path
import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as fonts
from zog.host_deploy.gateway import task_catalogue

SOURCE="1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
PR17="324b1469cb490a571d428cadd9ce72bbec5507b4"
READER="bf0b37fea1767bf7ab02ca2d1c5d1a0d5487d4b6"
CURRENT_PR26_REVIEW="02db124609b92396ff89fa628d8ddc9383e05f4b"
TARGETS=("libpng-final","freetype-final","fontconfig-final")
ENTRIES=(("fontconfig-final","fontconfig","fontconfig/stages/final"),
         ("freetype-final","freetype","freetype/stages/final"),
         ("libpng-final","libpng","libpng/stages/final"))
PACKAGES={"libpng":("1.6.58","28eb403f51f0f7405249132cecfe82ea5c0ef97f1b32c5a65828814ae0d34775"),
          "freetype":("2.14.3","36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f"),
          "fontconfig":("2.18.3","4f7b554a38cdf78c033f666c8871f3749e14a094f65a07f630c91ed0b43d35e3")}


def root():
    result=Path(__file__).resolve().parents[1]
    assert (result/"src/zog/host_deploy/gateway/task_catalogue.py").is_file()
    return result


def prepared():
    return root()/"dependencies/image-build-prepared"


def original():
    return root()/"dependencies/image-build"


def literal(path):
    return ast.literal_eval(path.read_text())


def test_exact_fonts_target_order_and_one_task_catalogue_candidate():
    reviewed=task_catalogue.REVIEWED_IMAGE_TASKS[fonts.TASK]
    assert reviewed=={"entries":ENTRIES,"targets":TARGETS}
    plan=literal(original()/"project/bootstrap/graphics-fonts.py")
    assert plan["schema"]==1 and plan["architecture"]=="x86_64"
    assert [(s["id"],s["project"],s["recipe"]) for s in plan["stages"]]==[
        ENTRIES[2],ENTRIES[1],ENTRIES[0]]
    assert plan["targets"]==list(TARGETS)
    assert fonts.SOURCE==SOURCE and fonts.READER_SOURCE==READER
    assert fonts.PIN_PATH=="project/pins/2026-10-01/commit-pin.py"
    assert fonts.PIN_SHA256=="d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"


@pytest.mark.parametrize("package", sorted(PACKAGES))
def test_exact_archive_license_notice_evidence_is_declared_not_release_clearance(package):
    version,digest=PACKAGES[package]
    base=original()/"project/package"/package
    source=literal(base/"upstream.py")
    rights=literal(base/"license.py")
    recipe=literal(base/"recipe-plan.py")
    assert source["version"]==version and source["sha256"]==digest
    assert source["verification_status"]=="downloaded-exact-release-sha256"
    assert rights["package"]==package and rights["version"]==version
    assert rights["source"]["sha256"]==digest
    assert rights["status"]=="declared", "a declaration is not a public release grant"
    assert rights["patches"]==[]
    assert rights["evidence"] and all(
        len(row["sha256"])==64 and row["source_sha256"]==digest
        for row in rights["evidence"])
    assert rights["components"] and any(
        row["status"]=="unresolved" for row in rights["components"])
    assert recipe["status"]=="authored" and recipe["stages"]==["final"]


def test_pr17_legacy_preparation_is_held_not_reinterpreted_as_current_approval():
    record=json.loads((prepared()/"project/graphics-first-workspace/first-fonts-github-preparation-v1.json").read_text())
    assert record["schema"]=="zog-fonts-github-trigger-preparation-v1"
    assert record["status"]=="PREPARED_NOT_SUBMITTABLE"
    assert record["task"]==fonts.TASK
    assert record["producer"]["source_revision"]==SOURCE
    assert record["submission"]=={
        "enabled":False, "auto_retry":False, "manual_direct_ssm_allowed":False,
        "github_issue_created":False, "submitted_sqs_message":False,
        "acceptance_claimed":False,
    }
    assert record["budget"]=={
        "work_bytes":30*1024**3,"external_bytes":2*1024**3,
        "total_bytes":32*1024**3,"execution_limit_seconds":21600,
    }
    assert all(x is None for x in record["native_gates"].values())
    assert all(x is None for x in (
        record["gateway"]["request_id"],record["gateway"]["issue_number"],
        record["gateway"]["queue_receipt"],
        record["task_catalogue"]["selected_base_generation"],
        record["task_catalogue"]["installed_catalogue_sha256"]))
    # This earlier source-only audit explicitly predates the signed dual-kind
    # compiler acceptance and current Task C owner; it cannot certify PR7 HEAD.
    assert record["reviewer"]["host_deploy_fonts_catalogue_revision"]!=CURRENT_PR26_REVIEW
    assert record["reviewer"]["host_deploy_fonts_catalogue_revision"]!="c01d7eb2ccc3de6f11252801f606a03cb84cad1f"
    assert record["native_gates"]["accepted_self_hosted_toolchain_generation"] is None


def test_oidc_single_attempt_fifo_contract_is_separate_from_protected_owner():
    workflow=(root()/".github/workflows/gateway-issue-dispatch.yml").read_text()
    code=(root()/"src/zog/host_deploy/gateway/github_dispatch.py").read_text()
    config=(root()/"src/zog/host_deploy/gateway/github_configuration.py").read_text()
    # Only GitHub issue-opened event triggers once; AWS credentials are OIDC,
    # not produced by a GitHub issue or the gateway execution owner.
    for token in ("types: [opened]","github.run_attempt == 1",
                  "vars.ZOG_GATEWAY_SUBMIT_ENABLED == 'true'",
                  "id-token: write","role-to-assume:",
                  "ZOG_GATEWAY_DISPATCH_REVISION","github_dispatch submit"):
        assert token in workflow
    for token in ('MessageGroupId=request["workspace_id"]',
                  'MessageDeduplicationId=request["request_id"]',
                  '"total_max_attempts": 1', 'event.get("action") != "opened"'):
        assert token in code
    for token in ("GITHUB_TRIGGERING_ACTOR", "AUTHORIZED_ACTORS",
                  "ALLOWED_OPERATIONS","GITHUB_RUN_ATTEMPT"):
        assert token in config
    # No SSM credentials or direct SendCommand in OIDC issue workflow.
    assert "ssm:SendCommand" not in workflow
    assert "aws ssm send-command" not in workflow
    assert "send_command(" not in code


def test_owner_route_remains_separately_protected_and_no_native_claim():
    # PR7 catalogues never grant or execute the actual operation.
    owner=(root()/"src/zog/host_deploy/gateway/graphics_catalogue_owner.py").read_text()
    route=(root()/"src/zog/host_deploy/gateway/graphics_base_acceptance.py").read_text()
    assert '"compiler_authorized": False' in owner
    assert "attest_installed_source(READER_SOURCE)" in owner
    assert 'kind not in ("toolchain", "image")' not in owner
    assert 'claim_once(' not in owner and "send_command(" not in owner
    assert "image-build-compiler-base-acceptance-v1" in route
    assert "historical-gap-declared" in route
