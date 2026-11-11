"""Source-only first Fonts pre-admission audit of immutable producer and GitHub queue.

Runs against separately checked out exact Git refs. It does not read native
STATE, AWS IAM, real SSM results, accepted rights, or authorize submission.
"""
import ast
import json
from pathlib import Path
import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as fonts
from zog.host_deploy.gateway import task_catalogue

SOURCE="1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
PR17="324b1469cb490a571d428cadd9ce72bbec5507b4"
READER="1616f192ef9d8964a8f37f32a86c69c0242a213c"
SELECTED_TASK_C="0fd2db17698423d4cd30b296fc9f78e83cee145c"
LEGACY_PR17_FONTS="78a772a6542dba660ddaa4223b28593c0251f810"
LEGACY_PR17_TASK_C="c46c6b5819b1f4496de1b860aa2785812244493e"
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


def test_fonts_catalogue_review_is_not_github_request_authority():
    # PR17's moving head independently pins the selected *PR7* exact source.
    # PR7 must not pin PR17's moving head back, which creates a circular
    # Git commit dependency. This check uses the actual local catalogue.
    assert fonts.TASK=="graphics-fonts-image-v1"
    assert fonts.SOURCE==SOURCE
    assert fonts.READER_SOURCE==READER
    owner=(root()/"src/zog/host_deploy/gateway/graphics_catalogue_owner.py").read_text()
    assert '"compiler_authorized": False' in owner
    assert '"compiler_base": bound_base["accepted_receipt_sha256"]' in owner
    assert "send_command(" not in owner
    assert "create_issue(" not in owner
    assert "ssm:SendCommand" not in owner
    assert SELECTED_TASK_C!="02db124609b92396ff89fa628d8ddc9383e05f4b"

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


def test_actual_selected_task_c_is_trusted_host_single_attempt_not_s3_broker():
    current=root()/"dependencies/host-deploy-taskc"
    pipeline=(current/"src/zog/host_deploy/gateway/generic_pipeline.py").read_text()
    trusted=(current/"src/zog/host_deploy/gateway/trusted_host_submission.py").read_text()
    intent=(current/"src/zog/host_deploy/gateway/graphics_operation_send_intent.py").read_text()
    for needle in ("def _protected_original_identifiers(",
                   "send_intent.claim(", "send_intent.record_command(",
                   "trusted.submit_once("):
        assert needle in pipeline
    for needle in ("def selected_command(", "def submit_once(",
                   'DOCUMENT = "AWS-RunShellScript"',
                   "verify_current_target("):
        assert needle in trusted
    assert 'return host.submit_command(script, seconds=seconds)' in trusted
    assert "os.fsync(" in intent and "def refuse_if_claimed(" in intent
    # Historical broker sources may still exist, but selected code neither
    # imports their signed approvals nor depends on S3 or owner-only IAM.
    import ast
    for source in (pipeline,trusted):
        modules=[node.module for node in ast.walk(ast.parse(source))
                 if isinstance(node,ast.ImportFrom)]
        assert all(not m or not any(old in m for old in (
            "graphics_owner_ipc","graphics_owner_trust_history",
            "storage_approval","owner_checkpoint"))
            for m in modules)

def test_real_recipe_dependency_edges_are_exact_and_no_host_substitution():
    packages=original()/"project/package"
    expected={
        "libpng":{"build":[],"runtime":[]},
        "freetype":{"build":["libpng-final"],"runtime":["libpng-final"]},
        "fontconfig":{"build":["freetype-final"],"runtime":["freetype-final"]},
    }
    for name,dependencies in expected.items():
        folder=packages/name/"stages/final"
        assert literal(folder/"dependencies.py")==dependencies
        sources=literal(folder/"sources.py")
        assert len(sources)==1
        upstream=literal(packages/name/"upstream.py")
        assert sources[0]=={
            "url":upstream["release_url"],
            "sha256":upstream["sha256"],
            "destination":"upstream","archive":True,
        }
        commands=literal(folder/"build.py")
        assert set(commands)=={"configure","build","test","install"}
        assert commands["configure"] and commands["test"]
        assert all("test -n \"$DESTDIR\"" in " ".join(cmd)
                   for cmd in commands["install"])
        # Source closure excludes network acquisition during the selected
        # build and does not permit an unreviewed optional dependency.
        for stage in ("configure","build","test","install"):
            for cmd in commands[stage]:
                joined=" ".join(cmd)
                for forbidden in ("curl ", "wget ", "pip install ",
                                  "apt-get ", "dnf install ", "sudo "):
                    assert forbidden not in joined
    freetype_build=literal(packages/"freetype/stages/final/build.py")
    flags=" ".join(" ".join(x) for x in freetype_build["configure"])
    for required in ("--with-zlib=yes","--with-bzip2=yes",
                     "--with-png=yes","--with-harfbuzz=no",
                     "--with-brotli=no"):
        assert required in flags
    assert "make check" in " ".join(" ".join(x) for x in
                                   literal(packages/"fontconfig/stages/final/build.py")["test"])
