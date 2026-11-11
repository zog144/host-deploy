"""Source-only review of November 11 trusted-Host Task C integration.

No SSM SDK, AWS credentials, operation claim, issue creation or native catalogue
installation is exercised. The held Fonts catalogue remains the sole task.
"""
import ast
from pathlib import Path

import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as fonts
from zog.host_deploy.gateway import task_catalogue

TASK_C = Path("dependencies/host-deploy-taskc")
GATEWAY = TASK_C / "src/zog/host_deploy/gateway"
ROOT = Path("src/zog/host_deploy/gateway")


class TrustedRouteMismatch(ValueError):
    pass


def _deny(reason):
    raise TrustedRouteMismatch("trusted-Host Fonts source NO-GO: " + reason)


def inspect_pipeline(generic, trusted, intent, catalogue, *, selected_task, selected_owner):
    if not all(word in generic for word in (
        "def advance(", "send_intent.claim(", "send_intent.record_command(",
        "trusted.submit_once(", "_protected_original_identifiers(",
        'from . import trusted_host_submission as trusted',
        'arguments = {**task["arguments"]',
    )):
        _deny("old or arbitrary SSM execution route")
    if not all(word in trusted for word in (
        'DOCUMENT = "AWS-RunShellScript"', "def selected_command(",
        "def submit_once(", "verify_current_target(",
        'return host.submit_command(script, seconds=seconds)',
    )):
        _deny("trusted Host target/document/single-send boundary missing")
    if not all(word in intent for word in (
        'host-deploy-generic-operation-send-once-v1',
        "def claim(", "def refuse_if_claimed(", "def require_command(",
        "os.fsync(",
    )):
        _deny("local durable no-retry journal removed")
    for source in (generic, trusted):
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,ast.ImportFrom) and node.module and any(
                old in node.module for old in (
                    "graphics_owner_ipc", "graphics_owner_trust_history",
                    "graphics_s3", "graphics_broker", "owner_checkpoint",
                    "storage_approval", "installer_signature")):
                _deny("retired S3/separate owner or installer signer imported")
    if not all(x in catalogue for x in (
        'if name == "graphics-fonts-image-v1":',
        'required.add("compiler_base")',
        '"Fonts compiler receipt differs from original accepted evidence"',
    )):
        _deny("first Fonts immutable task lacks real compiler receipt")
    if not all(x in selected_owner for x in (
        '"compiler_base": bound_base["accepted_receipt_sha256"]',
        '"compiler_authorized": False',
        'SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"',
        'READER_SOURCE = "1616f192ef9d8964a8f37f32a86c69c0242a213c"',
    )):
        _deny("source-selected compiler receipt or original source changed")
    return "TRUSTED_HOST_FONTS_SOURCE_COMPATIBLE_NATIVE_HELD"


def samples():
    sources=[
        (GATEWAY/"generic_pipeline.py").read_text(),
        (GATEWAY/"trusted_host_submission.py").read_text(),
        (GATEWAY/"graphics_operation_send_intent.py").read_text(),
        (ROOT/"task_catalogue.py").read_text(),
        (ROOT/"graphics_catalogue_owner.py").read_text(),
    ]
    return sources


def test_original_fonts_selected_for_one_trusted_host_stage():
    assert inspect_pipeline(*samples())=="TRUSTED_HOST_FONTS_SOURCE_COMPATIBLE_NATIVE_HELD"
    assert fonts.SOURCE=="1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
    assert fonts.PIN_SHA256=="d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
    assert fonts.READER_SOURCE=="1616f192ef9d8964a8f37f32a86c69c0242a213c"
    assert fonts.TASK=="graphics-fonts-image-v1"
    assert task_catalogue.SCHEMA==2


@pytest.mark.parametrize("changed,text", [
    (0,"trusted.submit_once("),
    (1,'DOCUMENT = "AWS-RunShellScript"'),
    (2,"os.fsync("),
    (3,'required.add("compiler_base")'),
    (4,'"compiler_base": bound_base["accepted_receipt_sha256"]'),
])
def test_missing_trusted_route_or_compiler_binding_refused(changed,text):
    sources=samples()
    assert text in sources[changed]
    sources[changed]=sources[changed].replace(text,"REMOVED")
    with pytest.raises(TrustedRouteMismatch,match="NO-GO"):
        inspect_pipeline(*sources)


def test_retired_signing_broker_import_in_selected_route_refused():
    sources=samples()
    sources[0]+="\nfrom .graphics_owner_ipc import issue_signed_install_commit\n"
    with pytest.raises(TrustedRouteMismatch,match="retired S3"):
        inspect_pipeline(*sources)


def test_only_original_task_will_be_selected_with_explicit_compiler_receipt():
    fixture = {
        "schema":2,
        "tasks":{
            fonts.TASK:{
                "source_repository":fonts.REPOSITORY,
                "source_revision":fonts.SOURCE,
                "lane":"test-lane",
                "lane_owner":"test-host",
                "monthly_pin_repository_path":fonts.PIN_PATH,
                "monthly_pin_identity":"sha256:"+fonts.PIN_SHA256,
                "pin_date":"2026-10-01",
                "entries":[{"id":n,"project":p,"recipe":r}
                           for n,p,r in task_catalogue.REVIEWED_IMAGE_TASKS[fonts.TASK]["entries"]],
                "arguments":{"mode":"image","selection":"a"*64,
                             "compiler_base":"sha256:"+"b"*64,
                             "targets":list(task_catalogue.REVIEWED_IMAGE_TASKS[fonts.TASK]["targets"])},
                "retained_acceptance_sha256":"sha256:"+"c"*64,
            }
        },
    }
    assert set(task_catalogue.validate(fixture)["tasks"])=={fonts.TASK}
    del fixture["tasks"][fonts.TASK]["arguments"]["compiler_base"]
    with pytest.raises(task_catalogue.TaskCatalogueError):
        task_catalogue.validate(fixture)
