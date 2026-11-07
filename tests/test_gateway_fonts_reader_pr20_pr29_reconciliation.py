"""Independent exact-head PR20 producer / PR29 consumer / PR7 Fonts source selection.

Read-only CI comparison: no accepted native keys, state or runnable GitHub
request. A forged "plausible" v2 observation cannot replace the selected
immutable source and the actual producer verification witness.
"""
import ast
from pathlib import Path

import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as fonts
from zog.host_deploy.gateway import graphics_base_acceptance as accepted
from zog.host_deploy.gateway import task_catalogue

IMAGE_SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
OCTOBER_PIN = "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"
READER_SOURCE = "1616f192ef9d8964a8f37f32a86c69c0242a213c"
CONSUMER_SOURCE = "b3ac93cd92df1b280f087fbb748263d3371750aa"
ORIGINAL = Path("dependencies/image-build")
READER = Path("dependencies/image-build-base-observer")
CONSUMER = Path("dependencies/host-deploy-reviewed-pr29")
CURRENT = Path("src/zog/host_deploy/gateway")

class ReaderDrift(ValueError):
    pass

def require(statement, reason):
    if not statement:
        raise ReaderDrift("first-Fonts independent source reconciliation NO-GO: " + reason)

def _tree_constant(text, name):
    tree=ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(left,ast.Name) and left.id==name for left in node.targets):
            return ast.literal_eval(node.value)
    raise ReaderDrift("missing original declared source contract: "+name)

def validate(producer, isolation, upstream_consumer, local_consumer,
             upstream_owner, local_owner, *, original_pin, expected_reader=READER_SOURCE):
    """Static exact-source review, not a substitute for real native opening."""
    require(expected_reader==READER_SOURCE, "outdated or substituted reader revision")
    require(_tree_constant(producer, "SCHEMA")==accepted.ACCEPTANCE_SCHEMA,
            "original compiler acceptance schema changed")
    require(_tree_constant(producer, "BINDING")==accepted.BINDING_SCHEMA,
            "original compiler binding schema changed")
    require(_tree_constant(isolation,"SCHEMA")=="image-build-compiler-isolation-v2",
            "legacy isolation schema selected")
    require(_tree_constant(isolation,"PROFILE")=="selected-root-kernel-mounts-v1",
            "old imaginary no-Host-mount profile selected")
    fields=_tree_constant(isolation,"FIELDS")
    require(fields=={
      "schema","profile","witness_sha256","runtime_id","invocation_id",
      "uid","gid","effective_capabilities","no_new_privileges",
      "mount_namespace","host_mount_namespace","network_namespace",
      "host_network_namespace","network_interfaces","imported_root",
      "source_root","output_root","mounts","selected_files"},
      "source-observed isolation field contract incomplete")
    require(_tree_constant(producer,"SLOTS")==(
      "compiler","linker","assembler","libc_header","abi_header","crt","libc"),
      "selected compiler/header/linker inventory roles substituted")
    require(_tree_constant(upstream_consumer,"ABI")==
            _tree_constant(local_consumer,"ABI")==accepted.ABI,
            "Zog native target ABI no longer permitted by current consumer")
    require(local_consumer==upstream_consumer,
            "first-Fonts catalogue uses a consumer different from reviewed PR29")
    require(local_owner==upstream_owner,
            "first-Fonts catalogue source is not reviewed PR29 owner")
    require(_tree_constant(local_owner,"SOURCE")==IMAGE_SOURCE,
            "original compiler recipe producer silently repinned")
    require(_tree_constant(local_owner,"PIN_SHA256")==OCTOBER_PIN,
            "original October monthly pin repinned")
    require(_tree_constant(local_owner,"READER_SOURCE")==READER_SOURCE,
            "first-Fonts selected reader stale or unreviewed")
    require("image-build-compiler-isolation-v2" in local_consumer and
            "selected-root-kernel-mounts-v1" in local_consumer and
            'not match(probe["isolation"].get("witness_sha256"),SHA)' in local_consumer,
            "signed original mount-observation profile or witness no longer required")
    require("host_mounts_visible" not in local_consumer and
            "pivot_root" not in local_consumer,
            "consumer reintroduced unobserved legacy isolation assertions")
    require("from .compiler_base_isolation import validate as validate_isolation" in producer,
            "producer stopped authenticating original observed mount/namespace evidence")
    require("validate_isolation(probe[\"isolation\"], e, claim[\"installed_paths\"])" in producer,
            "producer isolation checks no longer bind original controller/files")
    require("observed[\"uid\"]!=configuration.get(\"execution_user_id\")" in producer and
            "observed[\"gid\"]!=configuration.get(\"execution_group_id\")" in producer,
            "native nonroot worker identity no longer bound to selected controller")
    require("len(mounts)<=40" in isolation and
            "path=='/'" in isolation and "elif path in PSEUDO:" in isolation and
            "not {'/','/proc','/image-build/source','/image-build/output'}.issubset(seen)" in isolation,
            "original selected root/pseudo-mount obligations changed")
    require("separately accepted" not in local_owner or "compiler_authorized" in local_owner,
            "native approval and selected catalogue authority conflated")
    require('\"compiler_authorized\": False' in local_owner or
            '"compiler_authorized": False' in local_owner,
            "review-only catalogue granted compilation")
    import hashlib
    require(hashlib.sha256(original_pin).hexdigest()==OCTOBER_PIN,
            "original immutable October pin bytes changed")
    return "SELECTED_SOURCE_RECONCILED_NATIVE_NO_GO"

def inputs():
    paths=[
      READER/"src/zog/image_build/compiler_base_acceptance.py",
      READER/"src/zog/image_build/compiler_base_isolation.py",
      CONSUMER/"src/zog/host_deploy/gateway/graphics_base_acceptance.py",
      CURRENT/"graphics_base_acceptance.py",
      CONSUMER/"src/zog/host_deploy/gateway/graphics_catalogue_owner.py",
      CURRENT/"graphics_catalogue_owner.py",
    ]
    for p in paths+[ORIGINAL/"project/pins/2026-10-01/commit-pin.py"]:
        assert p.is_file(), "unconditional exact-source dependency checkout absent: "+str(p)
    return ([p.read_text() for p in paths],
            (ORIGINAL/"project/pins/2026-10-01/commit-pin.py").read_bytes())

def test_exact_producer_reader_consumer_and_original_monthly_pin():
    source,pin=inputs()
    assert validate(*source,original_pin=pin)=="SELECTED_SOURCE_RECONCILED_NATIVE_NO_GO"
    assert fonts.SOURCE==IMAGE_SOURCE and fonts.READER_SOURCE==READER_SOURCE
    assert set(task_catalogue.REVIEWED_IMAGE_TASKS[fonts.TASK]["targets"])=={
        "libpng-final","freetype-final","fontconfig-final"}
    assert fonts.TASK=="graphics-fonts-image-v1"

@pytest.mark.parametrize("mutation",[
 "old_reader","legacy_isolation","removed_worker_binding",
 "changed_pseudo_mounts","changed_consumer","changed_owner",
 "changed_producer","changed_month_pin","wrong_abi","missing_witness"
])
def test_selected_source_drift_denied_even_when_string_looks_plausible(mutation):
    (s,pin)=inputs()
    if mutation=="old_reader":
        with pytest.raises(ReaderDrift,match="outdated or substituted"):
            validate(*s,original_pin=pin,
                     expected_reader="bf0b37fea1767bf7ab02ca2d1c5d1a0d5487d4b6")
        return
    if mutation=="legacy_isolation":s[1]=s[1].replace(
        "selected-root-kernel-mounts-v1","pivot_root-no-host-mounts-v1")
    elif mutation=="removed_worker_binding":s[0]=s[0].replace(
        "observed[\"uid\"]!=configuration.get(\"execution_user_id\")","False")
    elif mutation=="changed_pseudo_mounts":s[1]=s[1].replace(
        "elif path in PSEUDO:","elif path in {}:")
    elif mutation=="changed_consumer":s[3]=s[3].replace(
        "selected-root-kernel-mounts-v1","no-host-mounts-v1")
    elif mutation=="changed_owner":s[5]=s[5].replace(
        READER_SOURCE,"bf0b37fea1767bf7ab02ca2d1c5d1a0d5487d4b6")
    elif mutation=="changed_producer":s[5]=s[5].replace(
        IMAGE_SOURCE,"a"*40)
    elif mutation=="changed_month_pin":pin=b"synthetic-replaced-monthly-pin"
    elif mutation=="wrong_abi":s[3]=s[3].replace(
        "x86_64-zog-linux-gnu","aarch64-linux-gnu")
    elif mutation=="missing_witness":s[3]=s[3].replace(
        'not match(probe["isolation"].get("witness_sha256"),SHA)',"False")
    with pytest.raises(ReaderDrift,match="NO-GO"):
        validate(*s,original_pin=pin)

def test_no_compiler_submission_granted_by_consumer_source():
    src=(CURRENT/"graphics_catalogue_owner.py").read_text()
    assert 'attest_installed_source(READER_SOURCE)' in src
    assert 'attest_installed_source(SOURCE)' in src
    assert '"compiler_authorized": False' in src
    assert 'O_EXCL' in src
    assert '"work_bytes": 30 * 1024**3' in src
    assert '"external_bytes": 2 * 1024**3' in src
    assert '"execution_limit_seconds": 21600' in src
