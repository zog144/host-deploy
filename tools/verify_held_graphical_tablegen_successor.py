"""Independent review of corrected LLVM TableGen held graphical successor.

Source-only: checks the unchanged PR19/PR20 held lineage and the *new*
immutable image-build PR8 original-source revision. Never imports or calls a
gateway send path, allocates a worker or admits a native generation.
"""
import ast
import copy
import json
from pathlib import Path

from verify_held_graphical_extension import load_proposal, validate as validate_old
from verify_held_graphical_source_dag import (
    load as load_old_dag, verify as verify_old_dag,
    ROOTS, STAGES, RESOURCES, CRITICAL
)

ROOT=Path(__file__).resolve().parents[1]
PROPOSAL=ROOT/"project/held-graphical-catalogue/workspace-next-tablegen-successor-v2.json"
REVIEW=ROOT/"project/held-graphical-catalogue/exact-source-dag-tablegen-successor-v2.json"
NEW="ed6ea94586ceeb13feee905b9e70afcb8963b128"
OLD="9cbd652226b863a7b4bb2d6d9539722e1a262508"
PR9="a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023"
LLVM_ARCHIVE="908bce97be0275943414b45af2e2b20e8f6d5d9266fdc120bd59f096ebc547ad"
OUTPUT="usr/bin/llvm-tblgen"
TABLEGEN_UNACCEPTED={"installed_tablegen_elf_sha256","installed_tablegen_provenance_receipt",
                     "tablegen_generator_input_output_attestation","selected_generator_toolchain_proof",
                     "independent_rights_approval","native_generation_accepted"}
def load():return json.loads(PROPOSAL.read_text())
def load_review():return json.loads(REVIEW.read_text())
def literal(path):return ast.literal_eval(Path(path).read_text())
def deny(why):raise ValueError("graphical TableGen successor NOT READY: "+why)

def verify(candidate, review, pr9_checkout, old_checkout, new_checkout, *, previous=None, previous_review=None):
    old=copy.deepcopy(previous if previous is not None else load_proposal())
    oldreview=copy.deepcopy(previous_review if previous_review is not None else load_old_dag())
    pr9=Path(pr9_checkout).resolve(strict=True)
    oldroot=Path(old_checkout).resolve(strict=True)
    newroot=Path(new_checkout).resolve(strict=True)
    # This invokes the existing real gateway's active catalogue and original source pin
    # checks, as well as the existing independently accepted v1 source-DAG inspection.
    if validate_old(old)!="HELD_NOT_SUBMITTABLE":
        deny("legacy catalogue no longer held")
    oldresult=verify_old_dag(oldreview,old,pr9,oldroot)
    if oldresult["llvm_tblgen"]!="UNMANIFESTED_PRODUCTION_HOLD":
        deny("original source hold bypassed")
    required=copy.deepcopy(old)
    required["candidate_revision"]="2026-11-04"
    required["producer"]["mesa_pr8_candidate_revision"]=NEW
    if type(candidate) is not dict or "successor_review" not in candidate:
        deny("missing successor-only source selection")
    extras=candidate["successor_review"]
    expected_extras={
        "schema":"zog-held-graphical-tablegen-successor-v1",
        "status":"SELECTED_SOURCE_CONTRACT_RECONCILED_NATIVE_NO_GO",
        "base_host_deploy_pr19_revision":"52fe84b6a2e3fa3e3626efae485851b16a762a62",
        "pr20_independent_dag_review_revision":"7d091af5673fbc9c767d9d46386d344197d0267a",
        "previous_llvm_mesa_source_revision":OLD,
        "corrected_llvm_mesa_source_revision":NEW,
        "llvm_source_archive_sha256":LLVM_ARCHIVE,
        "tablegen_build_target":"llvm-tblgen",
        "tablegen_source_declared_installed_path":OUTPUT,
        "installed_tablegen_elf_sha256":None,
        "installed_tablegen_provenance_receipt":None,
        "tablegen_generator_input_output_attestation":None,
        "selected_generator_toolchain_proof":None,
        "independent_rights_approval":None,
        "native_generation_accepted":None,
        "submit_allowed":False,
        "production_task_catalogue_changed":False,
    }
    if extras!=expected_extras:
        deny("incorrect source selection, minted TableGen witness, or changed authority")
    required["successor_review"]=expected_extras
    if candidate!=required:
        deny("successor silently altered old DAG, stage order, upstream tool or authorization holds")
    exp_review=copy.deepcopy(oldreview)
    exp_review["schema"]="zog-held-graphics-successor-source-dag-review-v1"
    exp_review["image_build_mesa_revision"]=NEW
    llvmrow=exp_review["stages"][0]["required_installed_outputs"]
    if OUTPUT in llvmrow:deny("old source's deliberately missing TableGen output hold erased")
    llvmrow.insert(1,OUTPUT)
    exp_review["unmanifested_planned_outputs"]={}
    exp_review["review_obligations"][0]=(
        "LLVM 21.1.6 now declares llvm-tblgen as an actual build/test/installed-output requirement; "
        "genuine generation, tool ELF, selected-path provenance and table generation still unobserved")
    exp_review["successor_status"]="TABLEGEN_SOURCE_OUTPUT_AUTHORED_NO_NATIVE_EVIDENCE"
    if review!=exp_review:
        deny("incomplete/missing package DAG, resources, rights or generated-tool no-native hold")
    for item in review["stages"]:
        stage=item["id"]
        which,where=ROOTS[stage]
        root=newroot if which=="pr8" else pr9
        dep=literal(root/where/"dependencies.py")
        output=literal(root/where/"produce-manifest.py")
        if (dep.get("build")!=item["build_predecessors"] or
            dep.get("runtime")!=item["runtime_predecessors"] or
            output.get("trees")!=["usr"] or
            output.get("required")!=item["required_installed_outputs"]):
            deny("selected exact package dependencies/output manifest drift: "+stage)
        if not CRITICAL[stage]["build"].issubset(set(dep["build"])) or not CRITICAL[stage]["runtime"].issubset(set(dep["runtime"])):
            deny("missing essential source predecessor: "+stage)
        if candidate["stage_order"][list(STAGES).index(stage)]["outputs"]!=old["stage_order"][list(STAGES).index(stage)]["outputs"]:
            deny("successor substituted installed output shape: "+stage)
        if set(candidate["stage_order"][list(STAGES).index(stage)]["outputs"])!=set(output["required"]):
            deny("catalogue proposed outputs not identical to actual package stage: "+stage)
    for source,where,required_output in RESOURCES:
        if required_output not in literal(pr9/where/"produce-manifest.py")["required"]:
            deny("XKB/font/terminfo resource no longer source declared")
    expected_new=literal(newroot/"project/graphics-drafts/llvm/stages/final/produce-manifest.py")["required"]
    expected_old=literal(oldroot/"project/graphics-drafts/llvm/stages/final/produce-manifest.py")["required"]
    if expected_new!=expected_old[:1]+[OUTPUT]+expected_old[1:]:
        deny("TableGen not the exact source-manifest improvement")
    for name in ("llvm","mesa","mesa-demos"):
        stage="project/graphics-drafts/"+name+"/stages/final/"
        if literal(oldroot/(stage+"sources.py"))!=literal(newroot/(stage+"sources.py")):
            deny("original upstream archive source pin silently replaced")
        if literal(oldroot/(stage+"dependencies.py"))!=literal(newroot/(stage+"dependencies.py")):
            deny("unreviewed LLVM/Mesa source-stage dependency graph modification")
    source=literal(newroot/"project/graphics-drafts/llvm/stages/final/sources.py")[0]
    if source["sha256"]!=LLVM_ARCHIVE:
        deny("LLVM upstream selected original source differs")
    llvm=literal(newroot/"project/graphics-drafts/llvm/stages/final/build.py")
    mesa=literal(newroot/"project/graphics-drafts/mesa/stages/final/build.py")
    build=llvm["build"][0][-1]
    test=llvm["test"][0][-1]
    install=llvm["install"][0][-1]
    conf=mesa["configure"][0][-1]
    if (build.splitlines()[:2]!=["cmake --build build-llvm --target llvm-tblgen --parallel 2",
                                 "cmake --build build-llvm --parallel 2"] or
        "test -x build-llvm/bin/llvm-tblgen" not in test or
        'install -Dm755 build-llvm/bin/llvm-tblgen "$DESTDIR/usr/bin/llvm-tblgen"' not in install or
        'test -x "$DESTDIR/usr/bin/llvm-tblgen"' not in install):
        deny("TableGen actual LLVM source build/test/installed binary closure absent")
    if ("ZOG_GRAPHICS_TOOLCHAIN_VERIFIER" not in conf or
        "--phase mesa" not in conf or
        "test -x /usr/bin/llvm-tblgen" not in conf or
        conf.index("ZOG_GRAPHICS_TOOLCHAIN_VERIFIER")>conf.index("test -x /usr/bin/llvm-tblgen") or
        "llvm-config --has-rtti" not in conf):
        deny("Mesa generator lacks selected-tool provenance preflight")
    rights=json.loads((newroot/"project/graphics-drafts/rights-admission-evidence.json").read_text())
    if (rights.get("rights_approved") is not False or
        rights.get("canonical_admitted") is not False or
        rights.get("status")!="independent-rights-and-native-output-NO-GO"):
        deny("rights/redistribution status was promoted")
    llvm_rights=rights["components"]["llvm"]
    if (llvm_rights["expected_output_paths"]!=expected_new or
        llvm_rights.get("installed_outputs_observed") is not False or
        llvm_rights.get("notice_delivery_verified") is not False or
        not any("TableGen" in str(x) for x in llvm_rights.get("outstanding",[])) or
        any(item.get("installed_outputs_observed") is not False or
            item.get("notice_delivery_verified") is not False
            for item in rights["components"].values())):
        deny("unreviewed installed notice, generated tool or source rights")
    historical_rights=json.loads((pr9/"project/graphics-first-workspace/remaining-distribution-evidence-2026-11-03.json").read_text())
    if historical_rights.get("redistribution_authorized") is not False or historical_rights.get("installed_generation_receipt") is not None:
        deny("TurboVNC original rights prematurely approved")
    return {"source_DAG":"RECONCILED","llvm_tablegen_source_requirement":"SATISFIED",
            "llvm_tablegen_native_evidence":None,"native_generation":None,
            "rights":"NO_GO","build_authorized":False,"submission":"HELD_NOT_SUBMITTABLE"}
