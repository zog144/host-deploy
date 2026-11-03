"""Independently compare held graphical proposal against exact PR9 + Mesa PR8 package manifests.

Pure source review. Never signs, submits, installs, or enables any future task.
"""
import ast
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RECORD=ROOT/"project/held-graphical-catalogue/exact-source-dag-review-v1.json"
PR9="a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023"
PR8="9cbd652226b863a7b4bb2d6d9539722e1a262508"
STAGES=("LLVM","Mesa","Xvnc","i3","xterm","mesa-demos-smoke")
ROOTS={
"LLVM":("pr8","project/graphics-drafts/llvm/stages/final"),
"Mesa":("pr8","project/graphics-drafts/mesa/stages/final"),
"Xvnc":("pr9","project/graphics-first-workspace/turbovnc-draft/stages/final"),
"i3":("pr9","project/package/i3/stages/final"),
"xterm":("pr9","project/package/xterm/stages/final"),
"mesa-demos-smoke":("pr8","project/graphics-drafts/mesa-demos/stages/final"),
}
CRITICAL={
"LLVM":{"build":{"zlib-native-environment"},"runtime":{"zlib-native-environment"}},
"Mesa":{"build":{"llvm-final","mako-final","pyyaml-final","libdrm-final","expat-final","zlib-native-environment","libxshmfence-final","libXxf86vm-final"},"runtime":{"llvm-final","libX11-final","libxcb-final"}},
"Xvnc":{"build":{"libjpeg-turbo-final","pixman-final","xkeyboard-config-final","xkbcomp-final","mesa-final","openssl-final","zlib-native-environment"},"runtime":{"xkeyboard-config-final","libXfont2-final","mesa-final"}},
"i3":{"build":{"libev-final","yajl-final","startup-notification-final","libxkbcommon-final","glib-final","cairo-final","pango-final"},"runtime":{"libev-final","libxcb-final","libxkbcommon-final"}},
"xterm":{"build":{"ncurses-temporary","libXaw-final","libXmu-final","libXpm-final","libXft-final"},"runtime":{"ncurses-temporary","luit-final","basic-font-final"}},
"mesa-demos-smoke":{"build":{"mesa-final","libX11-final","libXext-final"},"runtime":{"mesa-final","libX11-final","libXext-final"}}
}
RESOURCES=(
("pr9","project/package/xkeyboard-config/stages/final","usr/share/X11/xkb"),
("pr9","project/package/xkbcomp/stages/final","usr/bin/xkbcomp"),
("pr9","project/package/basic-font/stages/final","usr/share/fonts/X11/misc/6x13.pcf.gz"),
("pr9","project/package/basic-font/stages/final","usr/share/fonts/X11/misc/fonts.dir"),
("pr9","project/package/xterm/stages/final","usr/share/X11/app-defaults/XTerm"),
("pr9","project/package/xterm/stages/final","usr/share/terminfo/x/xterm"))
KNOWN_UNMANIFESTED={"LLVM":["usr/bin/llvm-tblgen"]}
def deny(message):
    raise ValueError("held graphics source DAG NOT READY: "+message)
def load():
    return json.loads(RECORD.read_bytes())
def literal(path):
    return ast.literal_eval(path.read_text())
def source_roots(pr9_checkout,mesa_checkout):
    return {"pr9":Path(pr9_checkout).resolve(strict=True),"pr8":Path(mesa_checkout).resolve(strict=True)}

def verify(review,proposal,pr9_checkout,mesa_checkout):
    src=source_roots(pr9_checkout,mesa_checkout)
    if (not isinstance(review,dict) or set(review)!={
            "schema","status","image_build_workspace_revision","image_build_mesa_revision",
            "active_task_authority_unchanged","source_only","accepted_generation_receipts",
            "toolchain_origin_proof","independent_rights_authorized",
            "native_compilation_authorized","installed_notice_bytes_verified",
            "stages","required_resources","unmanifested_planned_outputs",
            "review_obligations"
        } or review["schema"]!="zog-held-graphics-source-dag-review-v1"
        or review["status"]!="EXACT_SOURCE_DAG_REVIEW_NATIVE_NO_GO"
        or review["image_build_workspace_revision"]!=PR9
        or review["image_build_mesa_revision"]!=PR8
        or review["active_task_authority_unchanged"] is not True
        or review["source_only"] is not True
        or review["accepted_generation_receipts"] is not None
        or review["toolchain_origin_proof"] is not None
        or any(review[k] is not False for k in
            ("independent_rights_authorized","native_compilation_authorized","installed_notice_bytes_verified"))):
        deny("unreviewed source revision, native generation or rights claim")
    records=review["stages"]
    if (type(records) is not list or len(records)!=len(STAGES)
        or [r.get("id") for r in records]!=list(STAGES)):
        deny("missing or reordered future stage")
    planned=proposal.get("stage_order")
    if not isinstance(planned,list) or len(planned)!=len(STAGES):
        deny("not the same held stage proposal")
    for row,stage in zip(records,planned):
        name=row["id"]
        where,stage_root=ROOTS[name]
        if (set(row)!={
            "id","source","package","stage_root","build_predecessors",
            "runtime_predecessors","required_installed_outputs"}
            or row["source"]!=where or row["stage_root"]!=stage_root
            or row["id"]!=stage["id"]):
            deny("altered source-stage mapping: "+name)
        base=src[where]/stage_root
        if not (base/"dependencies.py").is_file() or not (base/"produce-manifest.py").is_file():
            deny("selected original package stage missing: "+name)
        dep=literal(base/"dependencies.py")
        manifest=literal(base/"produce-manifest.py")
        if (set(dep)!={"build","runtime"} or
            dep["build"]!=row["build_predecessors"] or
            dep["runtime"]!=row["runtime_predecessors"] or
            manifest.get("required")!=row["required_installed_outputs"] or
            manifest.get("trees")!=["usr"]):
            deny("source-manifest dependencies or bytes drift: "+name)
        for group in ("build","runtime"):
            if not CRITICAL[name][group].issubset(set(dep[group])):
                deny("missing essential predecessor: "+name+"/"+group)
        if any(dep[group].count(x)!=1 for group in dep for x in dep[group]):
            deny("duplicated predecessor: "+name)
        proposed=stage["outputs"]
        expected=set(row["required_installed_outputs"])
        extra=set(KNOWN_UNMANIFESTED.get(name,()))
        if (not isinstance(proposed,list) or len(proposed)!=len(set(proposed))
            or set(proposed)!=(expected|extra)):
            deny("stage lacks actual installed outputs or adds an unsupported output: "+name)
        if (stage["accepted_generation_receipt"] is not None or
            stage["recipe_status"] not in ("SOURCE_AUTHORED_NATIVE_HELD",
                "DRAFT_NOT_PACKAGE_ADMITTED","SOURCE_PLAN_NOT_CANONICAL")):
            deny("source list promoted to native generation: "+name)
        if where=="pr9":
            check_path=stage_root+"/dependencies.py"
            if stage["recipe_path"]!=check_path:
                deny("proposed Workspace recipe does not identify actual source: "+name)
        elif stage["recipe_path"] is not None:
            deny("Mesa/LLVM draft silently represented as canonical package: "+name)
    resources=review["required_resources"]
    if (type(resources) is not list or len(resources)!=len(RESOURCES)
        or {(r.get("source"),r.get("stage_root"),r.get("output")) for r in resources}!=set(RESOURCES)):
        deny("missing installed XKB/font/terminfo/desktop resources")
    for source,path,output in RESOURCES:
        manifest=literal(src[source]/path/"produce-manifest.py")
        if output not in manifest["required"]:
            deny("source installed resource absent: "+output)
    if review["unmanifested_planned_outputs"]!=KNOWN_UNMANIFESTED:
        deny("missing LLVM llvm-tblgen source manifest hold")
    llvm=records[0]["required_installed_outputs"]
    if "usr/bin/llvm-tblgen" in llvm:
        deny("unmanifested LLVM source tool incorrectly declared accepted")
    obligations=review["review_obligations"]
    if (not isinstance(obligations,list) or len(obligations)<7 or
        not any("llvm-tblgen" in str(item) for item in obligations) or
        not any("rights" in str(item).lower() for item in obligations) or
        not any("Mako" in str(item) and "PyYAML" in str(item) for item in obligations)):
        deny("future build-tool/resource/rights holds omitted")
    rights9=json.loads((src["pr9"]/"project/graphics-first-workspace/remaining-distribution-evidence-2026-11-03.json").read_text())
    rights8=json.loads((src["pr8"]/"project/graphics-drafts/rights-admission-evidence.json").read_text())
    if (rights9.get("redistribution_authorized") is not False or
        rights9.get("installed_generation_receipt") is not None or
        rights8.get("status")!="independent-rights-and-native-output-NO-GO" or
        any(r.get("installed_outputs_observed") is not False for r in rights8["components"].values())):
        deny("unapproved rights or installed source bytes treated as accepted")
    return {"source_package_stage_dag":"EXACT","stage_outputs":"RECONCILED",
            "llvm_tblgen":"UNMANIFESTED_PRODUCTION_HOLD","rights":"NO_GO",
            "accepted_generation":None,"task_submission_allowed":False}
