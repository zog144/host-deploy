"""Independent original graphical package DAG and installed-resource omission tests."""
import copy
import importlib.util
import os
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
m=module("held_dag_review","tools/verify_held_graphical_source_dag.py")
held=module("held_main_review","tools/verify_held_graphical_extension.py")
pr9=os.environ["ZOG_HELD_PR9_SOURCE"]
pr8=os.environ["ZOG_HELD_MESA_SOURCE"]

def check(review=None,proposal=None):
    return m.verify(review if review is not None else m.load(),
                    proposal if proposal is not None else held.load_proposal(),
                    pr9,pr8)

def test_exact_pinned_package_graph_and_full_declared_outputs_remain_held():
    result=check()
    assert result["source_package_stage_dag"]=="EXACT"
    assert result["stage_outputs"]=="RECONCILED"
    assert result["llvm_tblgen"]=="UNMANIFESTED_PRODUCTION_HOLD"
    assert result["task_submission_allowed"] is False
    assert result["accepted_generation"] is None
    assert result["rights"]=="NO_GO"

@pytest.mark.parametrize("stage",m.STAGES)
def test_cannot_omit_one_real_source_manifest_dependency(stage):
    review=copy.deepcopy(m.load())
    row=next(v for v in review["stages"] if v["id"]==stage)
    assert row["build_predecessors"]
    row["build_predecessors"].pop()
    with pytest.raises(ValueError,match="NOT READY"):
        check(review=review)

@pytest.mark.parametrize("stage,output",[
    ("LLVM","usr/share/licenses/llvm/BLAKE3-LICENSE"),
    ("Mesa","usr/share/licenses/mesa/glapi-generator-license.py"),
    ("Xvnc","usr/bin/vncserver"),
    ("Xvnc","usr/share/licenses/turbovnc/Xserver-COPYING"),
    ("i3","usr/bin/i3-nagbar"),
    ("xterm","usr/share/X11/app-defaults/XTerm"),
    ("xterm","usr/share/terminfo/x/xterm"),
    ("mesa-demos-smoke","usr/share/licenses/mesa-demos/glxgears.c")
])
def test_held_proposal_cannot_hide_actual_required_outputs_or_notices(stage,output):
    p=copy.deepcopy(held.load_proposal())
    value=next(s for s in p["stage_order"] if s["id"]==stage)
    assert output in value["outputs"]
    value["outputs"].remove(output)
    with pytest.raises(ValueError,match="NOT READY"):
        check(proposal=p)

@pytest.mark.parametrize("resource",[
    "usr/share/fonts/X11/misc/6x13.pcf.gz",
    "usr/share/fonts/X11/misc/fonts.dir",
    "usr/share/X11/xkb",
    "usr/bin/xkbcomp",
    "usr/share/X11/app-defaults/XTerm",
    "usr/share/terminfo/x/xterm"
])
def test_no_missing_xkb_font_or_term_resource(resource):
    review=copy.deepcopy(m.load())
    review["required_resources"]=[r for r in review["required_resources"]
                                  if r["output"]!=resource]
    with pytest.raises(ValueError,match="missing installed XKB/font"):
        check(review=review)

@pytest.mark.parametrize("stage,predecessor,kind",[
    ("Mesa","mako-final","build"),("Mesa","pyyaml-final","build"),
    ("Mesa","libdrm-final","build"),("Mesa","libxshmfence-final","build"),
    ("Xvnc","libjpeg-turbo-final","runtime"),("Xvnc","xkbcomp-final","build"),
    ("i3","libev-final","build"),("i3","yajl-final","runtime"),
    ("xterm","luit-final","runtime"),("xterm","ncurses-temporary","build"),
    ("LLVM","zlib-native-environment","runtime")
])
def test_no_hidden_toolchain_or_runtime_predecessor(stage,predecessor,kind):
    review=copy.deepcopy(m.load())
    row=next(r for r in review["stages"] if r["id"]==stage)
    assert predecessor in row[kind+"_predecessors"]
    row[kind+"_predecessors"].remove(predecessor)
    with pytest.raises(ValueError,match="NOT READY"):
        check(review=review)

def test_llvm_tblgen_missing_manifest_is_explicit_hold_not_synthetic_output():
    review=copy.deepcopy(m.load())
    assert review["unmanifested_planned_outputs"]=={"LLVM":["usr/bin/llvm-tblgen"]}
    review["unmanifested_planned_outputs"]["LLVM"]=[]
    with pytest.raises(ValueError,match="llvm-tblgen"):
        check(review=review)
    p=copy.deepcopy(held.load_proposal())
    p["stage_order"][0]["outputs"].remove("usr/bin/llvm-tblgen")
    with pytest.raises(ValueError,match="stage lacks"):
        check(proposal=p)

def test_cannot_invent_native_generation_or_rights():
    for field,value in (
        ("toolchain_origin_proof",{"signed-looking":True}),
        ("accepted_generation_receipts",{"X11":"a"*64}),
        ("native_compilation_authorized",True),
        ("independent_rights_authorized",True),
        ("installed_notice_bytes_verified",True)):
        data=copy.deepcopy(m.load())
        data[field]=value
        with pytest.raises(ValueError,match="NOT READY"):
            check(review=data)

def test_no_undisclosed_path_or_source_stage_can_enter_the_proposal():
    p=copy.deepcopy(held.load_proposal())
    p["stage_order"][1]["outputs"].append("usr/lib/libEGL.so")
    with pytest.raises(ValueError,match="stage lacks"):
        check(proposal=p)
    data=copy.deepcopy(m.load())
    data["stages"][1]["stage_root"]="project/package/mesa/stages/final"
    with pytest.raises(ValueError,match="altered source-stage mapping"):
        check(review=data)
