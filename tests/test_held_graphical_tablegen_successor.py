"""Corrected LLVM TableGen source successor remains a held catalogue."""
import copy
import importlib.util
import os
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "successor_review",ROOT/"tools/verify_held_graphical_tablegen_successor.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def check(candidate=None,review=None):
    return m.verify(candidate if candidate is not None else m.load(),
                    review if review is not None else m.load_review(),
                    os.environ["ZOG_HELD_PR9_SOURCE"],
                    os.environ["ZOG_HELD_MESA_OLD_SOURCE"],
                    os.environ["ZOG_HELD_MESA_NEW_SOURCE"])

def test_successor_selects_exact_corrected_llvm_and_keeps_old_hold_independently():
    result=check()
    assert result["llvm_tablegen_source_requirement"]=="SATISFIED"
    assert result["llvm_tablegen_native_evidence"] is None
    assert result["native_generation"] is None
    assert result["rights"]=="NO_GO"
    assert result["build_authorized"] is False
    assert result["submission"]=="HELD_NOT_SUBMITTABLE"

@pytest.mark.parametrize("key,value",[
  ("mesa_pr8_candidate_revision","9cbd652226b863a7b4bb2d6d9539722e1a262508"),
  ("workspace_pr9_candidate_revision","f"*40),
  ("current_protected_selected_revision","f"*40),
  ("current_protected_monthly_pin","sha256:"+"f"*64)
])
def test_old_or_forged_immutable_source_selection_rejected(key,value):
    c=copy.deepcopy(m.load());c["producer"][key]=value
    with pytest.raises(ValueError,match="NOT READY"):check(candidate=c)

@pytest.mark.parametrize("role,value",[
 ("installed_tablegen_elf_sha256","f"*64),
 ("installed_tablegen_provenance_receipt",{"signature":"plausible"}),
 ("tablegen_generator_input_output_attestation",{"output_sha256":"f"*64}),
 ("selected_generator_toolchain_proof",{"status":"accepted"}),
 ("independent_rights_approval","approved"),
 ("native_generation_accepted","f"*64),
 ("submit_allowed",True),
 ("production_task_catalogue_changed",True)
])
def test_signed_looking_evidence_or_compiler_authority_cannot_enter_source(role,value):
    c=copy.deepcopy(m.load());c["successor_review"][role]=value
    with pytest.raises(ValueError,match="NOT READY"):check(candidate=c)

@pytest.mark.parametrize("location,field,value",[
 ("authority","build_submission_allowed",True),
 ("authority","task_allowlist_extension_allowed",True),
 ("authority","protected_send_once_highwater",{"trusted":True}),
 ("required_predecessor_receipts","LLVM","f"*64),
 ("required_predecessor_receipts","X11","f"*64),
 ("required_package_stage_receipts","ncurses-temporary","f"*64),
 ("required_tool_provenance_receipts","meson-ninja-cmake-pkgconf","f"*64),
 ("required_tool_provenance_receipts","python-generators","f"*64),
 ("rights","rights_holder_authorized",True),
 ("execution","workers_authorized",True)
])
def test_authority_generation_and_tool_provenance_holds_are_immutable(location,field,value):
    c=copy.deepcopy(m.load());c[location][field]=value
    with pytest.raises(ValueError,match="NOT READY"):check(candidate=c)

@pytest.mark.parametrize("name,predecessor,side",[
 ("LLVM","zlib-native-environment","build"),
 ("Mesa","llvm-final","build"),
 ("Mesa","mako-final","build"),
 ("Mesa","pyyaml-final","build"),
 ("Mesa","libdrm-final","build"),
 ("Mesa","libxshmfence-final","build"),
 ("Xvnc","xkbcomp-final","build"),
 ("Xvnc","openssl-final","runtime"),
 ("i3","libev-final","build"),
 ("xterm","ncurses-temporary","runtime"),
 ("mesa-demos-smoke","mesa-final","build")
])
def test_real_package_stage_predecessor_may_not_disappear(name,predecessor,side):
    r=copy.deepcopy(m.load_review())
    row=next(row for row in r["stages"] if row["id"]==name)
    assert predecessor in row[side+"_predecessors"]
    row[side+"_predecessors"].remove(predecessor)
    with pytest.raises(ValueError,match="NOT READY"):check(review=r)

@pytest.mark.parametrize("name,output",[
 ("LLVM","usr/bin/llvm-tblgen"),
 ("LLVM","usr/share/licenses/llvm/BLAKE3-LICENSE"),
 ("Mesa","usr/share/licenses/mesa/glapi-generator-license.py"),
 ("Xvnc","usr/bin/vncpasswd"),
 ("i3","usr/bin/i3-nagbar"),
 ("xterm","usr/share/terminfo/x/xterm"),
 ("mesa-demos-smoke","usr/bin/glxgears"),
])
def test_installed_outputs_and_original_rights_notes_stay_required(name,output):
    r=copy.deepcopy(m.load_review())
    row=next(row for row in r["stages"] if row["id"]==name)
    assert output in row["required_installed_outputs"]
    row["required_installed_outputs"].remove(output)
    with pytest.raises(ValueError,match="NOT READY"):check(review=r)

def test_unmanifested_source_hold_reconciled_but_native_generator_hold_remains():
    r=copy.deepcopy(m.load_review())
    assert r["unmanifested_planned_outputs"]=={}
    r["unmanifested_planned_outputs"]={"LLVM":["usr/bin/llvm-tblgen"]}
    with pytest.raises(ValueError,match="NOT READY"):check(review=r)
    c=copy.deepcopy(m.load())
    c["successor_review"]["tablegen_generator_input_output_attestation"]={"passed":False}
    with pytest.raises(ValueError,match="NOT READY"):check(candidate=c)
