"""Non-dispatching verifier for the *held* future graphical proposal.

This file is a review tool, NOT a gateway loader, issuer, task catalogue
adapter, or worker. Its only positive result is HELD_NOT_SUBMITTABLE.
No code path here can construct, install, select, authorize or submit a task.
"""
import ast
import json
from pathlib import Path
import re
import subprocess

SCHEMA = "zog-held-graphical-extension-proposal-v1"
STAGE_DAG_PATHS = {
    "Xvnc": "project/graphics-first-workspace/turbovnc-draft/stages/final/dependencies.py",
    "i3": "project/package/i3/stages/final/dependencies.py",
    "xterm": "project/package/xterm/stages/final/dependencies.py",
}
MIN_RESOURCES = {
    "LLVM": {"usr/lib/libLLVM.so", "usr/bin/llvm-tblgen"},
    "Mesa": {"usr/lib/libGL.so", "usr/lib/dri/swrast_dri.so"},
    "Xvnc": {"usr/bin/Xvnc", "usr/share/X11/xkb", "usr/bin/xkbcomp",
             "usr/share/fonts/X11/misc/6x13.pcf.gz",
             "usr/share/fonts/X11/misc/fonts.dir",
             "usr/lib/libGL.so", "usr/lib/dri/swrast_dri.so",
             "usr/share/licenses/turbovnc/Xserver-COPYING",
             "usr/share/licenses/turbovnc/libsha1-COPYING"},
    "i3": {"usr/bin/i3", "usr/bin/i3bar", "usr/bin/i3-msg",
           "usr/share/X11/xkb", "usr/share/licenses/i3/LICENSE"},
    "xterm": {"usr/bin/xterm", "usr/bin/luit",
              "usr/share/terminfo/x/xterm",
              "usr/share/X11/app-defaults/XTerm",
              "usr/share/fonts/X11/misc/6x13.pcf.gz",
              "usr/share/licenses/xterm/COPYING"},
    "mesa-demos-smoke": {"usr/bin/glxgears", "usr/bin/glxinfo",
                         "usr/lib/dri/swrast_dri.so"},
}
FROZEN_STAGE_DEPENDENCIES = {
  "Xvnc": {
    "build": [
      "libjpeg-turbo-final",
      "pixman-final",
      "xkeyboard-config-final",
      "libX11-final",
      "libXau-final",
      "libXdmcp-final",
      "libxkbfile-final",
      "libXfont2-final",
      "mesa-final",
      "openssl-final",
      "zlib-native-environment",
      "libXext-final",
      "libXrender-final",
      "xorgproto-final",
      "xkbcomp-final"
    ],
    "runtime": [
      "libjpeg-turbo-final",
      "pixman-final",
      "xkeyboard-config-final",
      "libX11-final",
      "libXau-final",
      "libXdmcp-final",
      "libxkbfile-final",
      "libXfont2-final",
      "mesa-final",
      "openssl-final",
      "zlib-native-environment",
      "libXext-final",
      "libXrender-final",
      "xorgproto-final",
      "xkbcomp-final"
    ]
  },
  "i3": {
    "build": [
      "libev-final",
      "yajl-final",
      "startup-notification-final",
      "libxkbcommon-final",
      "xkeyboard-config-final",
      "libX11-final",
      "libxcb-final",
      "xcb-util-final",
      "xcb-util-wm-final",
      "xcb-util-cursor-final",
      "xcb-util-keysyms-final",
      "xcb-util-xrm-final",
      "glib-final",
      "cairo-final",
      "pango-final",
      "pcre2-final"
    ],
    "runtime": [
      "libev-final",
      "yajl-final",
      "startup-notification-final",
      "libxkbcommon-final",
      "xkeyboard-config-final",
      "libX11-final",
      "libxcb-final",
      "xcb-util-final",
      "xcb-util-wm-final",
      "xcb-util-cursor-final",
      "xcb-util-keysyms-final",
      "xcb-util-xrm-final",
      "glib-final",
      "cairo-final",
      "pango-final",
      "pcre2-final"
    ]
  },
  "xterm": {
    "build": [
      "libXt-final",
      "libXaw-final",
      "libXmu-final",
      "libXpm-final",
      "libXft-final",
      "ncurses-temporary"
    ],
    "runtime": [
      "libXt-final",
      "libXaw-final",
      "libXmu-final",
      "libXpm-final",
      "libXft-final",
      "ncurses-temporary",
      "luit-final",
      "basic-font-final"
    ]
  }
}
REQUIRED_SOURCE_DEPENDENCIES = {
    "Xvnc": {"xkbcomp-final", "xkeyboard-config-final", "mesa-final",
             "openssl-final", "zlib-native-environment", "pixman-final",
             "libjpeg-turbo-final"},
    "i3": {"libev-final", "yajl-final", "startup-notification-final",
           "libxkbcommon-final", "xkeyboard-config-final",
           "xcb-util-cursor-final", "xcb-util-xrm-final",
           "glib-final", "cairo-final", "pango-final"},
    "xterm": {"libXt-final", "libXaw-final", "libXmu-final", "libXpm-final",
              "libXft-final", "ncurses-temporary", "luit-final",
              "basic-font-final"},
}

STATUS = "HELD_NOT_SUBMITTABLE"
STAGES = ("LLVM", "Mesa", "Xvnc", "i3", "xterm", "mesa-demos-smoke")
PR9 = "a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023"
PR9_REVIEWED_INPUT = "db13d73a45f8a3be579226656442c331a9f701ea"
MESA = "9cbd652226b863a7b4bb2d6d9539722e1a262508"
SELECTED_COMPILER = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
MONTHLY_PIN = ("sha256:"
               "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36")
RECEIPT_SLOTS = (
    "accepted_toolchain", "fonts", "XCB", "X11", "zlib_native_environment",
    "ncurses_temporary", "LLVM", "Mesa", "Xvnc", "i3", "xterm", "mesa_demos",
)
_STAGE_SOURCE = {
    "LLVM": "mesa_pr8_candidate_revision",
    "Mesa": "mesa_pr8_candidate_revision",
    "Xvnc": "workspace_pr9_candidate_revision",
    "i3": "workspace_pr9_candidate_revision",
    "xterm": "workspace_pr9_candidate_revision",
    "mesa-demos-smoke": "mesa_pr8_candidate_revision",
}
_PROPOSAL = (Path(__file__).resolve().parents[1] /
             "project/held-graphical-catalogue/workspace-next-v1.json")


class HeldProposalRejected(ValueError):
    pass


def _deny(message):
    raise HeldProposalRejected(message)


def load_proposal():
    return json.loads(_PROPOSAL.read_bytes())


def _exact(value, fields, desc):
    if type(value) is not dict or set(value) != set(fields):
        _deny(desc + " has missing or unreviewed fields")


def validate(proposal):
    """Validate review-only source metadata; NEVER returns submission permission."""
    from zog.host_deploy.gateway import (
        protocol, task_catalogue, graphics_generation_chain as chain,
        graphics_catalogue_owner as installed)
    _exact(proposal, (
        "schema", "status", "purpose", "candidate_revision", "producer",
        "authority", "required_predecessor_receipts", "rights", "execution",
        "stage_order", "smoke", "required_package_stage_receipts"
    ), "proposal")
    if (proposal["schema"] != SCHEMA or proposal["status"] != STATUS
            or proposal["candidate_revision"] != "2026-11-03"):
        _deny("not held at reviewed version")
    p = proposal["producer"]
    _exact(p, (
        "repository", "workspace_pr9_candidate_revision",
        "workspace_pr9_reviewed_input_revision", "mesa_pr8_candidate_revision",
        "current_protected_selected_revision",
        "current_protected_monthly_pin", "workspace_handoff_path",
        "closure_path", "original_rights_matrix_path", "unresolved_rights_path",
        "stage_dependency_sources"
    ), "producer")
    if p != {
        "repository": "zog144/image-build",
        "workspace_pr9_candidate_revision": PR9,
        "workspace_pr9_reviewed_input_revision": PR9_REVIEWED_INPUT,
        "mesa_pr8_candidate_revision": MESA,
        "current_protected_selected_revision": SELECTED_COMPILER,
        "current_protected_monthly_pin": MONTHLY_PIN,
        "workspace_handoff_path":
            "project/graphics-first-workspace/source-to-native-handoff.json",
        "closure_path": "project/graphics-first-workspace/closure.json",
        "original_rights_matrix_path":
            "project/graphics-first-workspace/selected-component-rights-handoff.json",
        "unresolved_rights_path":
            "project/graphics-first-workspace/remaining-distribution-evidence-2026-11-03.json",
        "stage_dependency_sources": STAGE_DAG_PATHS,
    }:
        _deny("revision, source-rights, or live compiler pin substituted")
    if installed.SOURCE != SELECTED_COMPILER or (
            "sha256:" + installed.PIN_SHA256 != MONTHLY_PIN):
        _deny("current protected selected source unexpectedly changed")
    expected_active = {
        "graphics-fonts-image-v1", "graphics-xcb-core-image-v1",
        "graphics-x11-core-image-v1", "xcb-support-image-v1",
    }
    if (set(protocol.BUILD_TASKS) != expected_active
            or set(task_catalogue.REVIEWED_IMAGE_TASKS) != expected_active
            or tuple(chain.TASKS) != (
                "graphics-fonts-image-v1", "graphics-xcb-core-image-v1",
                "graphics-x11-core-image-v1")):
        _deny("active graphical authority changed")
    auth = proposal["authority"]
    _exact(auth, (
        "active_catalogue_unchanged", "activation_allowed",
        "build_submission_allowed", "installer_selection_allowed",
        "task_allowlist_extension_allowed", "canonical_promotion_allowed",
        "installed_authority_epoch", "independently_signed_current_checkpoint",
        "protected_operator_approval", "protected_installer_receipt",
        "original_request_history", "protected_send_once_highwater",
    ), "authority")
    if auth["active_catalogue_unchanged"] is not True or any(
        auth[k] is not False for k in (
            "activation_allowed", "build_submission_allowed",
            "installer_selection_allowed", "task_allowlist_extension_allowed",
            "canonical_promotion_allowed")
    ) or any(auth[k] is not None for k in (
        "installed_authority_epoch", "independently_signed_current_checkpoint",
        "protected_operator_approval", "protected_installer_receipt",
        "original_request_history", "protected_send_once_highwater")
    ):
        _deny("future proposal is being treated as current authority")
    receipts = proposal["required_predecessor_receipts"]
    _exact(receipts, RECEIPT_SLOTS, "accepted predecessor receipts")
    if any(receipts[k] is not None for k in RECEIPT_SLOTS):
        _deny("source proposal fabricated an accepted generation")
    rights = proposal["rights"]
    _exact(rights, (
        "original_archive_notice_inventory", "rights_holder_authorized",
        "compiled_object_mapping_accepted",
        "native_installed_notice_sha256_accepted", "evidence_source_revision",
        "independently_approved_rights_receipt", "hold_reason",
    ), "rights")
    if (rights["original_archive_notice_inventory"] !=
                "SOURCE_HASHES_ONLY_NOT_LICENSE_GRANT"
            or rights["rights_holder_authorized"] is not False
            or rights["compiled_object_mapping_accepted"] is not False
            or rights["native_installed_notice_sha256_accepted"] is not False
            or rights["independently_approved_rights_receipt"] is not None
            or rights["evidence_source_revision"] != PR9
            or not rights["hold_reason"]):
        _deny("unapproved source notices used as distribution grant")
    execution = proposal["execution"]
    _exact(execution, (
        "workers_authorized", "lane", "lane_owner", "host_id",
        "installation_id", "state_volume_id", "task_catalogue_sha256",
        "monotonic_epoch", "reserved_work_bytes", "reserved_external_bytes",
        "max_cpu_seconds", "actual_reservation_approved", "note",
    ), "execution")
    if (execution["workers_authorized"] is not False
            or execution["actual_reservation_approved"] is not False
            or any(execution[k] is not None for k in (
                "lane", "lane_owner", "host_id", "installation_id",
                "state_volume_id", "task_catalogue_sha256", "monotonic_epoch"))
            or execution["reserved_work_bytes"] != 30 * 1024**3
            or execution["reserved_external_bytes"] != 2 * 1024**3
            or execution["max_cpu_seconds"] != 21600):
        _deny("not an approved worker allocation")
    stages = proposal["stage_order"]
    if type(stages) is not list or [s.get("id") for s in stages if type(s) is dict] != list(STAGES):
        _deny("future graphical ordering changed")
    for index, stage in enumerate(stages):
        _exact(stage, (
            "id", "source", "depends_on", "requires_receipts", "recipe_path",
            "recipe_status", "outputs", "accepted_generation_receipt",
            "build_package_stages", "runtime_package_stages",
            "required_installed_resources",
        ), "future stage")
        if (stage["source"] != _STAGE_SOURCE[stage["id"]]
                or stage["accepted_generation_receipt"] is not None
                or type(stage["depends_on"]) is not list
                or len(set(stage["depends_on"])) != len(stage["depends_on"])
                or any(dep not in STAGES[:index] for dep in stage["depends_on"])
                or type(stage["requires_receipts"]) is not list
                or not stage["requires_receipts"]
                or any(key not in RECEIPT_SLOTS
                       for key in stage["requires_receipts"])
                or type(stage["outputs"]) is not list
                or not stage["outputs"]
                or any(type(v) is not str or
                       not v.startswith("usr/") for v in stage["outputs"])):
            _deny("future stage or prior-generation evidence not held")
        if (type(stage["build_package_stages"]) is not list
                or type(stage["runtime_package_stages"]) is not list
                or type(stage["required_installed_resources"]) is not list
                or not MIN_RESOURCES[stage["id"]].issubset(
                    set(stage["required_installed_resources"]))
                or len(stage["required_installed_resources"]) != len(
                    set(stage["required_installed_resources"]))
                or any(type(x) is not str or not x.startswith("usr/")
                       for x in stage["required_installed_resources"])):
            _deny("missing native graphical resource or evidence")
        for dep_list in (stage["build_package_stages"],
                         stage["runtime_package_stages"]):
            if (len(dep_list) != len(set(dep_list))
                    or any(type(x) is not str or not
                           (x.endswith("-final") or x in (
                               "zlib-native-environment","ncurses-temporary"))
                           for x in dep_list)):
                _deny("unreviewed package-stage graph")
        if stage["id"] in STAGE_DAG_PATHS:
            frozen = FROZEN_STAGE_DEPENDENCIES[stage["id"]]
            if (stage["build_package_stages"] != frozen["build"] or
                    stage["runtime_package_stages"] != frozen["runtime"]):
                _deny("pinned source package stage DAG differs from review")
            if (stage["recipe_path"] != STAGE_DAG_PATHS[stage["id"]]
                    or not REQUIRED_SOURCE_DEPENDENCIES[stage["id"]].issubset(
                        set(stage["build_package_stages"]) |
                        set(stage["runtime_package_stages"]))):
                _deny("missing source-package predecessor")
        elif stage["build_package_stages"] or stage["runtime_package_stages"]:
            _deny("unaccepted LLVM/Mesa stage represented as compiled")
        if stage["recipe_path"] is not None and (
                not isinstance(stage["recipe_path"], str)
                or not stage["recipe_path"].startswith("project/")
                or ".." in Path(stage["recipe_path"]).parts):
            _deny("unsafe or invented recipe origin")
        if stage["recipe_status"] not in (
                "SOURCE_PLAN_NOT_CANONICAL", "DRAFT_NOT_PACKAGE_ADMITTED",
                "SOURCE_AUTHORED_NATIVE_HELD"):
            _deny("source-only recipe was promoted")
    package_receipts = proposal["required_package_stage_receipts"]
    all_package_ids = {d for stage in stages for d in (
        stage["build_package_stages"] + stage["runtime_package_stages"])}
    if (type(package_receipts) is not dict or
            set(package_receipts) != all_package_ids or
            any(v is not None for v in package_receipts.values())):
        _deny("missing or fabricated protected package-stage acceptance")
    if (stages[0]["recipe_path"] is not None
            or stages[1]["recipe_path"] is not None
            or stages[-1]["recipe_path"] is not None
            or stages[2]["depends_on"] != ["Mesa"]
            or stages[-1]["depends_on"] != ["Mesa", "Xvnc", "i3", "xterm"]):
        _deny("unknown Mesa/Xvnc/smoke closure")
    smoke = proposal["smoke"]
    _exact(smoke, (
        "type", "action", "command_candidate",
        "optional_diagnostic_candidate", "render_mode", "duration_seconds",
        "fps_threshold", "run_authorized", "result_receipt",
    ), "smoke")
    if (smoke["type"] != "NO_FPS_THRESHOLD_SOFTWARE_GLX"
            or smoke["run_authorized"] is not False
            or smoke["duration_seconds"] is not None
            or smoke["fps_threshold"] is not None
            or smoke["result_receipt"] is not None
            or smoke["command_candidate"] != "/usr/bin/glxgears"
            or smoke["optional_diagnostic_candidate"] != "/usr/bin/glxinfo -B"):
        _deny("smoke proposal is not a held, narrow CPU software test")
    return STATUS


def attest_source_checkouts(proposal, pr9_checkout, mesa_checkout):
    """Cross-compare immutable GitHub checkouts; read-only, still HELD."""
    if validate(proposal) != STATUS:
        _deny("unexpected validator result")
    p = proposal["producer"]
    for source, sha in (
        (pr9_checkout, PR9), (mesa_checkout, MESA),
    ):
        root = Path(source).resolve(strict=True)
        actual = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            text=True).strip()
        if actual != sha:
            _deny("moving or stale image-build source checkout")
    root = Path(pr9_checkout).resolve(strict=True)
    handoff = json.loads((root / p["workspace_handoff_path"]).read_bytes())
    closure = json.loads((root / p["closure_path"]).read_bytes())
    rights = json.loads((root / p["original_rights_matrix_path"]).read_bytes())
    supplemental = json.loads((root / p["unresolved_rights_path"]).read_bytes())
    if (handoff.get("status") != "PREPARED_NOT_SUBMITTABLE"
            or handoff.get("build_submission_allowed") is not False
            or handoff.get("native_accepted") is not False
            or handoff.get("rights_authorized") is not False
            or handoff.get("canonical_promotion_allowed") is not False
            or handoff.get("source_revisions") != {
                "workspace_pr9_reviewed_input": PR9_REVIEWED_INPUT,
                "mesa_pr8": MESA,
            }
            or set(handoff.get("accepted_generation_receipts", {})) != {
                "fonts", "XCB", "X11", "zlib_native_environment",
                "ncurses_temporary", "LLVM", "Mesa",
            }
            or any(value is not None for value in
                   handoff["accepted_generation_receipts"].values())
            or closure.get("status") != "source-incomplete"
            or closure.get("build_submission_allowed") is not False
            or rights.get("independent_redistribution_approved") is not False
            or supplemental.get("redistribution_authorized") is not False):
        _deny("current source/rights handoff does not establish held boundary")
    for stage in proposal["stage_order"]:
        if stage["id"] in STAGE_DAG_PATHS:
            dep_path = root / STAGE_DAG_PATHS[stage["id"]]
            try:
                deps = ast.literal_eval(dep_path.read_text())
            except (OSError, ValueError, SyntaxError):
                _deny("actual source stage DAG missing")
            if (type(deps) is not dict or set(deps) != {"build", "runtime"}
                    or deps["build"] != stage["build_package_stages"]
                    or deps["runtime"] != stage["runtime_package_stages"]):
                _deny("held package-stage DAG differs from pinned image-build")
        path = stage["recipe_path"]
        if path is not None and not (root / path).is_file():
            _deny("source-pinned recipe draft path missing")
    return STATUS


def refuse_submission(proposal):
    """A good source proposal NEVER becomes an authorized task."""
    validate(proposal)
    _deny("HELD_NOT_SUBMITTABLE: requires independent native authority")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr9-checkout", required=True)
    ap.add_argument("--mesa-checkout", required=True)
    args = ap.parse_args()
    print(attest_source_checkouts(load_proposal(), args.pr9_checkout,
                                  args.mesa_checkout))
