"""Explicit, non-executing migration preview for the original Fonts lane.

The source-pinned image-build runtime still requires a caller-selected UID/GID.
This module may inspect and stage a corrected candidate, but must never
activate it or claim the old producer can execute the new contract.
"""
import copy
import json
from pathlib import Path, PurePosixPath

from . import fonts_lane_profile as fonts
from . import image_build_lanes as lanes
from .workspace import locked, save

SCHEMA = "host-deploy-first-fonts-inherited-execution-migration-v1"
FILE = "first-fonts-inherited-execution-migration-v1.json"


def _project_root(path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("candidate project root must be an absolute path")
    root = PurePosixPath(path)
    if (root == PurePosixPath("/") or str(root) != path
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
            or root.name != fonts.LANE):
        raise ValueError("candidate project root must be normalized and name the existing lane")
    if path == fonts.RETAINED_PROJECT_ROOT:
        raise ValueError("old build-owner project root is historical evidence, not a new execution location")
    return path


def preview(directory, *, project_root):
    """Derive a new digest without editing the original record or contacting SSM.

    The new controller omits UID/GID selectors. This is intentionally a
    migration *candidate*, not runnable while the pinned image-build source
    still requires those selectors. Runtime access must be verified by the
    actual executing process, not by this caller's local credentials.
    """
    project_root = _project_root(project_root)
    with locked(directory) as root:
        workspace, host = fonts._owner(root)
        original, old, old_digest = fonts._approved(root)
        for existing in fonts._retained(root):
            if existing["lane"] != fonts.LANE and existing["specification"]["project_root"] == project_root:
                raise RuntimeError("migration destination is owned by another retained lane")
        candidate = copy.deepcopy(old)
        candidate["schema"] = lanes.INHERITED_SCHEMA
        candidate["project_root"] = project_root
        candidate["controller"].pop("execution_user_id", None)
        candidate["controller"].pop("execution_group_id", None)
        candidate["controller"]["execution_identity"] = "inherit"
        candidate = lanes.validate(candidate)
        digest = lanes.specification_sha256(candidate)
        return {
            "schema": SCHEMA,
            "status": "review-required-not-executable",
            "binding": fonts._binding(workspace, host),
            "historical_record": str(lanes._path(root, fonts.LANE)),
            "historical_specification_sha256": old_digest,
            "historical_state": original["state"],
            "candidate_specification": candidate,
            "candidate_specification_sha256": digest,
            "execution_identity": "inherit-from-authenticated-executing-process",
            "access_verification": "required-in-actual-executing-process",
            "runtime_compatibility": "blocked-pinned-image-build-requires-uid-gid",
            "original_record_unchanged": True,
        }


def stage(directory, *, project_root):
    """Save an immutable review candidate; never migrate a prepared/active lane."""
    candidate = preview(directory, project_root=project_root)
    with locked(directory) as root:
        # Recheck the original record *under this write lock*. It may have
        # changed between the read-only preview and staging; never persist a
        # stale migration as though it were bound to the current workspace.
        workspace, host = fonts._owner(root)
        original, _, old_digest = fonts._approved(root)
        if (old_digest != candidate["historical_specification_sha256"]
                or original["state"] != candidate["historical_state"]
                or fonts._binding(workspace, host) != candidate["binding"]):
            raise RuntimeError("original first Fonts lane changed before migration staging")
        for other in fonts._retained(root):
            if (other["lane"] != fonts.LANE and
                    other["specification"]["project_root"] == candidate["candidate_specification"]["project_root"]):
                raise RuntimeError("migration destination became owned by another lane")
        path = Path(root) / FILE
        if path.is_symlink():
            raise RuntimeError("unsafe existing Fonts migration staging file")
        if path.exists():
            if not path.is_file() or json.loads(path.read_text()) != candidate:
                raise RuntimeError("Fonts migration is already staged with different inputs")
        else:
            save(path, candidate)
    return candidate
