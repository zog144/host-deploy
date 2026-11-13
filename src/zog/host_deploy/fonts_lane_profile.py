"""Source-owned first-Fonts managed lane: read-only host verification, then local preparation.

The profile is not a compiler-base receipt, a worker quota, or permission to submit.
The only deployment-specific inputs come from a root-owned *remote* controller
configuration observed through the workspace-selected Host, and are snapshotted
in the owner workspace by the separate explicit verify command. Preparation
never contacts the Host. No caller can supply a replacement lane specification.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import time

from . import image_build_lanes as lanes
from .gateway import fonts_lane_review
from .gateway import graphics_catalogue_owner as fonts
from .provision import configuration
from .workspace import load, locked, save

PROFILE = "host-deploy-first-fonts-managed-lane-v2"
REMOTE_CONFIG_SCHEMA = "host-deploy-first-fonts-controller-facts-v1"
FACTS_SCHEMA = "host-deploy-verified-first-fonts-facts-v1"
LANE = "gateway-first-fonts-runtime"
PROJECT_ROOT = str(lanes.DEFAULT_ROOT / LANE)
REMOTE_CONFIG = "/etc/zog/first-fonts-controller-facts-v1.json"
FACTS_FILE = "first-fonts-verified-facts-v1.json"
FACTS_MAX_AGE_SECONDS = 3600
COMPANION_REVISION = "a866c9c4b0dd385045f00ce2de7d809f5b67c104"
_CONTROLLER = {
    "socket_path", "execution_user_id", "execution_group_id",
    "startup_timeout_seconds", "execution_timeout_seconds",
    "termination_grace_seconds", "wait_timeout_seconds",
    "transport_timeout_seconds",
}
_POLICY = {
    "memory_maximum_bytes", "thread_count_maximum", "cpu_weight",
    "disk_reservation_bytes",
}
_REMOTE_KEYS = {
    "schema", "workspace_id", "account_id", "region", "instance_id",
    "provenance_host_id", "provenance_project_id", "observed_state_dir",
    "python_executable", "controller", "resource_policy",
}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _read_regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("expected regular, nonsymlinked workspace evidence: " + str(path))
    return json.loads(path.read_text())


def _owner(directory):
    # Workspace identity and host binding are trusted only from the existing
    # workspace files. No caller-supplied Host/Project ID overrides are used.
    workspace, host = configuration(directory)
    if (not isinstance(host, dict)
            or not isinstance(host.get("workspace_id"), str)
            or not isinstance(host.get("instance_id"), str)
            or not re.fullmatch(r"i-[0-9a-f]{8,17}", host["instance_id"])
            or not re.fullmatch(r"[0-9]{12}", host.get("account_id", ""))
            or host.get("region") != workspace["region"]
            or host["workspace_id"] != workspace["workspace_id"]):
        raise RuntimeError("first Fonts requires a verified, workspace-owned compiler Host")
    return workspace, host


def _binding(workspace, host):
    return {key: value for key, value in (
        ("workspace_id", workspace["workspace_id"]),
        ("account_id", host["account_id"]),
        ("region", host["region"]),
        ("instance_id", host["instance_id"]),
    )}


def _absolute(value):
    if type(value) is not str or not value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return (str(path) == value and
            all(p not in ("", ".", "..") for p in value.split("/")[1:]) and
            all(33 <= ord(c) != 127 for c in value))


def validate_remote_facts(value, workspace, host):
    """Reject unsupported profile overrides and mismatched compiler identities."""
    if type(value) is not dict or set(value) != _REMOTE_KEYS or value.get("schema") != REMOTE_CONFIG_SCHEMA:
        raise ValueError("invalid first Fonts controller facts schema")
    for key, expected in _binding(workspace, host).items():
        if value[key] != expected:
            raise ValueError("first Fonts controller facts mismatch selected Host: " + key)
    for key in ("provenance_host_id", "provenance_project_id"):
        if type(value[key]) is not str or not _ID.fullmatch(value[key]):
            raise ValueError("invalid first Fonts " + key)
    if value["provenance_host_id"] == value["provenance_project_id"]:
        raise ValueError("first Fonts Host and Project identities must be distinct")
    observed = value["observed_state_dir"]
    if observed is not None and (not _absolute(observed) or observed == PROJECT_ROOT + "/state"):
        raise ValueError("invalid first Fonts observed state directory")
    lanes.validate_python_executable(value["python_executable"])
    if type(value["resource_policy"]) is not dict or set(value["resource_policy"]) != _POLICY:
        raise ValueError("invalid first Fonts resource policy")
    if type(value["controller"]) is not dict or set(value["controller"]) != _CONTROLLER:
        raise ValueError("invalid first Fonts controller policy")
    if not _absolute(value["controller"]["socket_path"]):
        raise ValueError("first Fonts controller socket must be normalized absolute")
    # Full schema validation includes finite timeouts, UID/GID bounds, and exact source.
    spec = _spec(value)
    lanes.validate(spec)
    return json.loads(_canonical(value))


def _spec(facts):
    controller, policy = facts["controller"], facts["resource_policy"]
    return lanes.specification(
        LANE, mode="managed", project_root=PROJECT_ROOT,
        source_repository=fonts.REPOSITORY, source_revision=fonts.SOURCE,
        monthly_pin_repository_path=fonts.PIN_PATH,
        monthly_pin_identity="sha256:" + fonts.PIN_SHA256,
        provenance_host_id=facts["provenance_host_id"],
        provenance_project_id=facts["provenance_project_id"],
        observed_state_dir=facts["observed_state_dir"],
        python_executable=facts["python_executable"],
        **policy, **controller,
    )


def profile():
    """The reviewed source selection, not an operator-supplied lane JSON."""
    if (fonts.SOURCE != lanes.FIRST_FONTS_PRODUCER_REVISION
            or lanes.expected_build_record_revision(fonts.SOURCE) != COMPANION_REVISION):
        raise RuntimeError("first Fonts producer/companion source review differs")
    return {
        "schema": PROFILE, "lane": LANE, "project_root": PROJECT_ROOT,
        "source_repository": fonts.REPOSITORY, "source_revision": fonts.SOURCE,
        "monthly_pin_repository_path": fonts.PIN_PATH,
        "monthly_pin_identity": "sha256:" + fonts.PIN_SHA256,
        "build_record_revision": COMPANION_REVISION,
        "remote_configuration": REMOTE_CONFIG,
    }


def _probe_script():
    """Run only in the explicit verification phase, never in prepare()."""
    # A root-owned config is in the selected trusted Host's local trust boundary.
    # Check kernel file ownership and runtime objects, not just an operator's JSON.
    code = r'''
import grp, json, os, pwd, stat
from pathlib import Path
p = Path(CONFIG_PATH)
fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('controller facts must be root-owned, regular and not group/world writable')
    with os.fdopen(fd) as stream:
        fd = -1
        facts = json.load(stream)
finally:
    if fd >= 0:
        os.close(fd)
if not isinstance(facts, dict):
    raise RuntimeError('invalid controller facts')
controller = facts.get('controller')
if not isinstance(controller, dict):
    raise RuntimeError('missing controller facts')
socket = controller.get('socket_path')
if not isinstance(socket, str) or not socket.startswith('/') or not stat.S_ISSOCK(os.lstat(socket).st_mode):
    raise RuntimeError('controller socket is not present')
uid = controller.get('execution_user_id')
gid = controller.get('execution_group_id')
if type(uid) is not int or uid <= 0 or pwd.getpwuid(uid).pw_uid != uid:
    raise RuntimeError('controller execution user is not present')
if type(gid) is not int or gid <= 0 or grp.getgrgid(gid).gr_gid != gid:
    raise RuntimeError('controller execution group is not present')
python = facts.get('python_executable')
if not isinstance(python, str) or not python.startswith('/') or not os.access(python, os.X_OK):
    raise RuntimeError('reviewed Python executable is not usable')
observed = facts.get('observed_state_dir')
if observed is not None and (not isinstance(observed, str) or not os.path.isdir(observed)):
    raise RuntimeError('observed-state directory does not exist')
print(json.dumps(facts, sort_keys=True))
'''
    return "python3 -c " + shlex.quote("CONFIG_PATH=" + repr(REMOTE_CONFIG) + "\n" + code)


def verify(directory, *, now=None):
    """Explicit live read-only Host verification; saves ONLY local trusted evidence.

    This operation may use AWS SSM to read the workspace-selected running Host.
    It never prepares/activates a lane, writes a remote file or sends compilation.
    """
    profile()
    with locked(directory) as root:
        workspace, host = _owner(root)
        # Imported lazily: preparation has no path that instantiates Host.
        from .runner import Host
        result = Host(host).command(_probe_script())
        try:
            facts = validate_remote_facts(json.loads(result), workspace, host)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("invalid observed first Fonts runtime facts") from exc
        stamped = int(time.time() if now is None else now)
        evidence = {
            "schema": FACTS_SCHEMA,
            "profile": PROFILE,
            "binding": _binding(workspace, host),
            "captured_at": stamped,
            "facts": facts,
            "facts_sha256": _digest(facts),
        }
        save(root / FACTS_FILE, evidence)
        return {"profile": profile(), "verified_facts_sha256": evidence["facts_sha256"],
                "captured_at": stamped, "workspace": str(root)}


def _verified(root, workspace, host, *, now=None):
    evidence = _read_regular(root / FACTS_FILE)
    if (type(evidence) is not dict
            or set(evidence) != {"schema", "profile", "binding", "captured_at", "facts", "facts_sha256"}
            or evidence["schema"] != FACTS_SCHEMA or evidence["profile"] != PROFILE
            or evidence["binding"] != _binding(workspace, host)
            or type(evidence["captured_at"]) is not int):
        raise RuntimeError("missing or mismatched verified first Fonts Host evidence")
    age = int(time.time() if now is None else now) - evidence["captured_at"]
    if not 0 <= age <= FACTS_MAX_AGE_SECONDS:
        raise RuntimeError("first Fonts Host/controller verification is stale")
    facts = validate_remote_facts(evidence["facts"], workspace, host)
    if evidence["facts_sha256"] != _digest(facts):
        raise RuntimeError("first Fonts Host evidence hash mismatch")
    return facts, evidence["facts_sha256"]


def _retained(root):
    """Read *every* record, not only active records, fail closed on corrupt history."""
    directory = root / "image-build-lanes"
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise RuntimeError("unsafe retained lane directory")
    records = []
    for path in sorted(directory.glob("*.json")):
        record = _read_regular(path)
        if (not isinstance(record, dict)
                or record.get("lane") != path.stem
                or record.get("schema") not in lanes._RECORD_SCHEMAS
                or record.get("state") not in {"prepared", "active", "retired"}):
            raise RuntimeError("invalid retained image-build lane history")
        validated = lanes.validate(record.get("specification"))
        if validated["lane"] != path.stem or validated["schema"] != record["schema"]:
            raise RuntimeError("inconsistent retained image-build lane identity")
        records.append(record)
    return records


def prepare(directory, *, now=None):
    """Prepare one immutable source-owned lane in the existing local workspace.

    No Host, AWS, SSM, controller or catalogue calls occur in this function.
    """
    reviewed = profile()
    with locked(directory) as root:
        workspace, host = _owner(root)
        facts, facts_sha = _verified(root, workspace, host, now=now)
        spec = _spec(facts)
        digest = lanes.specification_sha256(spec)
        metadata = {"schema": PROFILE, "profile_sha256": _digest(reviewed),
                    "build_record_revision": COMPANION_REVISION,
                    "specification_sha256": digest, "verified_facts_sha256": facts_sha,
                    "binding": _binding(workspace, host)}
        records = _retained(root)
        matching = [record for record in records if record["lane"] == LANE]
        if matching:
            existing = matching[0]
            if (existing["state"] != "prepared"
                    or existing["specification"] != spec
                    or existing.get("fonts_lane_profile") != metadata):
                raise RuntimeError("existing first Fonts lane differs; new review required")
            # Reject conflicts that appeared since first preparation.
            other = [record for record in records if record["lane"] != LANE]
            if fonts_lane_review.review(other, spec)["status"] != "DISTINCT_LANE_PROPOSAL_NOT_PREPARED":
                raise RuntimeError("first Fonts lane no longer has unique identity")
            return existing
        result = fonts_lane_review.review(records, spec)
        if result["status"] != "DISTINCT_LANE_PROPOSAL_NOT_PREPARED" or result["specification_sha256"] != digest:
            raise RuntimeError("reviewed first Fonts profile is not a distinct lane")
        path = lanes._path(root, LANE)
        record = {"schema": lanes.SCHEMA, "lane": LANE,
                  "specification": spec, "state": "prepared", "fonts_lane_profile": metadata}
        save(path, record)
        return record


def validate_activation(root, record, spec, workspace, host, *, expected_specification_sha256):
    """Called under image_build_lanes.activate's workspace lock, before Host use."""
    reviewed = profile()
    if (record.get("lane") != LANE or record.get("state") != "prepared"
            or spec["schema"] != lanes.SCHEMA or spec["mode"] != "managed"):
        raise RuntimeError("first Fonts activation requires the prepared reviewed lane")
    binding = _binding(workspace, host)
    facts, facts_sha = _verified(root, workspace, host)
    exact = _spec(facts)
    digest = lanes.specification_sha256(spec)
    if (expected_specification_sha256 != digest
            or spec != exact
            or record.get("fonts_lane_profile") != {
                "schema": PROFILE, "profile_sha256": _digest(reviewed),
                "build_record_revision": COMPANION_REVISION,
                "specification_sha256": digest, "verified_facts_sha256": facts_sha,
                "binding": binding,
            }):
        raise RuntimeError("first Fonts activation differs from verified prepared digest/Host")
    retained = _retained(root)
    others = [r for r in retained if r["lane"] != LANE]
    if fonts_lane_review.review(others, spec)["status"] != "DISTINCT_LANE_PROPOSAL_NOT_PREPARED":
        raise RuntimeError("first Fonts activation has competing lane identity")
    return reviewed
