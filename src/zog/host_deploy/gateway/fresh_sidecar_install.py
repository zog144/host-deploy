"""Fixed host-owned controller sidecar; not an SSM or GitHub execution API.

Native caller must provide the separately authorized root-owned installation
backend, the exact installed-source attestation and a retained old-state
readback. This module never writes systemd unit files or reloads PID1.
"""
import hashlib
import json
import os
from pathlib import PurePosixPath

from .fresh_quota_volume import MOUNT as BUILD_MOUNT
from .compiler_execution_identity import (
    FRESH_ROOT_CONTROL_REVISION, FRESH_SCHEMA, validate,
)

SCHEMA = "host-deploy-fresh-sidecar-install-v1"
ROLE = "build-only-project-v1"
UNIT = "zog-fresh-cross-bootstrap-oct25-controller.service"
SOCKET = "/run/zog/root-control-fresh-cross-bootstrap-oct25.sock"
PROJECT = "fresh-cross-bootstrap-oct25"
SLICE_UNIT = "zogfreshcrossbootstrapoct25.slice"
LOG_NAMESPACE = "zogfreshcrossbootstrapoct25"
REGISTRATION_SOURCE = str(BUILD_MOUNT / "controller-build-resources")
REGISTRATION_DEST = "/var/lib/zog/build-resources"
REQUIRED_ENV = frozenset({
    "ROOT_CONTROL_SOCKET", "ROOT_CONTROL_SOCKET_GID",
    "ROOT_CONTROL_CONTROLLER_UID", "ROOT_CONTROL_ROLE",
    "ROOT_CONTROL_AUTHORIZED_PROJECT", "PYTHONPATH",
    "PYTHONDONTWRITEBYTECODE",
})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def review_plan(binding, installed):
    """Freeze executable/environment and unit properties for trusted PID1 use.

    'installed' must be made by the independently trusted host installer.
    This function cannot attest bytes, ownership, NSS, or live PID1 itself.
    """
    if type(binding) is not dict or binding.get("schema") != FRESH_SCHEMA:
        raise ValueError("sidecar accepts fresh-only execution identity")
    value = validate(
        binding, project_root=binding["project_root"],
        python_executable=binding["python_executable"],
        source_revision=binding["source_revision"],
        build_record_revision=binding["build_record_revision"],
        box_control_revision=binding["box_control_revision"],
        task_identity=binding["task_catalogue_identity"],
    )
    if (value["socket_path"] != SOCKET
            or PurePosixPath(value["project_root"]).name != PROJECT):
        raise ValueError("sidecar identity is not the exact reviewed lane")
    if (type(installed) is not dict or set(installed) != {
            "root_control_revision", "root_control_tree_sha256",
            "root_control_python_root", "host_deploy_python_root",
            "host_deploy_tree_sha256", "python_executable",
            "installer_receipt_sha256", "host_id", "boot_id",
            "legacy_baseline_sha256", "reactivation_receipt_sha256",
            "watchdog_receipt_sha256"}):
        raise ValueError("missing immutable host-owned installer evidence")
    if installed["root_control_revision"] != FRESH_ROOT_CONTROL_REVISION:
        raise ValueError("sidecar executable source differs from reviewed role")
    for key in ("root_control_tree_sha256", "installer_receipt_sha256",
                "legacy_baseline_sha256", "reactivation_receipt_sha256",
                "watchdog_receipt_sha256", "host_deploy_tree_sha256"):
        if (type(installed[key]) is not str or len(installed[key]) != 71
                or not installed[key].startswith("sha256:")
                or any(c not in "0123456789abcdef" for c in installed[key][7:])):
            raise ValueError("sidecar host-owned evidence is not SHA-256 bound")
    for key in ("root_control_python_root", "host_deploy_python_root",
                "python_executable"):
        v = installed[key]
        if (type(v) is not str or not v.startswith("/")
                or str(PurePosixPath(v)) != v
                or ".." in v.split("/") or "\0" in v):
            raise ValueError("sidecar executable/source path unsafe")
    if installed["python_executable"] != value["python_executable"]:
        raise ValueError("sidecar Python interpreter differs from binding")
    for key in ("host_id", "boot_id"):
        v = installed[key]
        if type(v) is not str or not 1 <= len(v) <= 128 or any(
                ord(c) < 33 or ord(c) > 126 for c in v):
            raise ValueError("sidecar host/boot authority missing")
    environment = {
        "ROOT_CONTROL_SOCKET": SOCKET,
        "ROOT_CONTROL_SOCKET_GID": str(value["controller_gid"]),
        "ROOT_CONTROL_CONTROLLER_UID": str(value["controller_uid"]),
        "ROOT_CONTROL_ROLE": ROLE,
        "ROOT_CONTROL_AUTHORIZED_PROJECT": value["project_root"],
        "PYTHONPATH": installed["root_control_python_root"],
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if set(environment) != REQUIRED_ENV:
        raise ValueError("sidecar environment incomplete")
    properties = {
        "Description": "Zog isolated build-only root-control sidecar",
        "Type": "exec",
        "ExecStart": [
            installed["python_executable"], "-B", "-m", "zog.root_control"
        ],
        "Environment": [f"{k}={environment[k]}" for k in sorted(environment)],
        "User": "0", "Group": "0", "Slice": SLICE_UNIT,
        # A kernel cgroup.kill must never resurrect this privileged sidecar
        # and create more privileged build operations after budget expiry.
        # Restart/reboot always requires an independently reviewed new grant.
        "Restart": "no", "RestartSec": "0s",
        "StartLimitBurst": 1, "StartLimitIntervalSec": "60s",
        "StandardOutput": "journal", "StandardError": "journal",
        "LogNamespace": LOG_NAMESPACE,
        # Full imported worker rootfs belongs in the 30-GiB build volume;
        # only this sidecar sees its root-owned registration directory.
        # No host-wide bind or modification of historical build-resources.
        "BindPaths": [[REGISTRATION_SOURCE, REGISTRATION_DEST, False, 0]],
        "NoNewPrivileges": True,
    }
    # Do not permit environment inheritance, ExecStartEx, daemon reload,
    # arbitrary commands, caller-selected policies or a shared listener.
    result = {"schema": SCHEMA, "unit": UNIT,
              "mode": "replace-irrelevant-only-if-absent",
              "role": ROLE, "host_id": installed["host_id"],
              "boot_id": installed["boot_id"],
              "project_root": value["project_root"],
              "controller_uid": value["controller_uid"],
              "controller_gid": value["controller_gid"],
              "socket": SOCKET,
              "root_control_revision": FRESH_ROOT_CONTROL_REVISION,
              "identity": value, "installed": installed.copy(),
              "properties": properties}
    result["sha256"] = "sha256:" + hashlib.sha256(_canonical(result)).hexdigest()
    return result


def install(plan, *, host_owner):
    """Single-shot protected backend installation. No remote shell fallback.

    host_owner is a trusted, root-only native installer interface implementing
    validate_old_baseline, verify_source_and_nss, read_unit, start_transient,
    and observe_unit. No caller may supply a command to this interface.
    """
    if os.geteuid() != 0:
        raise PermissionError("root-owned sidecar installer required")
    if (type(plan) is not dict or plan.get("schema") != SCHEMA
            or plan.get("unit") != UNIT or plan.get("socket") != SOCKET):
        raise ValueError("invalid fixed sidecar plan")
    raw = dict(plan)
    digest = raw.pop("sha256", None)
    if digest != "sha256:" + hashlib.sha256(_canonical(raw)).hexdigest():
        raise ValueError("sidecar plan digest invalid")
    # Reject mutation or startup even if the caller manufactured a digest.
    approved = review_plan(plan["identity"], plan["installed"])
    if approved != plan:
        raise ValueError("sidecar plan differs from reviewed identity")
    host_owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    host_owner.verify_source_and_nss(plan)
    if host_owner.read_unit(UNIT) is not None or host_owner.socket_exists(SOCKET):
        raise RuntimeError("fresh sidecar already exists; no implicit replacement")
    # The trusted installer must own a serialized durable transaction and
    # persist BOTH prepared identity and attempted PID1 start before D-Bus.
    # An uncertain reply must never create another service or new identity.
    preparation = host_owner.prepare_once(plan)
    if (type(preparation) is not dict
            or preparation.get("plan_sha256") != plan["sha256"]
            or preparation.get("state") != "prepared"
            or preparation.get("durable") is not True):
        raise RuntimeError("sidecar protected installation was not durably prepared")
    attempted = host_owner.mark_start_attempt(plan["sha256"])
    if (type(attempted) is not dict or attempted.get("state") != "attempted"
            or attempted.get("plan_sha256") != plan["sha256"]
            or attempted.get("durable") is not True):
        raise RuntimeError("sidecar attempted-start marker is not durable")
    # Host-side implementation must call PID1 StartTransientUnit with this
    # fixed property set and no daemon-reload or general shell.
    receipt = host_owner.start_transient(UNIT, "fail", plan["properties"])
    observed = host_owner.observe_unit(UNIT)
    if (type(receipt) is not dict or type(observed) is not dict
            or not observed.get("active")
            or not observed.get("invocation_id")
            or observed.get("unit") != UNIT
            or observed.get("project_root") != plan["project_root"]
            or observed.get("socket") != SOCKET
            or observed.get("role") != ROLE):
        raise RuntimeError("sidecar started but authenticated activation is unproven")
    host_owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    return {"schema": SCHEMA, "plan_sha256": plan["sha256"],
            "unit": UNIT, "boot_id": plan["boot_id"],
            "invocation_id": observed["invocation_id"],
            "native_receipt": receipt}
