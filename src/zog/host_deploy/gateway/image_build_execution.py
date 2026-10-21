"""Explicit SSM execution and observation for prepared image-build gateway dispatches.

The persistent SQS consumer does not call this module automatically.
"""

import base64
import hashlib
import json
from pathlib import Path
import re
import shlex

from ..runner import Host
from .. import image_build_lanes
from .compiler_execution_identity import validate as validate_execution_identity, IDENTITY_RUNTIME
from .image_build_dispatch import REMOTE_SCHEMA, verify_current_target
from .ledger import (
    load_dispatch,
    load_request,
    mark_completion,
    mark_dispatch_submitted,
    mark_dispatch_submitting,
    mark_dispatch_uncertain,
    record_dispatch_observation,
    record_remote_result,
    record_dispatch_runtime_preflight,
)


RECEIPT_SCHEMA = "host-deploy-image-build-receipt-v1"
CONTROL_TIMEOUT_SECONDS = 300
_MAX_REMOTE_STDIO = 1024 * 1024
_MAX_REMOTE_RESULT = 128 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _binding(record):
    if not isinstance(record, dict) or record.get("phase") not in {
        "prepared",
        "submitting",
        "submitted",
        "submission_uncertain",
    }:
        raise RuntimeError("gateway dispatch is not prepared")
    binding = record.get("binding")
    if not isinstance(binding, dict) or binding.get("kind") != REMOTE_SCHEMA:
        raise RuntimeError("gateway dispatch is not an image-build remote operation")
    required = {
        "schema",
        "kind",
        "request_id",
        "workspace_id",
        "lane",
        "target",
        "source",
        "monthly_pin_repository_path",
        "monthly_pin_identity",
        "observed_state_dir",
        "project_root",
        "source_root",
        "remote_request_path",
        "remote_result_path",
        "argv",
        "remote_request",
        "remote_request_sha256",
    }
    optional = {"task", "task_catalogue_identity", "controller_companion",
                "compiler_execution_identity"}
    if binding.get("schema") in {2, 3}:
        required.add("python_executable")
        image_build_lanes.validate_python_executable(binding.get("python_executable"))
    elif binding.get("schema") != 1:
        raise RuntimeError("unsupported gateway dispatch binding schema")
    if binding.get("schema") == 3:
        required.update({"runtime_companion", "runtime_profile"})
        companion = image_build_lanes.validate_runtime_companion(
            binding.get("runtime_companion"), project_root=binding["project_root"]
        )
        profile = binding.get("runtime_profile")
        selected_controller = binding.get("controller_companion")
        if selected_controller is not None:
            if "--controller-config" not in binding["argv"]:
                raise RuntimeError("controller companion requires managed controller")
            selected_controller = image_build_lanes.validate_controller_companion(
                selected_controller, project_root=binding["project_root"]
            )
            if selected_controller["producer_revision"] != binding["source"]["revision"]:
                raise RuntimeError("controller companion is bound to another producer")
        elif (binding["source"]["revision"] in (
                  image_build_lanes.TOOLCHAIN_PRODUCER_REVISION,
                  image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION)
              and "--controller-config" in binding["argv"]):
            raise RuntimeError("new producer requires explicit controller selection")
        if (binding["source"]["revision"] in (
                    image_build_lanes.TOOLCHAIN_PRODUCER_REVISION,
                    image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION)
                and companion["revision"] !=
                image_build_lanes.TOOLCHAIN_BUILD_RECORD_COMPATIBILITY):
            raise RuntimeError("new producer requires its exact build-record companion")
        expected_profile = {
            "schema": 1,
            "operation": binding["remote_request"]["operation"],
            "provenance": "--provenance-pin" in binding["argv"],
            "controller": "--controller-config" in binding["argv"],
            "external_observed_state": "--observed-state-dir" in binding["argv"],
            "controller_revision": (
                (selected_controller["revision"] if selected_controller is not None
                 else image_build_lanes.BOX_CONTROL_COMPATIBILITY)
                if "--controller-config" in binding["argv"] else None
            ),
            "controller_source_root": (
                binding["project_root"] + "/companions/box-control"
                if "--controller-config" in binding["argv"] else None
            ),
        }
        if profile != expected_profile:
            raise RuntimeError("unsupported image-build runtime profile")
        if companion["producer_revision"] != binding["source"]["revision"]:
            raise RuntimeError("runtime companion is bound to different producer")
    if binding.get("schema") != 3 and "controller_companion" in binding:
        raise RuntimeError("legacy dispatch cannot have controller companion")
    if "compiler_execution_identity" in binding:
        if (binding["schema"] != 3 or binding["source"]["revision"] !=
                image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION
                or "task" not in binding or "controller_companion" not in binding):
            raise RuntimeError("compiler nonroot identity is not bound to protected task")
        validate_execution_identity(
            binding["compiler_execution_identity"],
            project_root=binding["project_root"],
            python_executable=binding["python_executable"],
            source_revision=binding["source"]["revision"],
            build_record_revision=binding["runtime_companion"]["revision"],
            box_control_revision=binding["controller_companion"]["revision"],
            task_identity=binding["task_catalogue_identity"],
        )
    elif (binding.get("task")
          and binding["source"]["revision"] ==
          image_build_lanes.RESTORED_TOOLCHAIN_PRODUCER_REVISION):
        raise RuntimeError("restored toolchain requires nonroot execution identity")
    if set(binding) - required - optional or not required.issubset(binding):
        raise RuntimeError("image-build dispatch binding fields are invalid")
    if ("task" in binding) != ("task_catalogue_identity" in binding):
        raise RuntimeError("image-build task catalogue binding is incomplete")
    request = binding["remote_request"]
    encoded = _canonical(request)
    if (
        request.get("schema") != REMOTE_SCHEMA
        or request.get("operation_id") != binding["request_id"]
        or request.get("source") != binding["source"]
        or hashlib.sha256(encoded).hexdigest() != binding["remote_request_sha256"]
    ):
        raise RuntimeError("image-build remote request differs from dispatch binding")
    monthly_path = binding["monthly_pin_repository_path"]
    if (
        not isinstance(monthly_path, str)
        or not monthly_path
        or "\0" in monthly_path
    ):
        raise RuntimeError("image-build dispatch monthly pin path is invalid")
    monthly_parts = Path(monthly_path).parts
    if (
        Path(monthly_path).is_absolute()
        or not monthly_parts
        or any(part in {"", ".", ".."} for part in monthly_parts)
        or monthly_parts[0] == ".git"
    ):
        raise RuntimeError("image-build dispatch monthly pin path is unsafe")
    if (
        not isinstance(binding["monthly_pin_identity"], str)
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            binding["monthly_pin_identity"],
        )
    ):
        raise RuntimeError("image-build dispatch monthly pin identity is invalid")
    observed_state = binding["observed_state_dir"]
    if observed_state is not None:
        if (
            not isinstance(observed_state, str)
            or not observed_state
            or "\0" in observed_state
            or not Path(observed_state).is_absolute()
        ):
            raise RuntimeError("image-build dispatch observed state is invalid")
        if binding["remote_request"]["operation"] != "pipeline.inspect":
            raise RuntimeError("external observed state permits only pipeline.inspect")
    project_root = Path(binding["project_root"])
    source_root = Path(binding["source_root"])
    request_path = Path(binding["remote_request_path"])
    result_path = Path(binding["remote_result_path"])
    if (
        not project_root.is_absolute()
        or source_root != project_root / "source"
        or request_path
        != project_root / "gateway-requests" / binding["request_id"] / "request.json"
        or result_path
        != project_root / "gateway-requests" / binding["request_id"] / "result.json"
    ):
        raise RuntimeError("image-build dispatch remote paths are invalid")
    argv = binding["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or any(
            not isinstance(value, str)
            or not value
            or "\0" in value
            or len(value) > 8192
            for value in argv
        )
        or argv[-1] != str(request_path)
    ):
        raise RuntimeError("image-build dispatch argv is invalid")
    if binding["schema"] in {2, 3}:
        python_path = "PYTHONPATH=" + str(Path(binding["source_root"]) / "src")
        if binding["schema"] == 3:
            python_path += ":" + binding["runtime_companion"]["source_root"] + "/src"
            if binding["runtime_profile"]["controller"]:
                python_path += (
                    ":" + binding["runtime_profile"]["controller_source_root"]
                    + "/box-control/src"
                )
        if binding["argv"][:3] != [
            "env",
            python_path,
            binding["python_executable"],
        ]:
            raise RuntimeError("image-build producer interpreter differs from frozen runtime")
    return binding


_WRAPPER = r'''
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_STDIO = 1024 * 1024
MAX_RESULT = 128 * 1024

request_path = Path(sys.argv[1])
result_path = Path(sys.argv[2])
source_root = Path(sys.argv[3])
source_revision = sys.argv[4]
monthly_pin_repository_path = sys.argv[5]
monthly_pin_identity = sys.argv[6]
request_sha256 = sys.argv[7]
payload = base64.b64decode(sys.argv[8], validate=True)
identity = None
if len(sys.argv) > 9 and sys.argv[9].startswith("identity-v1:"):
    identity = json.loads(base64.b64decode(sys.argv[9].split(":", 1)[1], validate=True))
    argv = sys.argv[10:]
else:
    argv = sys.argv[9:]

def fail(message):
    raise SystemExit(message)

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != data:
            fail("retained gateway file differs from bound bytes")
        return
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

if hashlib.sha256(payload).hexdigest() != request_sha256:
    fail("gateway request payload hash mismatch")

head = subprocess.run(
    ["git", "-C", str(source_root), "rev-parse", "--verify", "HEAD"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=30,
)
if head.returncode or head.stdout.strip() != source_revision:
    fail("deployed image-build checkout revision differs from lane binding")
status = subprocess.run(
    ["git", "-C", str(source_root), "status", "--porcelain=v1", "--untracked-files=all"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=30,
)
if status.returncode or status.stdout:
    fail("deployed image-build checkout is not clean")

relative_pin = Path(monthly_pin_repository_path)
if (
    relative_pin.is_absolute()
    or not relative_pin.parts
    or any(part in ("", ".", "..") for part in relative_pin.parts)
    or relative_pin.parts[0] == ".git"
):
    fail("bound monthly provenance pin path is unsafe")
pin_path = source_root.joinpath(*relative_pin.parts)
current = source_root
for part in relative_pin.parts:
    current = current / part
    if current.is_symlink():
        fail("bound monthly provenance pin must not traverse a symlink")
try:
    resolved_root = source_root.resolve(strict=True)
    resolved_pin = pin_path.resolve(strict=True)
    resolved_pin.relative_to(resolved_root)
except (OSError, ValueError):
    fail("bound monthly provenance pin escapes deployed checkout")
if not resolved_pin.is_file():
    fail("bound monthly provenance pin is not a regular file")
try:
    pin_digest = hashlib.sha256(resolved_pin.read_bytes()).hexdigest()
except OSError:
    fail("deployed image-build monthly pin is unavailable")
if monthly_pin_identity != "sha256:" + pin_digest:
    fail("deployed monthly pin digest differs from lane binding")

atomic(request_path, payload)

if result_path.exists():
    if result_path.is_symlink():
        fail("retained gateway result is unsafe")
    result_bytes = result_path.read_bytes()
else:
    if identity is None:
        completed = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
        )
    else:
        import fcntl
        if argv[-1] != str(request_path):
            fail("frozen compiler request path changed")
        # Root retains the durable 0700 journal. The controller is given
        # only sealed, read-only immutable request bytes, never root registry
        # directory permissions or a writable request/result pathname.
        descriptor = os.memfd_create("zog-compiler-request", os.MFD_ALLOW_SEALING)
        try:
            os.write(descriptor, payload)
            os.lseek(descriptor, 0, os.SEEK_SET)
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            completed = _as_controller(
                identity, argv, request_fd=descriptor, timeout=300)
        finally:
            os.close(descriptor)
    if len(completed.stdout) > MAX_STDIO or len(completed.stderr) > MAX_STDIO:
        fail("image-build remote operation output exceeds control-plane limit")
    if completed.returncode:
        sys.stderr.buffer.write(completed.stderr[-4096:])
        fail("image-build remote operation command failed")
    try:
        lines = [line for line in completed.stdout.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError:
        fail("image-build remote operation output is not UTF-8")
    if not lines:
        fail("image-build remote operation returned no result")
    try:
        result = json.loads(lines[-1])
        result_bytes = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError):
        fail("image-build remote operation returned invalid JSON")
    if len(result_bytes) > MAX_RESULT:
        fail("image-build remote result exceeds control-plane limit")
    atomic(result_path, result_bytes)

if len(result_bytes) > MAX_RESULT:
    fail("retained image-build remote result exceeds control-plane limit")
try:
    result = json.loads(result_bytes)
except (TypeError, ValueError):
    fail("retained image-build remote result is invalid JSON")

request = json.loads(payload)
if (
    result.get("schema") != "image-build-remote-result-v1"
    or result.get("operation_id") != request.get("operation_id")
    or result.get("operation_type") != request.get("operation")
    or result.get("source_repository") != request.get("source", {}).get("repository")
    or result.get("source_revision") != request.get("source", {}).get("revision")
):
    fail("image-build remote result identity differs from request")

failure = result.get("failure")
if isinstance(failure, dict):
    failure = {
        "type": str(failure.get("type", ""))[:128],
        "reason": str(failure.get("reason", ""))[:2000],
        **(
            {"job_id": str(failure.get("job_id"))[:128]}
            if failure.get("job_id") is not None
            else {}
        ),
    }
elif failure is not None:
    failure = {"type": "unstructured", "reason": str(failure)[:2000]}

summary = {
    "schema": result.get("schema"),
    "operation_id": result.get("operation_id"),
    "operation_type": result.get("operation_type"),
    "source_repository": result.get("source_repository"),
    "source_revision": result.get("source_revision"),
    "pipeline_id": result.get("pipeline_id"),
    "status": result.get("status"),
    "terminal_outcome": result.get("terminal_outcome"),
    "failure": failure,
    "uncertainty": bool(result.get("uncertainty")),
    "allowed_next_operations": list(result.get("allowed_next_operations") or [])[:32],
    "missing_evidence_count": len(result.get("missing_evidence") or []),
    "recipe_identity": result.get("recipe_identity"),
    "selected_generation": result.get("selected_generation"),
    "attempt_ids": list(result.get("attempt_ids") or [])[:24],
    "controller_jobs": list(result.get("controller_jobs") or [])[:24],
    "predecessor": result.get("predecessor"),
    "artifacts": {
        name: result.get("artifacts", {}).get(name)
        for name in ("remote_capabilities", "recipe_snapshot", "contract",
                     "pin_date", "monthly_identity", "inventory_digest",
                     "toolchain_specification", "toolchain_execution")
        if isinstance(result.get("artifacts"), dict)
        and name in result["artifacts"]
    },
}
receipt = {
    "schema": "host-deploy-image-build-receipt-v1",
    "request_id": request.get("operation_id"),
    "remote_request_sha256": request_sha256,
    "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
    "result_bytes": len(result_bytes),
    "result": summary,
}
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
'''


def remote_script(binding):
    """Return a server-generated shell command for one frozen binding."""
    binding = _binding({"phase": "prepared", "binding": binding})
    request_bytes = _canonical(binding["remote_request"])
    payload = base64.b64encode(request_bytes).decode("ascii")
    execution = binding.get("compiler_execution_identity")
    wrapper = (IDENTITY_RUNTIME + "\n" + _WRAPPER) if execution else _WRAPPER
    arguments = [
        (binding["python_executable"] if binding["schema"] in {2, 3} else "python3"),
        "-c",
        wrapper,
        binding["remote_request_path"],
        binding["remote_result_path"],
        binding["source_root"],
        binding["source"]["revision"],
        binding["monthly_pin_repository_path"],
        binding["monthly_pin_identity"],
        binding["remote_request_sha256"],
        payload,
        *(
            ["identity-v1:" + base64.b64encode(_canonical(execution)).decode("ascii")]
            if execution else []
        ),
        *binding["argv"],
    ]
    return " ".join(shlex.quote(value) for value in arguments)


def producer_runtime_preflight(host, binding):
    """Run the pinned image-build read-only CLI, before SSM producer submission."""
    if binding["schema"] != 3:
        raise RuntimeError("producer preflight needs dependency-bound dispatch")
    companion = binding["runtime_companion"]
    profile = binding["runtime_profile"]
    source = binding["source_root"]
    root = companion["source_root"]
    python = binding["python_executable"]
    cli = [
        "env", "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONPATH=" + source + "/src:" + root + "/src",
        python, "-B", "-m", "zog.image_build.runtime_preflight",
        "--repository-root", source,
        "--python-executable", python,
        "--operation", profile["operation"],
        "--component-root", "build-record=" + root,
    ]
    if profile["provenance"]:
        cli.append("--provenance")
    if profile["external_observed_state"]:
        cli.append("--external-observed-state")
    if profile["controller"]:
        box_root = profile["controller_source_root"]
        cli.extend(["--controller", "--component-root", "box-control=" + box_root])
        cli[2] += ":" + box_root + "/box-control/src"
    script = ["set -eu"]
    for checkout, revision in (
        (source, binding["source"]["revision"]),
        (root, companion["revision"]),
    ):
        script.extend((
            "test ! -L " + shlex.quote(checkout),
            "test " + shlex.quote(revision) + " = $(git -C "
            + shlex.quote(checkout) + " rev-parse --verify HEAD)",
            "test -z \"$(git -C " + shlex.quote(checkout)
            + " status --porcelain=v1 --untracked-files=all)\"",
        ))
    if profile["controller"]:
        box_root = profile["controller_source_root"]
        script.extend((
            "test ! -L " + shlex.quote(box_root),
            "test " + shlex.quote(profile["controller_revision"])
            + " = $(git -C " + shlex.quote(box_root) + " rev-parse --verify HEAD)",
            'test -z "$(git -C ' + shlex.quote(box_root)
            + ' status --porcelain=v1 --untracked-files=all)"',
        ))
    script.append(shlex.join(cli))
    raw = host.command("\n".join(script), seconds=120)
    if not isinstance(raw, str) or len(raw) > 32768:
        raise RuntimeError("producer preflight evidence is not bounded")
    report = json.loads(raw)
    if (not isinstance(report, dict)
            or report.get("contract") != "image-build-runtime-preflight-v1"
            or report.get("ready") is not True
            or report.get("mutation") is not False):
        raise RuntimeError("producer runtime readiness not confirmed")
    if (report.get("python", {}).get("executable") != python
            or report.get("image_build", {}).get("repository_root") != source
            or report.get("requirements", {}).get("operation") != profile["operation"]
            or report.get("requirements", {}).get("bindings") != {
                "provenance": profile["provenance"],
                "controller": profile["controller"],
                "external_observed_state": profile["external_observed_state"],
            }):
        raise RuntimeError("producer preflight differs from frozen profile")
    checks = report.get("checks")
    if not isinstance(checks, list) or not any(
        isinstance(item, dict) and item.get("component") == "build-record"
        and item.get("status") == "ready"
        and item.get("validated_revision") == companion["revision"]
        and isinstance(item.get("source"), str)
        and item["source"].startswith(root + "/src/")
        for item in checks
    ):
        raise RuntimeError("producer preflight did not verify bound build-record")
    if profile["controller"] and not any(
        isinstance(item, dict) and item.get("component") == "box-control"
        and item.get("status") == "ready"
        and item.get("validated_revision") == profile["controller_revision"]
        and isinstance(item.get("source"), str)
        and item["source"].startswith(
            profile["controller_source_root"] + "/box-control/src/"
        )
        for item in checks
    ):
        raise RuntimeError("producer preflight did not verify bound box-control")
    return report


def submit_prepared(gateway_root, request_id, *, host_factory=Host, at=None):
    """Submit exactly one prepared SSM command; never replay uncertain state."""
    record = load_dispatch(gateway_root, request_id)
    binding = _binding(record)
    if record["phase"] == "submitted":
        return load_request(gateway_root, request_id), record
    if record["phase"] != "prepared":
        raise RuntimeError(
            "dispatch is not safely submit-able; reconcile existing evidence instead"
        )
    if binding["remote_request"]["operation"] == "capabilities.inspect":
        raise RuntimeError(
            "generic build requires supervised multi-stage advancement; "
            "single SSM dispatch-submit is prohibited"
        )
    if binding["schema"] != 3:
        raise RuntimeError(
            "legacy dependency-unbound dispatch cannot be newly submitted; "
            "retain its immutable execution evidence"
        )
    host_configuration = verify_current_target(gateway_root, binding)
    host = host_factory(host_configuration)
    try:
        report = producer_runtime_preflight(host, binding)
    except Exception as error:
        record_dispatch_runtime_preflight(
            gateway_root, request_id,
            {"contract": "image-build-runtime-preflight-v1",
             "ready": False, "mutation": False,
             "failures": [{"reason": str(error)[:512]}]},
            at=at,
        )
        raise
    record_dispatch_runtime_preflight(gateway_root, request_id, report, at=at)
    script = remote_script(binding)

    mark_dispatch_submitting(gateway_root, request_id, at=at)
    try:
        command_id = host.submit_command(
            script,
            seconds=CONTROL_TIMEOUT_SECONDS,
        )
    except BaseException as error:
        mark_dispatch_uncertain(
            gateway_root,
            request_id,
            error,
            at=at,
        )
        raise
    return mark_dispatch_submitted(
        gateway_root,
        request_id,
        command_id,
        at=at,
    )


def _observation(value):
    if value is None:
        return {"status": "InvocationDoesNotExist"}
    result = {
        "status": str(value.get("Status", ""))[:64],
        "status_details": str(value.get("StatusDetails", ""))[:128],
    }
    response_code = value.get("ResponseCode")
    if type(response_code) is int:
        result["response_code"] = response_code
    stderr = value.get("StandardErrorContent")
    if isinstance(stderr, str) and stderr:
        result["stderr_tail"] = stderr[-2000:]
    return result


def parse_receipt(text, binding):
    binding = _binding({"phase": "submitted", "binding": binding})
    if not isinstance(text, str) or len(text.encode("utf-8")) > 64 * 1024:
        raise RuntimeError("SSM receipt is missing or oversized")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("SSM command returned no gateway receipt")
    try:
        receipt = json.loads(lines[-1])
    except (TypeError, ValueError):
        raise RuntimeError("SSM gateway receipt is invalid JSON") from None
    expected = {
        "schema",
        "request_id",
        "remote_request_sha256",
        "result_sha256",
        "result_bytes",
        "result",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise RuntimeError("SSM gateway receipt fields are invalid")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["request_id"] != binding["request_id"]
        or receipt["remote_request_sha256"] != binding["remote_request_sha256"]
        or not isinstance(receipt["result_sha256"], str)
        or not _SHA256.fullmatch(receipt["result_sha256"])
        or type(receipt["result_bytes"]) is not int
        or not 1 <= receipt["result_bytes"] <= _MAX_REMOTE_RESULT
    ):
        raise RuntimeError("SSM gateway receipt identity is invalid")
    result = receipt["result"]
    result_fields = {
        "schema",
        "operation_id",
        "operation_type",
        "source_repository",
        "source_revision",
        "pipeline_id",
        "status",
        "terminal_outcome",
        "failure",
        "uncertainty",
        "allowed_next_operations",
        "missing_evidence_count",
    }
    auxiliary = {"recipe_identity", "artifacts", "selected_generation",
                 "attempt_ids", "controller_jobs", "predecessor"}
    remote = binding["remote_request"]
    if (
        not isinstance(result, dict)
        or not result_fields.issubset(result)
        or set(result) - result_fields - auxiliary
        or result["schema"] != "image-build-remote-result-v1"
        or result["operation_id"] != binding["request_id"]
        or result["operation_type"] != remote["operation"]
        or result["source_repository"] != binding["source"]["repository"]
        or result["source_revision"] != binding["source"]["revision"]
        or result["status"] not in {"completed", "failed", "pending", "released"}
        or type(result["uncertainty"]) is not bool
        or type(result["missing_evidence_count"]) is not int
        or not 0 <= result["missing_evidence_count"] <= 1_000_000
        or not isinstance(result["allowed_next_operations"], list)
        or len(result["allowed_next_operations"]) > 32
    ):
        raise RuntimeError("image-build result summary differs from dispatch binding")
    if ("recipe_identity" in result and result["recipe_identity"] is not None
            and (not isinstance(result["recipe_identity"], str)
                 or not re.fullmatch(r"sha256:[a-f0-9]{64}", result["recipe_identity"]))):
        raise RuntimeError("invalid image-build snapshot identity")
    if "artifacts" in result and (not isinstance(result["artifacts"], dict)
            or len(_canonical(result["artifacts"])) > 32000):
        raise RuntimeError("image-build receipt artifacts are not bounded")
    if remote["operation"].startswith("toolchain."):
        if (result.get("predecessor") != remote.get("predecessor")
                or not isinstance(result.get("attempt_ids"), list)
                or len(result["attempt_ids"]) > 24
                or not isinstance(result.get("controller_jobs"), list)
                or len(result["controller_jobs"]) > 24):
            raise RuntimeError("toolchain evidence and predecessor are invalid")
        artifacts = result.get("artifacts", {})
        if remote["operation"] == "toolchain.specification.inspect":
            if not isinstance(artifacts.get("toolchain_specification"), dict):
                raise RuntimeError("missing producer toolchain specification")
        elif not isinstance(artifacts.get("toolchain_execution"), dict):
            raise RuntimeError("missing producer toolchain execution evidence")
    return receipt


def completion_for_receipt(receipt):
    result = receipt["result"]
    if result["uncertainty"]:
        return "recovery_blocked"
    if result["operation_type"] == "pipeline.inspect":
        # The status query itself completed successfully; its payload may report
        # a pending, failed, completed, or released pipeline.
        return "completed"
    if (
        result["status"] == "failed"
        and result.get("terminal_outcome") in {"timeout", "timed_out"}
    ):
        return "timed_out"
    return {
        "pending": "running",
        "completed": "completed",
        "failed": "failed",
        "released": "cancelled",
    }[result["status"]]


def observe_submitted(gateway_root, request_id, *, host_factory=Host, at=None):
    """Inspect an existing SSM CommandId; never submit a replacement command."""
    record = load_dispatch(gateway_root, request_id)
    binding = _binding(record)
    if record["phase"] != "submitted":
        raise RuntimeError("dispatch has no recorded SSM command identity")
    host_configuration = verify_current_target(gateway_root, binding)
    host = host_factory(host_configuration)
    observed = host.inspect_command(record["command_id"])
    evidence = record_dispatch_observation(
        gateway_root,
        request_id,
        _observation(observed),
        at=at,
    )
    if observed is None:
        return load_request(gateway_root, request_id), evidence, None

    status = observed.get("Status")
    if status in {"Pending", "InProgress", "Delayed", "Cancelling"}:
        state = mark_completion(
            gateway_root,
            request_id,
            "running",
            at=at,
        )
        return state, evidence, None
    if status != "Success":
        state = mark_completion(
            gateway_root,
            request_id,
            "recovery_blocked",
            at=at,
        )
        return state, evidence, None

    try:
        receipt = parse_receipt(observed.get("StandardOutputContent", ""), binding)
    except Exception:
        mark_completion(
            gateway_root,
            request_id,
            "recovery_blocked",
            at=at,
        )
        raise
    completion = completion_for_receipt(receipt)
    state, retained = record_remote_result(
        gateway_root,
        request_id,
        receipt,
        completion,
        at=at,
    )
    return state, evidence, retained
