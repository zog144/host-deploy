"""Protected adapter from host-deploy gateway history to image-build acceptance.

This module never accepts an output generation, recipe path, arbitrary argv or
request JSON. It derives one completed admitted predecessor request from the
durable gateway ledger and invokes the exact installed image-build reader.
"""
import json
import os
from pathlib import Path
import re
import subprocess

from . import generic_pipeline
from . import graphics_catalogue_owner as first
from . import graphics_generation_chain as chain
from . import image_build_execution
from .image_build_dispatch import verify_current_target
from .ledger import load_dispatch, load_request

CONTEXT = "image-build-graphical-predecessor-attestation-context-v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_EVIDENCE = 65536
GIT = "/usr/bin/git"


class GraphicalAttesterBlocked(RuntimeError):
    pass


def _deny(reason):
    raise GraphicalAttesterBlocked(
        "graphical-generation-attester-not-accepted: " + reason
    )


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _unique_json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_EVIDENCE:
        _deny("producer evidence is missing or oversized")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _deny("duplicate producer evidence field")
            result[key] = value
        return result
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: _deny("non-finite producer evidence"),
        )
    except GraphicalAttesterBlocked:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise GraphicalAttesterBlocked(
            "graphical-generation-attester-not-accepted: invalid producer evidence"
        ) from error


def _argv_value(argv, flag):
    matches = [index for index, value in enumerate(argv) if value == flag]
    if len(matches) != 1 or matches[0] + 1 >= len(argv):
        _deny("frozen producer argv lacks " + flag)
    value = argv[matches[0] + 1]
    if not isinstance(value, str) or not value or "\0" in value:
        _deny("frozen producer argv has invalid " + flag)
    return value


def _run(argv, **kwargs):
    return subprocess.run(argv, **kwargs)


def _verify_checkout(path, revision):
    """Read-only worktree/commit proof; never refresh or write the Git index."""
    root = Path(path)
    if (
        root.is_symlink() or not root.is_dir()
        or not isinstance(revision, str)
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
    ):
        _deny("installed source checkout is unsafe")
    if not Path(GIT).is_file():
        _deny("fixed Git reader is unavailable")

    def call(arguments, *, stdout=subprocess.PIPE):
        result = _run(
            [GIT, "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if result.returncode != 0 or result.stderr:
            _deny("installed source checkout differs")
        return result

    head = call(["rev-parse", "--verify", "HEAD"]).stdout
    if head != (revision + "\n").encode("ascii"):
        _deny("installed source revision differs")
    call(["diff-index", "--cached", "--quiet", revision, "--"])
    call(["diff-files", "--quiet", "--"])
    untracked = call(
        ["ls-files", "--others", "--exclude-standard", "-z"]
    ).stdout
    if untracked:
        _deny("installed source checkout has untracked files")


def _matching_completed_request(
    state_directory, policy, previous_task, catalogue_sha256, input_generation_id
):
    request_root = Path(state_directory) / "requests"
    if request_root.is_symlink() or not request_root.is_dir():
        _deny("gateway request ledger is unavailable")
    matches = []
    for entry in sorted(request_root.iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            _deny("gateway request ledger contains unsafe entry")
        state = load_request(state_directory, entry.name)
        request = state.get("request", {})
        if (
            request.get("operation") == "build.submit"
            and request.get("parameters", {}).get("task") == previous_task
            and request.get("parameters", {}).get("lane") == policy["lane"]
            and state.get("states", {}).get("admission") == "admitted"
        ):
            matches.append((entry.name, state))
    if len(matches) != 1:
        _deny("predecessor request identity is absent or ambiguous")

    request_id, state = matches[0]
    request = state["request"]
    if (
        request_id != request.get("request_id")
        or not _ID.fullmatch(request_id)
        or request.get("source") != {
            "repository": first.REPOSITORY, "commit": first.SOURCE
        }
    ):
        _deny("predecessor gateway source/request differs")

    dispatch = load_dispatch(state_directory, request_id)
    binding = image_build_execution._binding(dispatch)
    verify_current_target(state_directory, binding)
    task = binding.get("task")
    if (
        binding.get("schema") != 3
        or binding.get("lane") != policy["lane"]
        or binding.get("source") != {
            "repository": first.REPOSITORY, "revision": first.SOURCE
        }
        or binding.get("monthly_pin_repository_path") != first.PIN_PATH
        or binding.get("monthly_pin_identity") != policy["monthly_pin_identity"]
        or binding.get("project_root") != policy["project_root"]
        or binding.get("observed_state_dir") is not None
        or binding.get("task_catalogue_identity") != catalogue_sha256
        or not isinstance(task, dict)
        or task.get("source_repository") != first.REPOSITORY
        or task.get("source_revision") != first.SOURCE
        or task.get("lane") != policy["lane"]
        or task.get("lane_owner") != policy["lane_owner"]
        or task.get("monthly_pin_identity") != policy["monthly_pin_identity"]
        or task.get("arguments", {}).get("selection") != input_generation_id
        or (
            previous_task == chain.TASKS[0]
            and "graphical_predecessor" in task.get("arguments", {})
        )
        or (
            previous_task == chain.TASKS[1]
            and not _HEX.fullmatch(task.get("arguments", {}).get(
                "graphical_predecessor", ""))
        )
    ):
        _deny("frozen predecessor dispatch differs")

    progress = generic_pipeline.status(state_directory, request_id)
    pipeline_id = progress.get("pipeline_id")
    if (
        progress.get("phase") != "completed"
        or not isinstance(pipeline_id, str)
        or not _ID.fullmatch(pipeline_id)
        or not isinstance(progress.get("stages"), list)
        or not progress["stages"]
        or any(step.get("phase") != "completed" for step in progress["stages"])
    ):
        _deny("predecessor gateway pipeline is not durably completed")
    return request_id, pipeline_id, binding


def _attest(
    state_directory, policy, previous_task, catalogue_sha256, input_generation_id
):
    if os.geteuid() != 0:
        raise PermissionError("graphical predecessor attester requires root")
    policy = chain.validate_policy(policy)
    if (
        previous_task not in chain.TASKS[:2]
        or not isinstance(catalogue_sha256, str)
        or not _SHA.fullmatch(catalogue_sha256)
        or not isinstance(input_generation_id, str)
        or not _HEX.fullmatch(input_generation_id)
    ):
        _deny("predecessor selector is invalid")

    request_id, pipeline_id, binding = _matching_completed_request(
        state_directory, policy, previous_task,
        catalogue_sha256, input_generation_id,
    )
    companion = binding.get("runtime_companion")
    profile = binding.get("runtime_profile")
    if (
        not isinstance(companion, dict)
        or companion.get("producer_revision") != first.SOURCE
        or companion.get("revision") is None
        or not isinstance(profile, dict)
    ):
        _deny("producer companion binding differs")

    # Root must not run Git or Python from Project source/companions.
    # Project .git/config may request executable fsmonitor/filter helpers and
    # a clean Git diff ignores shadowing content and import-time mutations.
    # The source/companion commit fields remain checked as provenance only.
    if profile.get("controller"):
        controller = binding.get("controller_companion")
        if (
            not isinstance(controller, dict)
            or controller.get("producer_revision") != first.SOURCE
            or controller.get("revision") != profile.get("controller_revision")
            or profile.get("controller_source_root") is None
        ):
            _deny("controller companion binding differs")
    from . import graphics_attester_import as protected_import
    import_pin = protected_import.verify(
        source_revision=first.SOURCE,
        monthly_pin_identity=policy["monthly_pin_identity"])

    argv = binding["argv"]
    state_dir = _argv_value(argv, "--state-dir")
    host_id = _argv_value(argv, "--provenance-host-id")
    project_id = _argv_value(argv, "--provenance-project-id")
    pin_path = _argv_value(argv, "--provenance-pin")
    expected_pin = _argv_value(argv, "--expected-pin-digest")
    if (
        host_id != policy["host_id"]
        or host_id != policy["lane_owner"]
        or expected_pin != policy["monthly_pin_identity"]
        or Path(state_dir) != Path(policy["project_root"]) / "state"
        or Path(pin_path) != Path(binding["source_root"]) / first.PIN_PATH
    ):
        _deny("producer provenance Host/Project/pin path differs")

    context = {
        "schema": CONTEXT,
        "task": previous_task,
        "host_id": policy["host_id"],
        "installation_id": policy["installation_id"],
        "lane": policy["lane"],
        "lane_owner": policy["lane_owner"],
        "project_id": project_id,
        "project_root": policy["project_root"],
        "source_repository": first.REPOSITORY,
        "source_revision": first.SOURCE,
        "monthly_pin_identity": policy["monthly_pin_identity"],
        "request_id": request_id,
        "pipeline_id": pipeline_id,
        "predecessor_catalogue_sha256": catalogue_sha256,
        "input_generation_id": input_generation_id,
        **({"graphical_predecessor_id":
            binding["task"]["arguments"]["graphical_predecessor"]}
           if previous_task == chain.TASKS[1] else {}),
    }

    command = protected_import.command(import_pin, [
        "--repository-root", binding["source_root"],
        "--state-dir", state_dir,
        "--source-repository", first.REPOSITORY,
        "--source-revision", first.SOURCE,
        "--provenance-host-id", host_id,
        "--provenance-project-id", project_id,
        "--provenance-pin", pin_path,
        "--expected-pin-digest", expected_pin,
    ])
    result = _run(
        command,
        input=_canonical(context),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
        cwd="/",
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        },
    )
    # Root-owned protected snapshots cannot change under unprivileged writers.
    # Reverify the entire inventory after the reader exits to also detect
    # unexpected in-flight inode replacement or modified ignored files.
    if protected_import.verify(
            source_revision=first.SOURCE,
            monthly_pin_identity=policy["monthly_pin_identity"]) != import_pin:
        _deny("protected import identity changed during invocation")
    if (
        result.returncode != 0 or result.stderr
        or not isinstance(result.stdout, bytes)
        or len(result.stdout) > MAX_EVIDENCE
    ):
        _deny("installed producer attester did not return clean evidence")
    evidence = _unique_json(result.stdout)
    # The chain resolver revalidates the complete exact schema. Check the
    # cross-owner fields here before evidence leaves this protected capability.
    for key, value in {
        "schema": chain.EVIDENCE,
        "task": previous_task,
        "host_id": policy["host_id"],
        "installation_id": policy["installation_id"],
        "lane": policy["lane"],
        "lane_owner": policy["lane_owner"],
        "project_root": policy["project_root"],
        "source_revision": first.SOURCE,
        "monthly_pin_identity": policy["monthly_pin_identity"],
        "request_id": request_id,
        "pipeline_id": pipeline_id,
        "predecessor_catalogue_sha256": catalogue_sha256,
        "input_generation_id": input_generation_id,
    }.items():
        if not isinstance(evidence, dict) or evidence.get(key) != value:
            _deny("producer evidence differs from protected gateway context")
    return evidence


def installed_capability(state_directory):
    """Return the exact callback consumed by install_next_native.

    The chain policy is read from protected STATE here; callers cannot pass a
    replacement policy or output generation into the capability.
    """
    if os.geteuid() != 0:
        raise PermissionError("graphical predecessor attester requires root")
    from .fresh_budget_guard import _protected_root
    _protected_root(chain.STORE)
    policy = chain.validate_policy(chain._read_locked(chain.POLICY))

    def attest(previous_task, predecessor_catalogue_sha256, input_generation_id):
        return _attest(
            state_directory, policy, previous_task,
            predecessor_catalogue_sha256, input_generation_id,
        )
    return attest
