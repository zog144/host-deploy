"""Finite GitHub/SQS -> SSM forwarding. No compiler dossier or catalogue.

GitHub Actions validates issue-opened identity and allowlist before SQS.
The trusted-Host queue/owned workspace and schema-5 lane select the SSM target,
document and installed image-build executable. The producer selects the active
toolchain and immutable recipe snapshot from its own Project. One fsynced intent = one SendCommand
attempt, even if the CommandId acknowledgement is lost.
"""
import hashlib
import json
import re
import time
from pathlib import Path

from ..runner import Host
from .github_dispatch import FIRST_FONTS_TASK
from .image_build_dispatch import prepare_image_build_dispatch, verify_current_target
from .image_build_execution import (
    CONTROL_TIMEOUT_SECONDS, RECEIPT_SCHEMA, _binding, remote_script,
)
from .project_current_observation import (
    CONTROL_TIMEOUT_SECONDS as PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
    OBSERVATION_SCHEMA as PROJECT_OBSERVATION_SCHEMA,
)
from .ledger import (
    load_dispatch, load_request, mark_dispatch_submitting,
    mark_dispatch_submitted, mark_dispatch_uncertain, prepare_dispatch,
    mark_completion, record_dispatch_observation, record_remote_result,
    valid_request_ids,
)

# Explicitly finite task/operation mapping. No supplied script, user-selected
# document, arbitrary executable, extra receipt file or mutable shell command.
SUPPORTED = frozenset({("build.submit", FIRST_FONTS_TASK)})
_RUNNING = frozenset({"Pending", "InProgress", "Delayed", "Cancelling"})
_TERMINAL = {"Success": "completed", "Failed": "failed",
             "Cancelled": "cancelled", "TimedOut": "timed_out"}


class ForwardingDenied(RuntimeError):
    pass


def _selected_request(root, request_id):
    state = load_request(root, request_id)
    if state["states"]["admission"] != "admitted":
        raise ForwardingDenied("request is not admitted")
    request = state["request"]
    parameters = request["parameters"]
    if ((request["operation"], parameters.get("task")) not in SUPPORTED
            or set(parameters) != {"lane", "task"}):
        raise ForwardingDenied("operation is not enabled for direct forwarding")
    return request


def _frozen_binding(root, request_id):
    record = load_dispatch(root, request_id)
    binding = _binding(record)
    original = _selected_request(root, request_id)
    if (binding.get("direct_forward") is not True
            or binding.get("request_id") != request_id
            or set(binding["remote_request"].get("arguments", {}))
                != {"mode", "targets"}
            or binding["remote_request"].get("operation_id") != request_id):
        raise ForwardingDenied("frozen SSM operation differs from authorized request")
    return record, binding


def advance(root, request_id, *, host_factory=Host, owner_factory=None):
    """Perform at most one durable phase; repeated calls never replay SSM."""
    original = _selected_request(root, request_id)
    dispatch = load_dispatch(root, request_id)
    if dispatch is None:
        state, record = prepare_image_build_dispatch(
            root, request_id, direct_forward=True)
        return {"request_id": request_id, "phase": record["phase"]}
    if dispatch["phase"] in ("submitting", "submission_uncertain"):
        # An uncertain SendCommand acknowledgement is NOT permission to retry.
        return {"request_id": request_id, "phase": "submission_uncertain"}
    record, binding = _frozen_binding(root, request_id)
    if record["phase"] not in ("prepared", "submitted"):
        raise ForwardingDenied("unrecognized forwarding phase")
    configuration = verify_current_target(root, binding)
    if record["phase"] == "prepared":
        if binding.get("schema") != 4 or binding.get("direct_forward") is not True:
            raise ForwardingDenied(
                "protected Fonts owner requires Project-current schema-4 dispatch")
        from . import fonts_owner_sender as owner
        # The authorized root-control owner, not this SQS-facing gateway,
        # provides the only SSM send. An absent protected owner fails while
        # the original request is still PREPARED (no attempted send).
        owner.ready(request_id, journal_factory=owner_factory)
        script = remote_script(binding)
        host = host_factory(configuration)
        mark_dispatch_submitting(root, request_id)
        try:
            command_id = owner.submit_once(
                root, request_id, binding=binding,
                configuration=configuration, host=host,
                script=script,
                seconds=(PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS
                         if binding.get("schema") == 4
                         else CONTROL_TIMEOUT_SECONDS),
                journal_factory=owner_factory,
            )
        except BaseException as error:
            mark_dispatch_uncertain(root, request_id, error)
            raise
        # If durable recording fails after SendCommand, the already-written
        # intent becomes uncertain on restart. It is never blindly resent.
        mark_dispatch_submitted(root, request_id, command_id)
        return {"request_id": request_id, "phase": "submitted",
                "command_id": command_id}
    # Result recovery reads the SAME recorded CommandId. No SendCommand.
    # An explicit trusted Project observation outranks a *stale* terminal
    # SSM control-window status. Otherwise a Gateway polling iteration could
    # incorrectly turn a reconciled running pipeline back into TimedOut.
    command_id = record["command_id"]
    observation_path = Path(root) / "requests" / request_id / "dispatch-observation.json"
    if binding.get("schema") == 4 and observation_path.is_file():
        saved = json.loads(observation_path.read_text())
        observed = saved.get("observation", {})
        if (saved.get("schema") == 1 and saved.get("request_id") == request_id
                and saved.get("command_id") == command_id
                and type(observed) is dict
                and observed.get("status") == "reconciled-project"):
            state = load_request(root, request_id)["states"]["completion"]
            if state in ("running", "recovery_blocked", "completed", "failed"):
                return {"request_id": request_id, "phase": state,
                        "command_id": command_id,
                        "pipeline_id": observed.get("producer", {}).get("pipeline_id"),
                        "observation_required": state in
                            ("running", "recovery_blocked")}
    host = host_factory(configuration)
    observation = host.inspect_command(command_id)
    if observation is None:
        return {"request_id": request_id, "phase": "submitted",
                "command_id": command_id, "status": "not-yet-visible"}
    if (type(observation) is not dict
            or observation.get("CommandId") != command_id
            or observation.get("InstanceId") != configuration["instance_id"]
            or observation.get("Status") not in _RUNNING | set(_TERMINAL)):
        raise ForwardingDenied("SSM invocation identity or status is invalid")
    status = observation["Status"]
    summary = {"schema": "host-deploy-direct-ssm-observation-v1",
               "command_id": command_id, "status": status}
    record_dispatch_observation(root, request_id, summary)
    if status in _RUNNING:
        return {"request_id": request_id, "phase": "submitted",
                "command_id": command_id, "status": status}
    if status != "Success":
        if binding.get("schema") == 4:
            # SSM's TimedOut/Failed/Cancelled describes the control window,
            # not the actual 14,400-second image-build pipeline. Never mark
            # a Project-current pipeline terminal without producer evidence.
            mark_completion(root, request_id, "recovery_blocked")
            return {"request_id": request_id, "phase": "recovery_blocked",
                    "command_id": command_id, "ssm_status": status,
                    "observation_required": True}
        record_remote_result(root, request_id, summary, _TERMINAL[status])
        return {"request_id": request_id, "phase": _TERMINAL[status],
                "command_id": command_id}
    output = observation.get("StandardOutputContent")
    if type(output) is not str or len(output.encode("utf-8")) > 1024 * 1024:
        raise ForwardingDenied("SSM output is unavailable or oversized")
    try:
        receipt = json.loads(output.strip().splitlines()[-1])
    except (IndexError, ValueError, TypeError):
        raise ForwardingDenied("SSM output has no producer result") from None
    if (type(receipt) is not dict or receipt.get("schema") != RECEIPT_SCHEMA
            or receipt.get("request_id") != request_id
            or receipt.get("remote_request_sha256") !=
                binding["remote_request_sha256"]
            or not isinstance(receipt.get("result"), dict)):
        raise ForwardingDenied("producer result differs from original operation")
    if binding.get("schema") == 4:
        result = receipt["result"]
        pipeline = result.get("pipeline_id")
        source_revision = result.get("source_revision")
        from .project_current import IDENTITY, REVISION
        if (type(source_revision) is not str
                or not REVISION.fullmatch(source_revision)
                or (pipeline is not None and
                    (type(pipeline) is not str or
                     not IDENTITY.fullmatch(pipeline)))
                or result.get("status") not in
                    ("pending", "running", "completed", "failed", "released")):
            raise ForwardingDenied("producer status or identity is invalid")
        # Do not store a provisional result as the immutable terminal
        # remote-result.json: later read-only observation may reconcile it.
        report = {**summary,
                  "producer": {
                      "request_id": request_id,
                      "source_revision": source_revision,
                      "pipeline_id": pipeline,
                      "status": result["status"],
                      "uncertainty": result.get("uncertainty") is True}}
        record_dispatch_observation(root, request_id, report)
        if (result["status"] == "completed"
                and result.get("terminal_outcome") == "success"
                and result.get("uncertainty") is False):
            completion = "completed"
        elif (result["status"] == "failed"
              and result.get("terminal_outcome") is not None
              and result.get("uncertainty") is False):
            completion = "failed"
        elif pipeline is not None:
            completion = "running"
        else:
            completion = "recovery_blocked"
        if completion in ("completed", "failed"):
            record_remote_result(root, request_id, receipt, completion)
        else:
            mark_completion(root, request_id, completion)
        return {"request_id": request_id, "phase": completion,
                "command_id": command_id, "pipeline_id": pipeline,
                "observation_required": completion not in ("completed", "failed")}
    record_remote_result(root, request_id, receipt, "completed")
    return {"request_id": request_id, "phase": "completed",
            "command_id": command_id}


FIRST_FONTS_COMPILER_PROJECT_UID = 24201  # Reviewed compiler Project owner, not Gateway root.


def reconcile_project_observation(root, request_id, *, host_factory=Host):
    """Explicit read-only SSM probe on the selected compiler Host.

    The registry/Gateway never mounts the compiler Project. This method
    accepts no caller-supplied status or script, and is never called by
    automatic SQS polling. Its inspection CommandId is independent of the
    protected, once-only original build submission.
    """
    record, binding = _frozen_binding(root, request_id)
    if record["phase"] != "submitted" or binding.get("schema") != 4:
        raise ForwardingDenied(
            "observation requires submitted Project-current request")
    config = verify_current_target(root, binding)
    from .project_current import REVISION, IDENTITY
    from .project_current_observation import read_only_observation_script

    previous_path = Path(root) / "requests" / request_id / "dispatch-observation.json"
    prior = {}
    if previous_path.exists():
        previous = json.loads(previous_path.read_text())
        if (previous.get("schema") != 1
                or previous.get("request_id") != request_id
                or previous.get("command_id") != record["command_id"]
                or type(previous.get("observation")) is not dict):
            raise ForwardingDenied("retained SSM/Project observation identity differs")
        prior = previous["observation"].get("producer", {})
        if type(prior) is not dict:
            raise ForwardingDenied("previous Project producer identity is invalid")

    expected_pipeline = prior.get("pipeline_id")
    if (expected_pipeline is not None and
            (type(expected_pipeline) is not str
             or not IDENTITY.fullmatch(expected_pipeline))):
        raise ForwardingDenied("retained pipeline identity is invalid")
    # This new, fixed SSM command only inspects the frozen compiler Host.
    # Its identity is distinct from the protected original Task C build send.
    script = read_only_observation_script(
        binding["project_root"], binding["python_executable"], request_id,
        pipeline_id=expected_pipeline)
    try:
        host = host_factory(config)
        inspection_id = host.submit_command(script, seconds=120)
        if (type(inspection_id) is not str or not inspection_id
                or len(inspection_id) > 128):
            raise ValueError("invalid read-only SSM inspection CommandId")
        deadline = time.monotonic() + 210
        observed_ssm = None
        while time.monotonic() < deadline:
            observed_ssm = host.inspect_command(inspection_id)
            if observed_ssm is not None:
                if (type(observed_ssm) is not dict
                        or observed_ssm.get("CommandId") != inspection_id
                        or observed_ssm.get("InstanceId") != config["instance_id"]
                        or observed_ssm.get("Status") not in
                            (_RUNNING | set(_TERMINAL))):
                    raise ValueError("read-only SSM command/Host identity differs")
                if observed_ssm["Status"] in _TERMINAL:
                    break
            time.sleep(2)
        if observed_ssm is None or observed_ssm.get("Status") != "Success":
            raise ValueError("read-only SSM inspection not confirmed successful")
        raw = observed_ssm.get("StandardOutputContent")
        if (type(raw) is not str or not raw.strip()
                or len(raw.encode("utf-8")) > 131072):
            raise ValueError("read-only SSM output missing or oversized")
        observation = json.loads(raw.strip())
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            TimeoutError) as error:
        raise ForwardingDenied(
            "selected compiler SSM read-only inspection is uncertain: " +
            str(error)) from error

    if (type(observation) is not dict
            or observation.get("schema") != PROJECT_OBSERVATION_SCHEMA
            or observation.get("project_root") != binding["project_root"]
            or observation.get("request_id") != request_id
            or observation.get("operation_id") != request_id
            or observation.get("evidence_source") != "local-selected-project"
            or type(observation.get("evidence")) is not dict
            or observation.get("mutation") is not False
            or observation.get("execution_authorized") is not False
            or type(observation.get("source_revision")) is not str
            or not REVISION.fullmatch(observation["source_revision"])
            or type(observation.get("terminal_confirmed")) is not bool
            or type(observation.get("uncertainty")) is not bool
            or observation["uncertainty"] is not (
                not observation["terminal_confirmed"])):
        raise ForwardingDenied("read-only selected-Host evidence differs")
    pipeline = observation.get("pipeline_id")
    if (pipeline is not None and
            (type(pipeline) is not str or not IDENTITY.fullmatch(pipeline))):
        raise ForwardingDenied("selected Project pipeline identity is invalid")
    if prior and (
        prior.get("source_revision") != observation["source_revision"]
        or (prior.get("pipeline_id") is not None
            and prior["pipeline_id"] != pipeline)
    ):
        raise ForwardingDenied("owned Project differs from original SSM producer")

    evidence = observation["evidence"]
    if (type(evidence.get("request_sha256")) is not str
            or type(evidence.get("pipeline_sha256")) is not (
                str if pipeline is not None else type(None))
            or type(evidence.get("evidence_sha256")) is not str
            or len(evidence["evidence_sha256"]) != 64):
        raise ForwardingDenied("selected Host evidence has no durable digest")
    if observation["terminal_confirmed"]:
        outcome = observation.get("terminal_outcome")
        if (observation.get("producer_status") == "completed"
                and outcome == "success"
                and observation.get("pipeline_status") == "complete"
                and type(observation.get("attempt_ids")) is list
                and observation["attempt_ids"]
                and len(evidence.get("attempt_statuses", {}))
                    == len(observation["attempt_ids"])):
            completion = "completed"
        elif (observation.get("producer_status") == "failed"
              and type(outcome) is str and outcome
              and observation.get("pipeline_status") == "pending"
              and type(evidence.get("result_sha256")) is str):
            completion = "failed"
        else:
            raise ForwardingDenied(
                "pipeline terminal outcome is not verified by selected Host")
    else:
        completion = "running" if pipeline is not None else "recovery_blocked"

    # The readback result and exact source/pipeline/attempt evidence digests
    # remain recorded under the original SSM CommandId. No sender is used.
    snapshot = {
        "schema": PROJECT_OBSERVATION_SCHEMA,
        "command_id": record["command_id"],
        "project_root": binding["project_root"],
        "source_revision": observation["source_revision"],
        "pipeline_id": pipeline,
        "pipeline_status": observation.get("pipeline_status"),
        "attempt_ids": observation.get("attempt_ids", []),
        "producer_status": observation.get("producer_status"),
        "terminal_outcome": observation.get("terminal_outcome"),
        "terminal_confirmed": observation["terminal_confirmed"],
        "evidence": evidence,
    }
    if completion in ("completed", "failed"):
        record_remote_result(root, request_id, snapshot, completion)
    else:
        mark_completion(root, request_id, completion)
    record_dispatch_observation(root, request_id, {
        "schema": "host-deploy-direct-ssm-observation-v1",
        "command_id": record["command_id"],
        "status": "reconciled-project",
        "producer": {
            "request_id": request_id,
            "source_revision": observation["source_revision"],
            "pipeline_id": pipeline,
            "status": observation.get("producer_status"),
            "uncertainty": not observation["terminal_confirmed"],
            "evidence_sha256": evidence["evidence_sha256"],
        },
    })
    return {"request_id": request_id, "command_id": record["command_id"],
            "phase": completion, "pipeline_id": pipeline}


def advance_one(root, *, host_factory=Host):
    """FIFO order for admitted direct tasks; no scanning for new sources."""
    directory = Path(root) / "requests"
    if not directory.exists():
        return None
    # SQS delivers in FIFO order but a restart may leave several admitted
    # requests in the durable ledger. Preserve their original receipt order;
    # lexicographic request IDs are not FIFO.
    ordered = []
    for request_id in valid_request_ids(root):
        candidate = directory / request_id
        transport = candidate / "transport.json"
        if transport.is_symlink() or not transport.is_file():
            raise ForwardingDenied("missing durable SQS delivery")
        try:
            value = json.loads(transport.read_text())
            arrival = value["first_seen_at"]
            if (type(arrival) is not str or not arrival.endswith("Z")
                    or value["request_id"] != candidate.name):
                raise ValueError("invalid FIFO receipt")
        except (KeyError, ValueError, TypeError):
            raise ForwardingDenied("invalid durable SQS delivery") from None
        ordered.append((arrival, request_id))
    for _, request_id in sorted(ordered):
        state = load_request(root, request_id)
        parameters = state["request"]["parameters"]
        if (state["states"]["admission"] != "admitted"
                or (state["request"]["operation"], parameters.get("task"))
                    not in SUPPORTED):
            continue
        if state["states"]["completion"] in (
                "completed", "failed", "timed_out", "cancelled"):
            continue
        return advance(root, request_id, host_factory=host_factory)
    return None
