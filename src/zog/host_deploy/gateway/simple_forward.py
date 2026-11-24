"""Finite GitHub/SQS -> SSM forwarding. No compiler dossier or catalogue.

GitHub Actions validates issue-opened identity and allowlist before SQS.
The trusted-Host queue/owned workspace and schema-5 lane select the SSM target,
document and installed image-build executable. The producer selects the active
toolchain and immutable recipe snapshot from its own Project. One fsynced intent = one SendCommand
attempt, even if the CommandId acknowledgement is lost.
"""
import json
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
    host = host_factory(configuration)
    command_id = record["command_id"]
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


def reconcile_project_observation(root, request_id, observation):
    """Explicitly reconcile a trusted read-only Host observation, never send.

    The caller must obtain this JSON from the reviewed Project-current
    read_only_observation_script on the already selected Host. No SQS field
    or untrusted issue body may supply this evidence. The original request,
    SSM CommandId and Project binding remain immutable.
    """
    record, binding = _frozen_binding(root, request_id)
    if record["phase"] != "submitted" or binding.get("schema") != 4:
        raise ForwardingDenied("observation requires submitted Project-current request")
    from .project_current import REVISION, IDENTITY
    if (type(observation) is not dict
            or observation.get("schema") != PROJECT_OBSERVATION_SCHEMA
            or observation.get("request_id") != request_id
            or observation.get("operation_id") != request_id
            or observation.get("project_root") != binding["project_root"]
            or observation.get("mutation") is not False
            or observation.get("execution_authorized") is not False
            or type(observation.get("source_revision")) is not str
            or not REVISION.fullmatch(observation["source_revision"])
            or type(observation.get("terminal_confirmed")) is not bool
            or type(observation.get("uncertainty")) is not bool
            or observation["uncertainty"] is not (
                not observation["terminal_confirmed"])):
        raise ForwardingDenied("read-only Project observation identity or status differs")
    pipeline = observation.get("pipeline_id")
    if (pipeline is not None and
            (type(pipeline) is not str or not IDENTITY.fullmatch(pipeline))):
        raise ForwardingDenied("read-only Project pipeline identity is invalid")
    previous_path = Path(root) / "requests" / request_id / "dispatch-observation.json"
    if previous_path.exists():
        previous = json.loads(previous_path.read_text())["observation"]
        prior = previous.get("producer", {})
        if prior and (prior.get("source_revision") != observation["source_revision"]
                      or (prior.get("pipeline_id") is not None and
                          prior.get("pipeline_id") != pipeline)):
            raise ForwardingDenied("read-only observation differs from original producer")
    if observation["terminal_confirmed"]:
        terminal = observation.get("producer_status")
        if terminal == "completed" and observation.get("terminal_outcome") == "success":
            completion = "completed"
        elif terminal == "failed" and observation.get("terminal_outcome"):
            completion = "failed"
        else:
            raise ForwardingDenied("producer terminal outcome is not authenticated")
    else:
        completion = "running" if pipeline is not None else "recovery_blocked"
    snapshot = {"schema": PROJECT_OBSERVATION_SCHEMA,
                "command_id": record["command_id"],
                "source_revision": observation["source_revision"],
                "pipeline_id": pipeline,
                "status": observation.get("producer_status"),
                "pipeline_status": observation.get("pipeline_status"),
                "attempt_ids": observation.get("attempt_ids", []),
                "terminal_confirmed": observation["terminal_confirmed"]}
    if completion in ("completed", "failed"):
        record_remote_result(root, request_id, snapshot, completion)
    else:
        mark_completion(root, request_id, completion)
    # Observations are append/replace evidence, never a new SSM SendCommand.
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
