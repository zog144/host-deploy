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
    parse_receipt, project_current_completion, project_receipt_observation,
    PROJECT_RECEIPT_OBSERVATIONS, observe_project_command,
)
from .project_current_observation import (
    CONTROL_TIMEOUT_SECONDS as PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS,
    OBSERVATION_SCHEMA as PROJECT_OBSERVATION_SCHEMA,
)
from .ledger import (
    load_dispatch, load_request, mark_dispatch_submitting,
    mark_dispatch_submitted, mark_dispatch_uncertain, prepare_dispatch,
    mark_completion, record_dispatch_observation, record_remote_result,
    valid_request_ids, load_project_observation, record_project_reconciliation,
    LedgerConflict,
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
    if (record["phase"] == "prepared"
            and "controller_sha256" not in binding):
        # A frozen digestless historical record remains readable after its
        # ORIGINAL send, but can never acquire a NEW protected SSM send intent.
        # Root-control O_EXCL does not protect a previously unsent operation.
        raise ForwardingDenied(
            "digestless historical prepared Fonts dispatch cannot send")
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
    host = host_factory(configuration)
    observation = host.inspect_command(command_id)
    if binding.get("schema") == 4:
        try:
            state, latest, _ = observe_project_command(
                root, request_id, record, binding, configuration, observation,
                parser=parse_receipt, claim_factory=project_receipt_observation)
        except RuntimeError as error:
            raise ForwardingDenied(str(error)) from error
        phase = state["states"]["completion"]
        retained = latest["observation"] if latest else {}
        # Preserve the existing transport-facing submitted status for an
        # initial control-window poll; a producer claim/reconciliation
        # instead reports the durable Project completion state.
        if retained.get("schema") in PROJECT_RECEIPT_OBSERVATIONS or (
                retained.get("status") == "reconciled-project"):
            return {"request_id": request_id, "phase": phase,
                    "command_id": command_id,
                    "pipeline_id": retained.get("producer", {}).get("pipeline_id"),
                    "observation_required": phase in ("running", "recovery_blocked")}
        if observation is None:
            return {"request_id": request_id, "phase": "submitted",
                    "command_id": command_id, "status": "not-yet-visible"}
        if observation["Status"] in _RUNNING:
            return {"request_id": request_id, "phase": "submitted",
                    "command_id": command_id, "status": observation["Status"]}
        return {"request_id": request_id, "phase": phase,
                "command_id": command_id, "ssm_status": observation["Status"],
                "observation_required": phase == "recovery_blocked"}
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
    # A status-only re-poll must not erase the original retained receipt
    # source/pipeline claim needed for a later protected same-pipeline read.
    old_path = Path(root) / "requests" / request_id / "dispatch-observation.json"
    previous = json.loads(old_path.read_text()) if old_path.is_file() else None
    retained_claim = (
        type(previous) is dict and previous.get("command_id") == command_id
        and type(previous.get("observation")) is dict
        and previous["observation"].get("schema") in PROJECT_RECEIPT_OBSERVATIONS)
    if not retained_claim:
        record_dispatch_observation(root, request_id, summary)
    if status in _RUNNING:
        return {"request_id": request_id, "phase": "submitted",
                "command_id": command_id, "status": status}
    if status != "Success":
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
    # The historical 240/300-second request has an immutable terminal
    # failure record. A new read-only inspection cannot silently rewrite it.
    state = load_request(root, request_id)["states"]["completion"]
    if (state not in {"pending", "running", "recovery_blocked"}
            or (Path(root) / "requests" / request_id /
                "remote-result.json").exists()):
        raise ForwardingDenied(
            "terminal historical Gateway result must not be reclassified")
    config = verify_current_target(root, binding)
    from .project_current import REVISION, IDENTITY
    from .project_current_observation import read_only_observation_script

    try:
        selected = load_project_observation(root, request_id)
        latest = selected["latest"]
        prior = latest["observation"] if latest else {}
        if selected["claim"] is None and (
                prior.get("schema") in PROJECT_RECEIPT_OBSERVATIONS
                or prior.get("status") == "reconciled-project"):
            # A pre-upgrade latest record may have lost the original claim.
            # Read C itself, never construct a claim from a later Project.
            original = host_factory(config).inspect_command(record["command_id"])
            if original is None or original.get("Status") not in (
                    "Success", "Failed", "TimedOut", "Cancelled"):
                raise ForwardingDenied("original SSM receipt readback required")
            observe_project_command(root, request_id, record, binding, config, original,
                                    parser=parse_receipt,
                                    claim_factory=project_receipt_observation)
            selected = load_project_observation(root, request_id)
            latest = selected["latest"]
            prior = latest["observation"] if latest else {}
            if (selected["claim"] is None and
                    prior.get("schema") in PROJECT_RECEIPT_OBSERVATIONS):
                raise ForwardingDenied("original SSM receipt readback required")
        # Prefer the most specific retained Project identity when the
        # original receipt did not yet identify a pipeline.
        producer = prior.get("producer", {})
        if selected["claim"] is not None:
            producer = (producer if prior.get("status") == "reconciled-project"
                        else selected["claim"]["producer"])
        if type(producer) is not dict:
            raise ForwardingDenied("previous Project producer identity is invalid")
        prior = producer
    except (RuntimeError, ValueError, KeyError, TypeError) as error:
        raise ForwardingDenied(str(error)) from error

    expected_pipeline = prior.get("pipeline_id")
    if (expected_pipeline is not None and
            (type(expected_pipeline) is not str
             or not IDENTITY.fullmatch(expected_pipeline))):
        raise ForwardingDenied("retained pipeline identity is invalid")
    # This fixed observer is sent by its own protected root-control journal
    # operation, never through a direct Gateway Host.submit_command fallback.
    script = read_only_observation_script(
        binding["project_root"], binding["python_executable"], request_id,
        pipeline_id=expected_pipeline)
    from . import fonts_inspection_owner as inspection_owner
    try:
        host = host_factory(config)
        inspection_number, inspection_id = inspection_owner.submit_or_recover(
            root, request_id, binding=binding, target=binding["target"],
            original_command_id=record["command_id"],
            pipeline_id=expected_pipeline, script=script, host=host)
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
                    inspection_owner.finish(
                        root, request_id, inspection_number, inspection_id,
                        status=observed_ssm["Status"])
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
            or type(observation.get("project_owner_uid")) is not int
            or observation["project_owner_uid"] != FIRST_FONTS_COMPILER_PROJECT_UID
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
    evidence_digest = evidence.get("evidence_sha256")
    computed_digest = hashlib.sha256(json.dumps(
        {key: value for key, value in evidence.items()
         if key != "evidence_sha256"},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")).hexdigest()
    if (type(evidence.get("request_sha256")) is not str
            or type(evidence.get("pipeline_sha256")) is not (
                str if pipeline is not None else type(None))
            or type(evidence_digest) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", evidence_digest)
            or computed_digest != evidence_digest):
        raise ForwardingDenied("selected compiler evidence digest differs")
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

    # The readback result is bound to its separately journaled inspection
    # CommandId and the unchanged original protected build CommandId.
    snapshot = {
        "schema": PROJECT_OBSERVATION_SCHEMA,
        "command_id": record["command_id"],
        "inspection_command_id": inspection_id,
        "compiler_instance_id": config["instance_id"],
        "project_root": binding["project_root"],
        "project_owner_uid": observation["project_owner_uid"],
        "source_revision": observation["source_revision"],
        "pipeline_id": pipeline,
        "pipeline_status": observation.get("pipeline_status"),
        "attempt_ids": observation.get("attempt_ids", []),
        "producer_status": observation.get("producer_status"),
        "terminal_outcome": observation.get("terminal_outcome"),
        "terminal_confirmed": observation["terminal_confirmed"],
        "evidence": evidence,
    }
    latest = {
        "schema": "host-deploy-direct-ssm-observation-v1",
        "command_id": record["command_id"],
        "inspection_command_id": inspection_id,
        "compiler_instance_id": config["instance_id"],
        "status": "reconciled-project",
        "producer": {
            "request_id": request_id,
            "source_revision": observation["source_revision"],
            "pipeline_id": pipeline,
            "status": observation.get("producer_status"),
            "uncertainty": not observation["terminal_confirmed"],
            "evidence_sha256": evidence["evidence_sha256"],
        },
    }
    try:
        record_project_reconciliation(root, request_id, expected=selected,
                                      observation=latest, result=snapshot,
                                      completion=completion)
    except LedgerConflict as error:
        raise ForwardingDenied(str(error)) from error
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
