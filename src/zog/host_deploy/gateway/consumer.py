"""Persistent SQS consumer for the GitHub-to-EC2 execution gateway."""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..workspace import save as atomic_save

from .ledger import (
    LedgerConflict,
    accept,
    claim_handoff,
    dispatcher_lock,
    load_dispatch,
    load_request,
    reconcile_all,
    reconcile_dispatch,
    reconcile_request,
    record_acknowledgement,
    record_failure,
    release_handoff,
    summary as ledger_summary,
)
from .adoption import (
    adopt_workspace,
    load_adoption,
    load_request as load_adoption_request,
    recover_rejected_adoption,
)
from .image_build_dispatch import prepare_image_build_dispatch
from .image_build_execution import observe_submitted, submit_prepared
from .task_catalogue import load as load_task_catalogue
from .generic_pipeline import advance as advance_generic, status as generic_status
from .toolchain_task import load as load_toolchain_task
from .toolchain_supervisor import (
    advance as advance_toolchain, status as toolchain_status,
    authorize_resume as authorize_toolchain_resume,
    authorize_recovery as authorize_toolchain_recovery,
)
from .generic_reporting import progress as generic_progress
from .protocol import RequestProtocolError, loads_request
from .queues import (
    AWS_REGION,
    DEAD_LETTER_QUEUE_NAME,
    PRIMARY_QUEUE_NAME,
    canonical_queue_target,
    queue_status,
    verify_queue_configuration,
)


DEFAULT_STATE_DIRECTORY = "/var/lib/host-deploy-gateway"
VISIBILITY_TIMEOUT_SECONDS = 60
LONG_POLL_SECONDS = 20
REVIEWED_MINIMUM_ADVANCE_SECONDS = 15
REVIEWED_ADVANCE_MARKER = "reviewed-generic-advance.json"


def _reviewed_clock():
    return datetime.now(timezone.utc)


def _reserve_reviewed_advance(root, request_id, catalogue_identity):
    """Durably bound one globally rate-limited supervisor action before work.

    Called only while holding dispatcher_lock: per-poll SQS volume cannot
    accelerate SSM mutation. A lost/restarted action retains its marker.
    """
    root = Path(root)
    path = root / REVIEWED_ADVANCE_MARKER
    now = _reviewed_clock().astimezone(timezone.utc)
    if path.is_symlink():
        raise RuntimeError("reviewed supervisor marker is a symlink")
    if path.exists():
        if not path.is_file() or path.stat().st_size > 4096:
            raise RuntimeError("reviewed supervisor marker is unsafe")
        try:
            marker = json.loads(path.read_text())
            when = datetime.fromisoformat(marker["reserved_at"])
            if (type(marker) is not dict or set(marker) != {
                    "schema", "reserved_at", "request_id", "catalogue_sha256"}
                    or marker["schema"] != 1 or when.tzinfo is None
                    or type(marker["request_id"]) is not str
                    or len(marker["request_id"]) != 32
                    or type(marker["catalogue_sha256"]) is not str
                    or not marker["catalogue_sha256"].startswith("sha256:")):
                raise ValueError("invalid marker")
            when = when.astimezone(timezone.utc)
        except (OSError, ValueError, KeyError, TypeError):
            raise RuntimeError("reviewed supervisor marker is corrupted") from None
        if when > now + timedelta(seconds=5):
            raise RuntimeError("reviewed supervisor clock moved backwards")
        if now - when < timedelta(seconds=REVIEWED_MINIMUM_ADVANCE_SECONDS):
            return False
    atomic_save(path, {
        "schema": 1,
        "reserved_at": now.isoformat(),
        "request_id": request_id,
        "catalogue_sha256": catalogue_identity,
    })
    return True


def _receive_count(message):
    attributes = message.get("Attributes")
    if not isinstance(attributes, dict):
        return 1
    raw = attributes.get("ApproximateReceiveCount", "1")
    try:
        count = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(1, min(count, 1_000_000))


class GatewayConsumer:
    def __init__(self, state_directory, primary_target, dead_letter_target, *,
                 client, approved_generic_catalogue=None,
                 approved_catalogue_identity=None, approved_catalogue_path=None,
                 approved_toolchain_task=None, approved_toolchain_identity=None,
                 approved_toolchain_path=None):
        self.state_directory = Path(state_directory)
        self.client = client
        self.configuration = verify_queue_configuration(
            client, primary_target, dead_letter_target
        )
        if ((approved_generic_catalogue is None)
                != (approved_catalogue_identity is None)):
            raise ValueError("reviewed generic catalogue must have exact digest")
        self.approved_generic_catalogue = approved_generic_catalogue
        self.approved_catalogue_identity = approved_catalogue_identity
        self.approved_catalogue_path = approved_catalogue_path
        if ((approved_toolchain_task is None)
                != (approved_toolchain_identity is None)):
            raise ValueError("reviewed toolchain task requires exact digest")
        self.approved_toolchain_task = approved_toolchain_task
        self.approved_toolchain_identity = approved_toolchain_identity
        self.approved_toolchain_path = approved_toolchain_path

    def _advance_one_reviewed(self):
        """At most one stage across durable admitted requests per iteration.

        Operator-enabled only; status-only and external-observed-state jobs
        continue using their separate explicit administrative commands.
        """
        if self.approved_generic_catalogue is None:
            return None
        if getattr(self, "approved_catalogue_path", None):
            current, identity = load_task_catalogue(
                self.approved_catalogue_path, require_root_owned=True
            )
            if (identity != self.approved_catalogue_identity
                    or current != self.approved_generic_catalogue):
                raise RuntimeError(
                    "reviewed generic catalogue changed: supervisor authorization revoked"
                )
        root = self.state_directory / "requests"
        if not root.exists():
            return None
        for candidate in sorted(root.iterdir()):
            if not candidate.is_dir() or candidate.is_symlink():
                raise RuntimeError("unsafe gateway request directory")
            request_id = candidate.name
            state = load_request(self.state_directory, request_id)
            if (state["request"]["operation"] != "build.submit"
                    or state["states"]["admission"] != "admitted"):
                continue
            dispatch = load_dispatch(self.state_directory, request_id)
            if dispatch is None:
                if not _reserve_reviewed_advance(
                        self.state_directory, request_id,
                        self.approved_catalogue_identity):
                    return None
                prepare_image_build_dispatch(
                    self.state_directory, request_id,
                    task_catalogue=self.approved_generic_catalogue,
                    task_catalogue_identity=self.approved_catalogue_identity,
                )
                return {"request_id": request_id, "action": "prepared"}
            if dispatch["phase"] != "prepared":
                continue
            # A retained dispatch is immutable, but automatic permission to
            # advance it is revocable: replacement of the protected task
            # catalogue must not continue an old job in the background.
            approved = dispatch.get("binding")
            if (type(approved) is not dict
                    or approved.get("task_catalogue_identity")
                    != self.approved_catalogue_identity):
                raise RuntimeError(
                    "reviewed generic catalogue changed since dispatch preparation; "
                    "manual owner reconciliation required"
                )
            current = generic_status(self.state_directory, request_id)
            if current["phase"] in ("uncertain", "failed", "completed"):
                continue
            if not _reserve_reviewed_advance(
                    self.state_directory, request_id,
                    self.approved_catalogue_identity):
                return None
            advance_generic(self.state_directory, request_id)
            return {"request_id": request_id, "action": "advanced"}
        return None

    def _advance_one_toolchain(self):
        """Explicitly approved typed toolchain work, at most one step per poll."""
        if self.approved_toolchain_task is None:
            return None
        task, digest = load_toolchain_task(
            self.approved_toolchain_path, require_root_owned=True
        )
        if (digest != self.approved_toolchain_identity
                or task != self.approved_toolchain_task):
            raise RuntimeError("protected typed toolchain task changed")
        request_root = self.state_directory / "requests"
        if not request_root.exists():
            return None
        for entry in sorted(request_root.iterdir()):
            if entry.is_symlink() or not entry.is_dir():
                raise RuntimeError("unsafe gateway request directory")
            request_id = entry.name
            state = load_request(self.state_directory, request_id)
            if (state["request"]["operation"] != "toolchain.submit"
                    or state["states"]["admission"] != "admitted"):
                continue
            dispatch = load_dispatch(self.state_directory, request_id)
            if dispatch is None:
                if not _reserve_reviewed_advance(
                        self.state_directory, request_id,
                        self.approved_toolchain_identity):
                    return None
                prepare_image_build_dispatch(
                    self.state_directory, request_id,
                    task_catalogue=self.approved_toolchain_task,
                    task_catalogue_identity=self.approved_toolchain_identity,
                )
                return {"request_id": request_id, "action": "toolchain-prepared"}
            if dispatch["phase"] != "prepared":
                continue
            frozen = dispatch["binding"]
            if (frozen.get("task_catalogue_identity")
                    != self.approved_toolchain_identity
                    or frozen.get("task") != self.approved_toolchain_task["task"]):
                raise RuntimeError("typed toolchain task authorization changed")
            current = toolchain_status(self.state_directory, request_id)
            if current["status"] in (
                    "completed", "failed", "uncertain", "awaiting_recovery"):
                continue
            if not _reserve_reviewed_advance(
                    self.state_directory, request_id,
                    self.approved_toolchain_identity):
                return None
            advance_toolchain(self.state_directory, request_id)
            return {"request_id": request_id, "action": "toolchain-advanced"}
        return None

    @property
    def primary_url(self):
        return self.configuration["primary_url"]

    def _failure(self, message, error):
        record_failure(
            self.state_directory,
            message_id=message.get("MessageId", "unknown"),
            receive_count=_receive_count(message),
            body=message.get("Body", ""),
            error=error,
        )

    def handle_message(self, message):
        message_id = message.get("MessageId")
        receipt = message.get("ReceiptHandle")
        body = message.get("Body")
        receive_count = _receive_count(message)
        if not isinstance(message_id, str) or not message_id:
            error = ValueError("SQS message has no MessageId")
            self._failure(message, error)
            return {"accepted": False, "error": str(error)}
        if not isinstance(receipt, str) or not receipt:
            error = ValueError("SQS message has no ReceiptHandle")
            self._failure(message, error)
            return {"accepted": False, "error": str(error)}
        if not isinstance(body, str):
            error = ValueError("SQS message body is not text")
            self._failure(message, error)
            return {"accepted": False, "error": str(error)}

        try:
            request = loads_request(body)
            state, duplicate = accept(
                self.state_directory,
                request,
                message_id=message_id,
                receive_count=receive_count,
            )
        except (RequestProtocolError, LedgerConflict, ValueError) as error:
            self._failure(message, error)
            return {"accepted": False, "error": str(error)}

        record_acknowledgement(
            self.state_directory,
            request["request_id"],
            "delete_attempting",
        )
        try:
            self.client.delete_message(
                QueueUrl=self.primary_url,
                ReceiptHandle=receipt,
            )
        except Exception as error:
            record_acknowledgement(
                self.state_directory,
                request["request_id"],
                "delete_uncertain",
                error=error,
            )
            return {
                "accepted": True,
                "duplicate": duplicate,
                "request_id": request["request_id"],
                "acknowledgement": "delete_uncertain",
            }

        record_acknowledgement(
            self.state_directory,
            request["request_id"],
            "acked",
        )
        try:
            state = reconcile_request(
                self.state_directory,
                request["request_id"],
            )
            admission = state["states"]["admission"]
        except Exception as error:
            # The request and transport acknowledgement are already durable.
            # Preserve evidence, then stop this service iteration so a storage
            # or integrity fault cannot be silently bypassed.
            record_failure(
                self.state_directory,
                message_id=message_id,
                receive_count=receive_count,
                body=body,
                error=error,
            )
            raise
        return {
            "accepted": True,
            "duplicate": duplicate,
            "request_id": request["request_id"],
            "acknowledgement": "acked",
            "admission": admission,
        }

    def poll_once(self, *, wait_seconds=LONG_POLL_SECONDS):
        response = self.client.receive_message(
            QueueUrl=self.primary_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=wait_seconds,
            VisibilityTimeout=VISIBILITY_TIMEOUT_SECONDS,
            AttributeNames=["ApproximateReceiveCount"],
        )
        messages = response.get("Messages", [])
        if not messages:
            reconcile_all(self.state_directory)
            self._advance_one_reviewed()
            self._advance_one_toolchain()
            return None
        result = self.handle_message(messages[0])
        reconcile_all(self.state_directory)
        self._advance_one_reviewed()
        self._advance_one_toolchain()
        return result

    def run(self):
        with dispatcher_lock(self.state_directory):
            reconcile_all(self.state_directory)
            while True:
                self.poll_once()


def _client():
    import boto3

    return boto3.client("sqs", region_name=AWS_REGION)


def _required(value, name):
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def administrative_status(state_directory, primary_target, dead_letter_target, client):
    return {
        "queues": queue_status(client, primary_target, dead_letter_target),
        "ledger": ledger_summary(state_directory),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="host-deploy-gateway")
    parser.add_argument(
        "--state-directory",
        default=os.environ.get("ZOG_GATEWAY_STATE_DIRECTORY", DEFAULT_STATE_DIRECTORY),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run")
    run.add_argument(
        "--queue-target",
        default=os.environ.get("ZOG_BUILD_REQUEST_QUEUE_URL"),
    )
    run.add_argument(
        "--dead-letter-target",
        default=os.environ.get("ZOG_BUILD_DEAD_LETTER_QUEUE_URL"),
    )
    run.add_argument("--once", action="store_true")
    run.add_argument(
        "--advance-reviewed-generic", action="store_true",
        help="Explicit reviewed-operator opt-in to supervised generic stages",
    )
    run.add_argument(
        "--approved-task-catalogue",
        help="Absolute root-owned, readonly finite generic build catalogue",
    )
    run.add_argument(
        "--approved-task-catalogue-sha256",
        help="Exact separately reviewed catalogue SHA-256; prevents silent repin on restart",
    )

    run.add_argument("--advance-reviewed-toolchain", action="store_true",
                     help="Explicit owner opt-in to pinned typed toolchain supervisor")
    run.add_argument("--approved-toolchain-task",
                     help="Root-owned, readonly typed toolchain task definition")
    run.add_argument("--approved-toolchain-task-sha256",
                     help="Exact reviewed typed toolchain task SHA-256")

    status = commands.add_parser("queue-status")
    status.add_argument(
        "--queue-target",
        default=os.environ.get("ZOG_BUILD_REQUEST_QUEUE_URL"),
    )
    status.add_argument(
        "--dead-letter-target",
        default=os.environ.get("ZOG_BUILD_DEAD_LETTER_QUEUE_URL"),
    )

    claim = commands.add_parser("claim-handoff")
    claim.add_argument("checkpoint")

    release = commands.add_parser("release-handoff")
    release.add_argument("workspace_id")
    release.add_argument("output")

    adopt = commands.add_parser("adopt-workspace")
    adopt.add_argument("request_file")

    adoption_status = commands.add_parser("adoption-status")
    adoption_status.add_argument("operation_id")

    recover_rejected = commands.add_parser("recover-rejected-adoption")
    recover_rejected.add_argument("request_file")

    inspect = commands.add_parser("request")
    inspect.add_argument("request_id")

    dispatch_status = commands.add_parser("dispatch-status")
    dispatch_status.add_argument("request_id")

    dispatch_prepare = commands.add_parser("dispatch-prepare")
    dispatch_prepare.add_argument("request_id")
    dispatch_prepare.add_argument(
        "--task-catalogue",
        default=os.environ.get("ZOG_GATEWAY_TASK_CATALOGUE"),
    )

    dispatch_prepare.add_argument("--toolchain-task",
        help="Exact protected local toolchain task definition")

    dispatch_reconcile = commands.add_parser("dispatch-reconcile")
    dispatch_reconcile.add_argument("request_id")

    dispatch_submit = commands.add_parser("dispatch-submit")
    dispatch_submit.add_argument("request_id")

    dispatch_observe = commands.add_parser("dispatch-observe")
    dispatch_observe.add_argument("request_id")

    generic_step = commands.add_parser("generic-advance")
    generic_step.add_argument("request_id")
    generic_read = commands.add_parser("generic-status")
    generic_read.add_argument("request_id")
    progress_cmd = commands.add_parser("generic-progress")
    progress_cmd.add_argument("request_id")

    typed = commands.add_parser("toolchain-advance")
    typed.add_argument("request_id")
    typed = commands.add_parser("toolchain-status")
    typed.add_argument("request_id")
    typed = commands.add_parser("toolchain-authorize-resume")
    typed.add_argument("request_id")
    typed.add_argument("phase")
    typed = commands.add_parser("toolchain-authorize-recovery")
    typed.add_argument("request_id")

    commands.add_parser("reconcile")

    arguments = parser.parse_args(argv)
    state_directory = Path(arguments.state_directory)

    if arguments.command in {"run", "queue-status"}:
        primary = _required(arguments.queue_target, "primary queue target")
        dead_letter = _required(
            arguments.dead_letter_target, "dead-letter queue target"
        )
        if arguments.command == "queue-status":
            client = _client()
            print(
                json.dumps(
                    administrative_status(
                        state_directory, primary, dead_letter, client
                    ),
                    sort_keys=True,
                )
            )
            return
        if (arguments.approved_task_catalogue or
                arguments.approved_task_catalogue_sha256) and not arguments.advance_reviewed_generic:
            parser.error("reviewed generic catalogue requires explicit opt-in")
        catalogue = None
        digest = None
        if arguments.advance_reviewed_generic:
            if not (arguments.approved_task_catalogue and
                    arguments.approved_task_catalogue_sha256):
                parser.error("opt-in requires catalogue path and reviewed SHA-256")
            catalogue, digest = load_task_catalogue(
                arguments.approved_task_catalogue, require_root_owned=True)
            if digest != arguments.approved_task_catalogue_sha256:
                parser.error("reviewed catalogue digest differs from supervisor policy")
        if (arguments.approved_toolchain_task or
                arguments.approved_toolchain_task_sha256) and not arguments.advance_reviewed_toolchain:
            parser.error("typed toolchain definition requires explicit supervisor opt-in")
        protected = None
        protected_identity = None
        if arguments.advance_reviewed_toolchain:
            if not (arguments.approved_toolchain_task
                    and arguments.approved_toolchain_task_sha256):
                parser.error("toolchain supervisor requires task path and SHA-256")
            protected, protected_identity = load_toolchain_task(
                arguments.approved_toolchain_task, require_root_owned=True
            )
            if protected_identity != arguments.approved_toolchain_task_sha256:
                parser.error("typed toolchain approval digest differs")
        # Do not allocate any AWS client until root-owned approval is verified.
        client = _client()
        consumer = GatewayConsumer(
            state_directory, primary, dead_letter, client=client,
            approved_generic_catalogue=catalogue,
            approved_catalogue_identity=digest,
            approved_catalogue_path=arguments.approved_task_catalogue,
            approved_toolchain_task=protected,
            approved_toolchain_identity=protected_identity,
            approved_toolchain_path=arguments.approved_toolchain_task,
        )
        if arguments.once:
            with dispatcher_lock(state_directory):
                result = consumer.poll_once(wait_seconds=0)
            print(json.dumps(result, sort_keys=True))
            return
        consumer.run()
        return

    if arguments.command == "claim-handoff":
        print(
            json.dumps(
                claim_handoff(state_directory, arguments.checkpoint),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "release-handoff":
        print(
            json.dumps(
                release_handoff(
                    state_directory,
                    arguments.workspace_id,
                    arguments.output,
                ),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "adopt-workspace":
        request = load_adoption_request(arguments.request_file)
        print(
            json.dumps(
                adopt_workspace(state_directory, request),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "adoption-status":
        print(
            json.dumps(
                load_adoption(state_directory, arguments.operation_id),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "recover-rejected-adoption":
        request = load_adoption_request(arguments.request_file)
        print(
            json.dumps(
                recover_rejected_adoption(state_directory, request),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "request":
        print(
            json.dumps(
                load_request(state_directory, arguments.request_id),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "dispatch-status":
        print(
            json.dumps(
                load_dispatch(state_directory, arguments.request_id),
                sort_keys=True,
            )
        )
        return

    if arguments.command == "dispatch-prepare":
        catalogue = None
        catalogue_identity = None
        if arguments.task_catalogue:
            catalogue, catalogue_identity = load_task_catalogue(
                arguments.task_catalogue, require_root_owned=True
            )
        if arguments.toolchain_task:
            if catalogue is not None:
                parser.error("select exactly one generic or toolchain catalogue")
            catalogue, catalogue_identity = load_toolchain_task(
                arguments.toolchain_task, require_root_owned=True
            )
        state, record = prepare_image_build_dispatch(
            state_directory,
            arguments.request_id,
            task_catalogue=catalogue,
            task_catalogue_identity=catalogue_identity,
        )
        print(
            json.dumps(
                {"states": state["states"], "dispatch": record},
                sort_keys=True,
            )
        )
        return

    if arguments.command == "dispatch-reconcile":
        state = reconcile_dispatch(
            state_directory,
            arguments.request_id,
        )
        print(json.dumps({"states": state["states"]}, sort_keys=True))
        return

    if arguments.command == "dispatch-submit":
        state, record = submit_prepared(
            state_directory,
            arguments.request_id,
        )
        print(
            json.dumps(
                {"states": state["states"], "dispatch": record},
                sort_keys=True,
            )
        )
        return

    if arguments.command == "dispatch-observe":
        state, observation, result = observe_submitted(
            state_directory,
            arguments.request_id,
        )
        print(
            json.dumps(
                {
                    "states": state["states"],
                    "observation": observation,
                    "remote_result": result,
                },
                sort_keys=True,
            )
        )
        return

    if arguments.command == "generic-progress":
        print(json.dumps(
            generic_progress(state_directory, arguments.request_id),
            sort_keys=True,
        ))
        return

    if arguments.command in {"generic-advance", "generic-status"}:
        # Intentional supervised operator action; no SQS consumer side effect.
        with dispatcher_lock(state_directory):
            value = (advance_generic(state_directory, arguments.request_id)
                     if arguments.command == "generic-advance"
                     else generic_status(state_directory, arguments.request_id))
        print(json.dumps(value, sort_keys=True))
        return

    if arguments.command in (
            "toolchain-advance", "toolchain-status",
            "toolchain-authorize-resume", "toolchain-authorize-recovery"):
        with dispatcher_lock(state_directory):
            if arguments.command == "toolchain-advance":
                value = advance_toolchain(state_directory, arguments.request_id)
            elif arguments.command == "toolchain-status":
                value = toolchain_status(state_directory, arguments.request_id)
            elif arguments.command == "toolchain-authorize-resume":
                value = authorize_toolchain_resume(
                    state_directory, arguments.request_id, arguments.phase)
            else:
                value = authorize_toolchain_recovery(
                    state_directory, arguments.request_id)
        print(json.dumps(value, sort_keys=True))
        return

    if arguments.command == "reconcile":
        result = reconcile_all(state_directory)
        print(json.dumps({"requests": len(result)}, sort_keys=True))
        return


if __name__ == "__main__":
    main()
