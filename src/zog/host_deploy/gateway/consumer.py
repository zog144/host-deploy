"""Persistent SQS consumer for the GitHub-to-EC2 execution gateway."""

import argparse
import json
import os
from pathlib import Path

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
    def __init__(self, state_directory, primary_target, dead_letter_target, *, client):
        self.state_directory = Path(state_directory)
        self.client = client
        self.configuration = verify_queue_configuration(
            client, primary_target, dead_letter_target
        )

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
            return None
        result = self.handle_message(messages[0])
        reconcile_all(self.state_directory)
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

    dispatch_reconcile = commands.add_parser("dispatch-reconcile")
    dispatch_reconcile.add_argument("request_id")

    dispatch_submit = commands.add_parser("dispatch-submit")
    dispatch_submit.add_argument("request_id")

    dispatch_observe = commands.add_parser("dispatch-observe")
    dispatch_observe.add_argument("request_id")

    commands.add_parser("reconcile")

    arguments = parser.parse_args(argv)
    state_directory = Path(arguments.state_directory)

    if arguments.command in {"run", "queue-status"}:
        primary = _required(arguments.queue_target, "primary queue target")
        dead_letter = _required(
            arguments.dead_letter_target, "dead-letter queue target"
        )
        client = _client()
        if arguments.command == "queue-status":
            print(
                json.dumps(
                    administrative_status(
                        state_directory, primary, dead_letter, client
                    ),
                    sort_keys=True,
                )
            )
            return
        consumer = GatewayConsumer(
            state_directory, primary, dead_letter, client=client
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
                arguments.task_catalogue
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

    if arguments.command == "reconcile":
        result = reconcile_all(state_directory)
        print(json.dumps({"requests": len(result)}, sort_keys=True))
        return


if __name__ == "__main__":
    main()
