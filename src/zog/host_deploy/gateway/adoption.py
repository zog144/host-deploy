"""Explicit recovery/adoption for a host whose original workspace checkpoint is unavailable.

Adoption is deliberately separate from checkpoint claim.  It records the historical
gap, requires writer acknowledgements, binds the live EC2 identity, installs a
remote ownership epoch, and only then creates a gateway-owned workspace.
"""

from __future__ import annotations

from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
from pathlib import Path
import re
import uuid

from botocore.exceptions import ClientError

from ..provision import Cloud
from ..runner import Host
from ..workspace import save
from .ledger import ensure_root, utc_now


SCHEMA = 1
OWNER = "host-deploy-gateway"
REMOTE_MARKER = "/var/lib/host-deploy/ownership.json"
_HEX_32 = re.compile(r"[0-9a-f]{32}")
_ACCOUNT = re.compile(r"[0-9]{12}")
_INSTANCE = re.compile(r"i-[0-9a-f]{8,32}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+ -]{0,127}")
_WRITER = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")


class AdoptionConflict(RuntimeError):
    """The adoption identity or ownership evidence conflicts with retained state."""


@contextmanager
def _ownership_lock(root):
    root = ensure_root(root)
    directory = root / "ownership"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "adoption.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield root


def _identity(value, label):
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise ValueError("invalid " + label)
    if uuid.UUID(value).hex != value:
        raise ValueError("invalid " + label)
    return value


def _canonical(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ValueError("adoption request must be finite JSON") from None


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _error_sha256(value):
    return hashlib.sha256(
        str(value).encode("utf-8", errors="replace")
    ).hexdigest()


def _definite_send_command_rejection(error):
    """Classify only synchronous AWS rejection known not to create an SSM command."""
    if not isinstance(error, ClientError):
        return None
    if getattr(error, "operation_name", None) != "SendCommand":
        return None
    response = error.response if isinstance(error.response, dict) else {}
    detail = response.get("Error") if isinstance(response.get("Error"), dict) else {}
    code = detail.get("Code")
    if code != "AccessDeniedException":
        return None
    return {
        "schema": 1,
        "operation": "SendCommand",
        "code": code,
        "message": str(detail.get("Message", ""))[:512],
        "error_sha256": _error_sha256(error),
    }


def _retained_definite_rejection(record):
    rejection = record.get("rejection")
    if (
        isinstance(rejection, dict)
        and rejection.get("schema") == 1
        and rejection.get("operation") == "SendCommand"
        and rejection.get("code") == "AccessDeniedException"
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(rejection.get("error_sha256", "")),
        )
        and not record.get("marker_command_id")
    ):
        return json.loads(json.dumps(rejection))

    # Compatibility for the live record retained by the pre-recovery implementation.
    error = record.get("error")
    if (
        record.get("phase") == "marker_uncertain"
        and not record.get("marker_command_id")
        and isinstance(error, str)
        and "AccessDeniedException" in error
        and "SendCommand" in error
        and "ssm:SendCommand" in error
        and "not authorized to perform" in error
    ):
        return {
            "schema": 1,
            "operation": "SendCommand",
            "code": "AccessDeniedException",
            "message": error[:512],
            "error_sha256": _error_sha256(error),
            "legacy_unstructured": True,
        }
    return None


def validate_request(value):
    required = {
        "schema",
        "operation_id",
        "workspace_id",
        "name",
        "profile",
        "region",
        "account_id",
        "instance_id",
        "target_owner",
        "missing_original_checkpoint",
        "operator_authorization",
        "saved_state_hashes",
        "expected_writer_set",
        "writer_acknowledgements",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("unsupported adoption request fields")
    if value["schema"] != SCHEMA or type(value["schema"]) is not int:
        raise ValueError("unsupported adoption request schema")
    _identity(value["operation_id"], "adoption operation_id")
    _identity(value["workspace_id"], "adoption workspace_id")
    if not isinstance(value["name"], str) or not _NAME.fullmatch(value["name"]):
        raise ValueError("invalid adoption workspace name")
    profile = value["profile"]
    if profile is not None and (
        not isinstance(profile, str)
        or not profile
        or len(profile) > 128
        or any(ord(c) < 32 for c in profile)
    ):
        raise ValueError("invalid adoption AWS profile")
    if (
        not isinstance(value["region"], str)
        or not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", value["region"])
    ):
        raise ValueError("invalid adoption AWS region")
    if not isinstance(value["account_id"], str) or not _ACCOUNT.fullmatch(
        value["account_id"]
    ):
        raise ValueError("invalid adoption AWS account")
    if not isinstance(value["instance_id"], str) or not _INSTANCE.fullmatch(
        value["instance_id"]
    ):
        raise ValueError("invalid adoption EC2 instance")
    if value["target_owner"] != OWNER:
        raise ValueError("adoption target owner must be host-deploy-gateway")
    if value["missing_original_checkpoint"] is not True:
        raise ValueError("lost-workspace adoption requires explicit missing checkpoint evidence")
    authorization = value["operator_authorization"]
    if (
        not isinstance(authorization, str)
        or not authorization.strip()
        or len(authorization) > 512
        or any(ord(c) < 32 for c in authorization)
    ):
        raise ValueError("adoption requires bounded operator authorization")

    evidence = value["saved_state_hashes"]
    if (
        not isinstance(evidence, dict)
        or not evidence
        or len(evidence) > 32
        or any(
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", name)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for name, digest in evidence.items()
        )
    ):
        raise ValueError("adoption saved_state_hashes are invalid")

    expected = value["expected_writer_set"]
    acknowledgements = value["writer_acknowledgements"]
    if (
        not isinstance(expected, list)
        or not expected
        or len(expected) > 32
        or any(not isinstance(item, str) or not _WRITER.fullmatch(item) for item in expected)
        or len(set(expected)) != len(expected)
    ):
        raise ValueError("adoption expected_writer_set is invalid")
    if (
        not isinstance(acknowledgements, list)
        or len(acknowledgements) != len(expected)
    ):
        raise ValueError("adoption requires one acknowledgement per expected writer")
    writers = []
    cleaned = []
    for item in acknowledgements:
        if not isinstance(item, dict) or set(item) != {
            "writer",
            "acknowledgement",
            "quiesced",
        }:
            raise ValueError("invalid adoption writer acknowledgement")
        writer = item["writer"]
        acknowledgement = item["acknowledgement"]
        if (
            not isinstance(writer, str)
            or not _WRITER.fullmatch(writer)
            or writer in writers
            or item["quiesced"] is not True
            or not isinstance(acknowledgement, str)
            or not acknowledgement.strip()
            or len(acknowledgement) > 512
            or any(ord(c) < 32 for c in acknowledgement)
        ):
            raise ValueError("invalid adoption writer acknowledgement")
        writers.append(writer)
        cleaned.append(
            {
                "writer": writer,
                "acknowledgement": acknowledgement,
                "quiesced": True,
            }
        )
    if set(writers) != set(expected):
        raise ValueError("adoption writer acknowledgements do not match expected_writer_set")

    result = json.loads(_canonical(value))
    result["expected_writer_set"] = sorted(result["expected_writer_set"])
    result["writer_acknowledgements"] = sorted(
        cleaned, key=lambda item: item["writer"]
    )
    return result


def load_request(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise ValueError("adoption request must be a bounded regular file")
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        raise ValueError("invalid adoption request JSON") from None
    return validate_request(value)


def _workspace_value(request):
    return {
        "schema": 1,
        "workspace_id": request["workspace_id"],
        "name": request["name"],
        "profile": request["profile"],
        "region": request["region"],
    }


def _host_configuration(request, *, epoch=None, lifetime=None):
    result = {
        "region": request["region"],
        "profile": request["profile"],
        "instance_id": request["instance_id"],
        "workspace_id": request["workspace_id"],
        "account_id": request["account_id"],
    }
    if lifetime in {"temporary", "persistent"}:
        result["lifetime"] = lifetime
    if epoch is not None:
        result["ownership_epoch"] = epoch
        result["adoption_operation_id"] = request["operation_id"]
    return result


def _inventory(request, cloud_factory=Cloud):
    workspace = _workspace_value(request)
    cloud = cloud_factory(workspace)
    if cloud.account() != request["account_id"]:
        raise RuntimeError("AWS account differs from adoption request")
    instance = cloud.owned(request["instance_id"], request["account_id"])
    tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
    if tags.get("ZogWorkspace") != request["workspace_id"]:
        raise RuntimeError("live instance workspace tag differs from adoption request")
    block_devices = sorted(
        item.get("Ebs", {}).get("VolumeId")
        for item in instance.get("BlockDeviceMappings", [])
        if item.get("Ebs", {}).get("VolumeId")
    )
    launch_time = instance.get("LaunchTime")
    if hasattr(launch_time, "isoformat"):
        launch_time = launch_time.isoformat()
    elif launch_time is not None:
        launch_time = str(launch_time)
    value = {
        "account_id": request["account_id"],
        "region": request["region"],
        "instance_id": request["instance_id"],
        "workspace_id": request["workspace_id"],
        "state": instance.get("State", {}).get("Name"),
        "instance_type": instance.get("InstanceType"),
        "launch_time": launch_time,
        "volumes": block_devices,
        "tags": {
            key: tags.get(key)
            for key in ("ManagedBy", "ZogWorkspace", "Name", "ZogLifetime")
            if tags.get(key) is not None
        },
    }
    if value["state"] in {"terminated", "shutting-down"}:
        raise RuntimeError("cannot adopt a terminating or terminated host")
    return value


def _marker(request, epoch):
    return {
        "schema": 1,
        "owner": OWNER,
        "workspace_id": request["workspace_id"],
        "instance_id": request["instance_id"],
        "account_id": request["account_id"],
        "region": request["region"],
        "ownership_epoch": epoch,
        "adoption_operation_id": request["operation_id"],
    }


def _marker_write_script(marker):
    payload = base64.b64encode(_canonical(marker)).decode("ascii")
    code = r"""
import base64
import json
import os
from pathlib import Path
import tempfile

path = Path(%r)
expected = json.loads(base64.b64decode(%r, validate=True))
path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
if path.exists():
    if path.is_symlink():
        raise SystemExit("ownership marker is a symlink")
    observed = json.loads(path.read_text())
    if observed != expected:
        raise SystemExit("ownership marker belongs to different adoption")
    raise SystemExit(0)
descriptor, temporary = tempfile.mkstemp(prefix=".ownership-", dir=path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(expected, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
""" % (REMOTE_MARKER, payload)
    import shlex
    return "python3 -c " + shlex.quote(code)


def _marker_read_script():
    import shlex
    code = (
        "import json; from pathlib import Path; "
        f"p=Path({REMOTE_MARKER!r}); "
        "print(json.dumps(json.loads(p.read_text()),sort_keys=True)) if p.is_file() and not p.is_symlink() else print('null')"
    )
    return "python3 -c " + shlex.quote(code)


def _adoption_path(root, operation_id):
    return ensure_root(root) / "adoptions" / (_identity(operation_id, "adoption operation_id") + ".json")


def load_adoption(root, operation_id):
    path = _adoption_path(root, operation_id)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _ownership_conflicts(root, request):
    root = ensure_root(root)
    target_workspace = root / "workspaces" / request["workspace_id"]
    target_ownership = root / "ownership" / (request["workspace_id"] + ".json")
    if target_ownership.exists():
        value = json.loads(target_ownership.read_text())
        if not (
            value.get("adoption_operation_id") == request["operation_id"]
            and value.get("workspace_id") == request["workspace_id"]
        ):
            raise AdoptionConflict("workspace already has a different ownership claim")
    for path in sorted((root / "workspaces").glob("*/host.json")) if (root / "workspaces").exists() else []:
        try:
            host = json.loads(path.read_text())
        except (OSError, ValueError, TypeError):
            raise AdoptionConflict("invalid retained gateway host claim") from None
        if host.get("instance_id") == request["instance_id"]:
            workspace = path.parent.name
            if workspace != request["workspace_id"]:
                raise AdoptionConflict("EC2 instance is already claimed by another gateway workspace")
            if host.get("adoption_operation_id") not in {None, request["operation_id"]}:
                raise AdoptionConflict("workspace host belongs to another adoption operation")
    if target_workspace.exists():
        marker = target_workspace / "gateway-owner.json"
        if marker.exists():
            value = json.loads(marker.read_text())
            if value != {
                "schema": 1,
                "workspace_id": request["workspace_id"],
                "owner": OWNER,
            }:
                raise AdoptionConflict("existing gateway workspace owner differs")
    return target_workspace


def _prepare(root, request, *, at=None, cloud_factory=Cloud):
    root = ensure_root(root)
    request = validate_request(request)
    at = at or utc_now()
    path = _adoption_path(root, request["operation_id"])
    digest = _digest(request)
    if path.exists():
        record = json.loads(path.read_text())
        if record.get("request_sha256") != digest or record.get("request") != request:
            raise AdoptionConflict("adoption operation identity belongs to different input")
        return record

    _ownership_conflicts(root, request)
    inventory = _inventory(request, cloud_factory=cloud_factory)
    record = {
        "schema": 1,
        "operation_id": request["operation_id"],
        "workspace_id": request["workspace_id"],
        "request_sha256": digest,
        "request": request,
        "ownership_epoch": request["operation_id"],
        "inventory": inventory,
        "inventory_sha256": _digest(inventory),
        "phase": "prepared",
        "prepared_at": at,
    }
    save(path, record)
    return record


def _host_without_epoch(request):
    return _host_configuration(
        request,
        lifetime=None,
    )


def _observe_marker(request, epoch, *, host_factory=Host):
    host = host_factory(_host_without_epoch(request))
    output = host.command(_marker_read_script(), seconds=60)
    try:
        observed = json.loads(output)
    except (TypeError, ValueError):
        raise RuntimeError("remote ownership marker observation is invalid") from None
    return observed


def _commit_local(root, record, *, at=None, cloud_factory=Cloud):
    at = at or utc_now()
    request = record["request"]
    _ownership_conflicts(root, request)
    inventory = _inventory(request, cloud_factory=cloud_factory)
    if _digest(inventory) != record["inventory_sha256"] or inventory != record["inventory"]:
        raise AdoptionConflict("live host identity changed after adoption preparation")

    target = ensure_root(root) / "workspaces" / request["workspace_id"]
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    lifetime = inventory.get("tags", {}).get("ZogLifetime")
    files = {
        "workspace.json": _workspace_value(request),
        "host.json": _host_configuration(
            request,
            epoch=record["ownership_epoch"],
            lifetime=lifetime,
        ),
        "adoption.json": {
            "schema": 1,
            "operation_id": request["operation_id"],
            "workspace_id": request["workspace_id"],
            "instance_id": request["instance_id"],
            "account_id": request["account_id"],
            "region": request["region"],
            "owner": OWNER,
            "ownership_epoch": record["ownership_epoch"],
            "request_sha256": record["request_sha256"],
            "inventory_sha256": record["inventory_sha256"],
            "missing_original_checkpoint": True,
            "operator_authorization": request["operator_authorization"],
            "saved_state_hashes": request["saved_state_hashes"],
            "expected_writer_set": request["expected_writer_set"],
            "writer_acknowledgements": request["writer_acknowledgements"],
            "adopted_at": at,
        },
        "gateway-owner.json": {
            "schema": 1,
            "workspace_id": request["workspace_id"],
            "owner": OWNER,
        },
    }
    for name, value in files.items():
        path = target / name
        if path.exists():
            if json.loads(path.read_text()) != value:
                raise AdoptionConflict("partially adopted workspace differs from retained evidence")
        else:
            save(path, value)

    ownership = {
        "schema": 2,
        "workspace_id": request["workspace_id"],
        "owner": OWNER,
        "phase": "owned",
        "ownership_epoch": record["ownership_epoch"],
        "adoption_operation_id": request["operation_id"],
        "inventory_sha256": record["inventory_sha256"],
        "completed_at": at,
    }
    ownership_path = ensure_root(root) / "ownership" / (request["workspace_id"] + ".json")
    if ownership_path.exists():
        existing = json.loads(ownership_path.read_text())
        if existing != ownership:
            raise AdoptionConflict("retained ownership record differs from adoption")
    else:
        save(ownership_path, ownership)

    record = dict(record)
    record["phase"] = "owned"
    record["completed_at"] = at
    save(_adoption_path(root, request["operation_id"]), record)
    return {
        "operation_id": request["operation_id"],
        "workspace_id": request["workspace_id"],
        "workspace": str(target),
        "ownership_epoch": record["ownership_epoch"],
        "owned": True,
    }


def _adopt_workspace_locked(
    root,
    request,
    *,
    at=None,
    cloud_factory=Cloud,
    host_factory=Host,
):
    """Perform or resume one explicit lost-workspace adoption operation while locked."""
    at = at or utc_now()
    record = _prepare(root, request, at=at, cloud_factory=cloud_factory)
    request = record["request"]
    marker = _marker(request, record["ownership_epoch"])

    if record["phase"] == "owned":
        return _commit_local(root, record, at=record["completed_at"], cloud_factory=cloud_factory)

    if record["phase"] == "marker_submitting":
        record = dict(record)
        record["phase"] = "marker_uncertain"
        record["uncertainty_at"] = at
        record["error"] = (
            "recovered after ownership-marker submission intent without a recorded command identity"
        )
        save(_adoption_path(root, request["operation_id"]), record)

    if record["phase"] == "marker_uncertain":
        observed = _observe_marker(
            request, record["ownership_epoch"], host_factory=host_factory
        )
        if observed != marker:
            raise RuntimeError(
                "ownership-marker outcome remains uncertain; refusing replacement adoption mutation"
            )
        record = dict(record)
        record["phase"] = "marker_confirmed"
        record["marker_confirmed_at"] = at
        record.pop("uncertainty_at", None)
        record.pop("error", None)
        save(_adoption_path(root, request["operation_id"]), record)

    if record["phase"] == "marker_rejected":
        raise RuntimeError(
            "ownership-marker submission was definitely rejected; use recover-rejected-adoption before retry"
        )

    if record["phase"] in {"prepared", "marker_retry_authorized"}:
        record = dict(record)
        record["phase"] = "marker_submitting"
        previous_attempts = record.get("marker_attempt_count")
        if type(previous_attempts) is not int or previous_attempts < 0:
            previous_attempts = 1 if record.get("marker_attempt_started_at") else 0
        record["marker_attempt_count"] = previous_attempts + 1
        record["marker_attempt_started_at"] = at
        save(_adoption_path(root, request["operation_id"]), record)
        host = host_factory(_host_without_epoch(request))
        try:
            command_id = host.submit_command(_marker_write_script(marker), seconds=60)
        except BaseException as error:
            rejection = _definite_send_command_rejection(error)
            if rejection is None:
                record["phase"] = "marker_uncertain"
                record["uncertainty_at"] = at
                record.pop("rejection", None)
            else:
                record["phase"] = "marker_rejected"
                record["rejected_at"] = at
                record["rejection"] = rejection
                record.pop("uncertainty_at", None)
            record["error"] = str(error)[:512]
            save(_adoption_path(root, request["operation_id"]), record)
            raise
        record["phase"] = "marker_submitted"
        record["marker_command_id"] = command_id
        record["marker_submitted_at"] = at
        save(_adoption_path(root, request["operation_id"]), record)

    if record["phase"] == "marker_submitted":
        host = host_factory(_host_without_epoch(request))
        host.wait_command(record["marker_command_id"], seconds=60)
        observed = _observe_marker(
            request, record["ownership_epoch"], host_factory=host_factory
        )
        if observed != marker:
            raise AdoptionConflict("confirmed ownership marker differs from adoption binding")
        record = dict(record)
        record["phase"] = "marker_confirmed"
        record["marker_confirmed_at"] = at
        save(_adoption_path(root, request["operation_id"]), record)

    if record["phase"] != "marker_confirmed":
        raise RuntimeError("unsupported adoption recovery phase")

    return _commit_local(root, record, at=at, cloud_factory=cloud_factory)




def recover_rejected_adoption(
    root,
    request,
    *,
    at=None,
    cloud_factory=Cloud,
    host_factory=Host,
):
    """Explicitly authorize retry after a proven synchronous SendCommand rejection."""
    at = at or utc_now()
    request = validate_request(request)
    with _ownership_lock(root):
        root = ensure_root(root)
        path = _adoption_path(root, request["operation_id"])
        if not path.exists():
            raise RuntimeError("adoption operation does not exist")

        record = json.loads(path.read_text())
        if (
            record.get("request_sha256") != _digest(request)
            or record.get("request") != request
        ):
            raise AdoptionConflict(
                "adoption recovery request differs from retained operation"
            )

        if record.get("phase") == "marker_retry_authorized":
            return {
                "operation_id": request["operation_id"],
                "workspace_id": request["workspace_id"],
                "phase": "marker_retry_authorized",
                "retry_authorized": True,
            }

        if record.get("phase") not in {"marker_uncertain", "marker_rejected"}:
            raise RuntimeError(
                "adoption is not blocked by a rejected marker submission"
            )
        if record.get("marker_command_id"):
            raise RuntimeError(
                "rejected-marker recovery requires absence of a marker command identity"
            )

        rejection = _retained_definite_rejection(record)
        if rejection is None:
            raise RuntimeError(
                "retained adoption does not prove a definite SendCommand rejection"
            )

        _ownership_conflicts(root, request)
        inventory = _inventory(request, cloud_factory=cloud_factory)
        if (
            _digest(inventory) != record.get("inventory_sha256")
            or inventory != record.get("inventory")
        ):
            raise AdoptionConflict(
                "live host identity changed before rejected-marker recovery"
            )

        observed = _observe_marker(
            request,
            record["ownership_epoch"],
            host_factory=host_factory,
        )
        if observed is not None:
            if observed == _marker(request, record["ownership_epoch"]):
                raise RuntimeError(
                    "expected ownership marker now exists; resume the same adoption without rejection recovery"
                )
            raise AdoptionConflict(
                "remote ownership marker differs from the retained adoption"
            )

        history = record.get("recovery_history", [])
        if not isinstance(history, list) or len(history) > 15:
            raise AdoptionConflict(
                "retained adoption recovery history is invalid"
            )
        evidence = {
            "schema": 1,
            "kind": "definite-send-command-rejection",
            "authorized_at": at,
            "source_phase": record["phase"],
            "rejection": rejection,
            "inventory_sha256": record["inventory_sha256"],
            "remote_marker": "absent",
        }
        record = dict(record)
        record["recovery_history"] = history + [evidence]
        record["phase"] = "marker_retry_authorized"
        record["retry_authorized_at"] = at
        if "marker_attempt_count" not in record:
            record["marker_attempt_count"] = (
                1 if record.get("marker_attempt_started_at") else 0
            )
        save(path, record)
        return {
            "operation_id": request["operation_id"],
            "workspace_id": request["workspace_id"],
            "phase": "marker_retry_authorized",
            "retry_authorized": True,
            "rejection_code": rejection["code"],
        }


def adopt_workspace(
    root,
    request,
    *,
    at=None,
    cloud_factory=Cloud,
    host_factory=Host,
):
    """Perform or resume one explicit lost-workspace adoption operation."""
    with _ownership_lock(root):
        return _adopt_workspace_locked(
            root,
            request,
            at=at,
            cloud_factory=cloud_factory,
            host_factory=host_factory,
        )
