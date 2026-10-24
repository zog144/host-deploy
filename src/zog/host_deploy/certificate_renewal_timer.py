"""Root-policy-bound, one-shot timer adapter for selected certificate renewal.

Same-UID and authenticated split-UID selected broker backends. The renewal.tick journal
is the sole request ledger.  No Certbot command, key, or nginx action here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

from .certificate_renewal import (
    ATTESTATION_SCHEMA, RenewalBlocked, _binding, _load, _locked, tick,
)
from .station_production import build_controller, verify_controller_runtime

SCHEMA = "zog-host-deploy-cert-renewal-timer-v1"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ALLOWED_PYTHON = frozenset({
    "/usr/bin/python3.11", "/usr/bin/python3.12", "/usr/bin/python3.13"
})


def _absolute(value):
    if (not isinstance(value, str) or value == "/"
            or len(value) > 512 or not value.startswith("/")
            or any(x in ("", ".", "..") for x in value.split("/")[1:])):
        raise RenewalBlocked("invalid-renewal-policy")


def validate_policy(value):
    fields = {
        "schema", "application", "program", "certificate_id",
        "policy_sha256", "project_root", "generation",
        "controller_user", "issuer_user", "root_control_socket",
        "python_executable", "journal_directory", "issuer_policy_file",
        "issuer_state", "renew_when_days_remaining",
        "minimum_interval_hours", "evaluate_queued_request", "publication_policy_file",
        "issuer_observer_policy_file", "controller_backend",
        "issuer_lifecycle_socket", "issuer_inspection_policy_file",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != SCHEMA
            or value.get("application") != "certify-manage"
            or value.get("program") != "renew"):
        raise RenewalBlocked("invalid-renewal-policy")
    _binding(value["policy_sha256"], value["certificate_id"])
    if (not isinstance(value["generation"], str)
            or _SHA.fullmatch(value["generation"]) is None
            or not isinstance(value["controller_user"], str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value["controller_user"])
            or not isinstance(value["issuer_user"], str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value["issuer_user"])):
        raise RenewalBlocked("controller-issuer-identity-invalid")
    if value["controller_backend"] not in ("local", "selected-broker"):
        raise RenewalBlocked("controller-backend-unsupported")
    if value["controller_backend"] == "local":
        if (value["issuer_user"] != value["controller_user"]
                or value["issuer_lifecycle_socket"] is not None
                or value["root_control_socket"] is None):
            raise RenewalBlocked("controller-issuer-co-residency-required")
    else:
        if (value["issuer_lifecycle_socket"] is None
                or value["issuer_observer_policy_file"] is None
                or value["issuer_inspection_policy_file"] is None
                or value["root_control_socket"] is not None):
            raise RenewalBlocked("authenticated-selected-broker-required")
        _absolute(value["issuer_lifecycle_socket"])
    for key in ("project_root", "python_executable",
                "journal_directory", "issuer_policy_file", "issuer_state"):
        _absolute(value[key])
    if value["controller_backend"] == "local":
        _absolute(value["root_control_socket"])
    if value["publication_policy_file"] is not None:
        _absolute(value["publication_policy_file"])
    if value["issuer_observer_policy_file"] is not None:
        _absolute(value["issuer_observer_policy_file"])
    if value["issuer_inspection_policy_file"] is not None:
        _absolute(value["issuer_inspection_policy_file"])
    if (value["controller_backend"] == "local"
            and value["issuer_inspection_policy_file"] is not None):
        raise RenewalBlocked("unexpected-split-inspection-policy")
    if (value["controller_backend"] == "local"
            and value["evaluate_queued_request"] is not True):
        raise RenewalBlocked("controller-evaluator-not-authorized")
    if (value["controller_backend"] == "selected-broker"
            and value["evaluate_queued_request"] is not False):
        raise RenewalBlocked("generic-evaluator-forbidden")
    if (value["root_control_socket"] == "/run/zog/root-control.sock"
            or value["python_executable"] != "/usr/bin/python3.12"
            or type(value["renew_when_days_remaining"]) is not int
            or not 1 <= value["renew_when_days_remaining"] <= 60
            or type(value["minimum_interval_hours"]) is not int
            or not 24 <= value["minimum_interval_hours"] <= 720):
        raise RenewalBlocked("unapproved-renewal-runtime")
    return json.loads(json.dumps(value, sort_keys=True))


def load_policy(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise RenewalBlocked("renewal-policy-unavailable")
    parent = Path("/")
    for component in path.parts[1:-1]:
        parent = parent / component
        try:
            info = parent.lstat()
        except OSError:
            raise RenewalBlocked("renewal-policy-unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise RenewalBlocked("renewal-policy-parent-untrusted")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise RenewalBlocked("renewal-policy-unavailable")
    info = path.stat(follow_symlinks=False)
    if info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise RenewalBlocked("renewal-policy-untrusted")
    try:
        return validate_policy(json.loads(path.read_text()))
    except (ValueError, TypeError, UnicodeError):
        raise RenewalBlocked("invalid-renewal-policy") from None


def _issuer_verification(policy):
    """Read the genuine Certbot lineage through certify-manage's protected API."""
    from zog.certify_manage.manager import CertificateManager
    from zog.certify_manage.model import Authorization
    from zog.certify_manage.security import trusted_policy

    try:
        issuer = Authorization.from_dict(json.loads(
            trusted_policy(Path(policy["issuer_policy_file"]))))
        if (issuer.certificate_id != policy["certificate_id"]
                or issuer.fingerprint != policy["policy_sha256"]):
            raise RenewalBlocked("issuer-authorization-mismatch")
        manager = CertificateManager(Path(policy["issuer_state"]), issuer)
        status = manager.inspect()
        operation = {"operation": status.operation, "outcome": status.outcome}
    except RenewalBlocked:
        raise
    except Exception:
        raise RenewalBlocked("issuer-inspection-unavailable") from None

    if (status.health != "valid" or status.detail is not None
            or status.certificate_id != policy["certificate_id"]
            or tuple(status.hostnames) != tuple(issuer.hostnames)
            or status.policy_sha256 != policy["policy_sha256"]
            or operation["operation"] not in ("issue", "renew")
            or operation["outcome"] not in ("issued", "renewed", "unchanged")
            or not isinstance(status.fingerprint_sha256, str)
            or _SHA.fullmatch(status.fingerprint_sha256) is None
            or type(status.days_remaining) is not int):
        raise RenewalBlocked("issuer-readiness-unproven")
    try:
        completed = datetime.fromisoformat(status.operation_updated_at)
    except (ValueError, TypeError, KeyError):
        raise RenewalBlocked("issuer-completion-unproven") from None
    if completed.tzinfo is None:
        raise RenewalBlocked("issuer-completion-unproven")
    completed = completed.astimezone(timezone.utc)
    if completed > datetime.now(timezone.utc) + timedelta(minutes=2):
        raise RenewalBlocked("issuer-completion-in-future")
    return status, operation, completed


def _pending_start(journal_directory, *, policy_sha256, certificate_id, request_id):
    """Read the existing coordinator journal without creating a second ledger.

    Invoked only by the trusted callback while tick holds its project lock.
    """
    directory = Path(journal_directory)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        record = _load(fd, _binding(policy_sha256, certificate_id))
    finally:
        os.close(fd)
    if record is None or record["request_id"] != request_id:
        raise RenewalBlocked("issuer-request-identity-mismatch")
    return datetime.fromisoformat(record["issued_at"]).astimezone(timezone.utc)


def _authenticated_issuer_evidence(policy, *, request_id, started, controller_result):
    """Observe exact saved request through the separately authenticated broker.

    This is journal provenance, NOT a replacement for X.509 lineage checks.
    """
    from .certificate_issuer_observer import read_policy, observe_request
    if policy["issuer_observer_policy_file"] is None:
        raise RenewalBlocked("issuer-observer-not-authorized")
    approved = read_policy(policy["issuer_observer_policy_file"])
    if (approved["certificate_id"] != policy["certificate_id"]
            or approved["policy_sha256"] != policy["policy_sha256"]):
        raise RenewalBlocked("issuer-observer-policy-mismatch")
    observed = observe_request(
        approved, request_id=request_id, issued_at=started.isoformat(),
        controller_result=controller_result,
    )
    # The trusted root-control observation is request-bound, but the local
    # host-deploy timer policy independently owns the certificate policy pin.
    # Never consume station-access's UID-specific state or use an observed
    # digest as the local authorization source.
    if (type(observed) is not dict
            or observed.get("request_id") != request_id
            or observed.get("tls_ready") is not False):
        raise RenewalBlocked("root-observation-request-mismatch")
    if observed.get("status") == "journal-ready":
        if (observed.get("policy_sha256") != policy["policy_sha256"]
                or observed.get("certificate_id") != policy["certificate_id"]
                or observed.get("host_policy_digest") !=
                   approved["host_policy_digest"]):
            raise RenewalBlocked("root-observation-local-policy-mismatch")
    return observed


def _publication_policy(policy):
    """Independent root-owned authorization of stage and chosen TLS consumer."""
    from zog.certify_manage.security import trusted_policy
    from .certificate_renewal_publication import validate_policy
    try:
        selected = validate_policy(json.loads(trusted_policy(
            Path(policy["publication_policy_file"]))))
    except Exception:
        raise RenewalBlocked("publication-authorization-unavailable") from None
    for field in ("certificate_id", "policy_sha256", "issuer_state", "issuer_policy_file"):
        if selected[field] != policy[field]:
            raise RenewalBlocked("publication-authorization-mismatch")
    return selected


def _publish_one(policy, controller, approval, callback):
    outcome = callback(policy["journal_directory"], controller, approval)
    if outcome["state"] in {"stage-submitted", "stage-pending"}:
        if not getattr(controller, "direct_selected_launch", False):
            try:
                evaluation = controller.evaluate()
            except Exception:
                raise RenewalBlocked("stage-evaluation-unavailable") from None
            if evaluation is None or getattr(evaluation, "ok", None) is not True:
                raise RenewalBlocked("stage-evaluation-failed")
        if controller.application_request_result(outcome["stage_id"]) is not None:
            outcome = callback(policy["journal_directory"], controller, approval)
    return outcome


def run(policy, *, controller, issuer_checker=None,
        publication_policy_loader=_publication_policy, publication_advance=None,
        issuer_observer=_authenticated_issuer_evidence):
    """Authorized renewal, then independent selected stage and TLS delivery."""
    policy = validate_policy(policy)
    if issuer_checker is None:
        if policy["controller_backend"] == "selected-broker":
            from .certificate_issuer_inspection import inspection_checker
            issuer_checker = inspection_checker(policy)
        else:
            issuer_checker = _issuer_verification
    if publication_advance is None:
        from .certificate_renewal_publication import advance
        publication_advance = advance
    try:
        status, _operation, _completed = issuer_checker(policy)
    except RenewalBlocked:
        status = None

    def observe(request_id):
        started = _pending_start(
            policy["journal_directory"],
            policy_sha256=policy["policy_sha256"],
            certificate_id=policy["certificate_id"], request_id=request_id,
        )
        result = controller.application_request_result(request_id)
        if policy["issuer_observer_policy_file"] is not None:
            trusted = issuer_observer(
                policy, request_id=request_id, started=started,
                controller_result=result,
            )
            if trusted["status"] != "journal-ready":
                return None
        inspected, original, completed = issuer_checker(policy)
        if (completed < started or original.get("operation") != "renew"
                or original.get("outcome") not in ("renewed", "unchanged")):
            raise RenewalBlocked("issuer-result-not-fresh")
        if policy["issuer_observer_policy_file"] is not None:
            journal_time = datetime.fromisoformat(trusted["journal_updated_at"])
            if journal_time.tzinfo is None:
                raise RenewalBlocked("issuer-observer-time-untrusted")
            journal_time = journal_time.astimezone(timezone.utc)
            if (trusted["certificate_id"] != policy["certificate_id"]
                    or trusted["policy_sha256"] != policy["policy_sha256"]
                    or (policy["controller_backend"] == "selected-broker"
                        and trusted.get("host_policy_digest") is None)
                    or trusted["tls_ready"] is not False
                    or trusted["certificate_fingerprint_sha256"] !=
                       inspected.fingerprint_sha256
                    or trusted["outcome"] != original["outcome"]
                    or (policy["controller_backend"] == "selected-broker"
                        and journal_time != completed)
                    or (policy["controller_backend"] == "local"
                        and journal_time > completed + timedelta(minutes=2))):
                raise RenewalBlocked("issuer-observer-lineage-mismatch")
        completed_controller = getattr(result, "updated_at", None)
        if getattr(controller, "direct_selected_launch", False):
            # The selected broker returns no timestamp. Root-control's
            # authenticated journal-ready response verifies that the exact
            # saved runtime was terminal and its journal postdates intent.
            if (policy["issuer_observer_policy_file"] is None
                    or trusted["status"] != "journal-ready"):
                raise RenewalBlocked("issuer-controller-timeline-unproven")
        elif (type(completed_controller) not in (int, float)
                or completed_controller <= 0
                or completed > datetime.fromtimestamp(
                    completed_controller, timezone.utc) + timedelta(minutes=2)):
            raise RenewalBlocked("issuer-controller-timeline-mismatch")
        return {
            "schema": ATTESTATION_SCHEMA,
            "request_id": request_id, "certificate_id": policy["certificate_id"],
            "policy_sha256": policy["policy_sha256"], "health": inspected.health,
            "operation": "renew", "outcome": original["outcome"],
            "fingerprint_sha256": inspected.fingerprint_sha256,
        }

    # If a changed renewal was previously verified, it must be delivered
    # before a newer renewal is authorized. Never replace an uncertain key.
    with _locked(policy["journal_directory"]) as fd:
        previous = _load(fd, _binding(policy["policy_sha256"], policy["certificate_id"]))
    if previous and previous["phase"] == "verified" and previous["outcome"] == "renewed":
        # Even a previously verified request may not be staged after the
        # issuer changes or an independent inspector/observer goes offline.
        if policy["controller_backend"] == "selected-broker":
            confirmation = observe(previous["request_id"])
            if (confirmation is None
                    or confirmation["outcome"] != "renewed"
                    or confirmation["fingerprint_sha256"] != previous["fingerprint"]):
                raise RenewalBlocked("renewal-publication-proof-stale")
        if policy["publication_policy_file"] is None:
            raise RenewalBlocked("publication-authorization-required")
        approval = publication_policy_loader(policy)
        delivery = _publish_one(policy, controller, approval, publication_advance)
        if delivery["state"] != "browser-verified":
            return {
                "schema": previous["schema"], "phase": "verified",
                "request_id": previous["request_id"], "outcome": "renewed",
                "fingerprint": previous["fingerprint"],
                "publication": delivery["state"],
            }

    due = (status is not None
           and type(status.days_remaining) is int
           and status.days_remaining <= policy["renew_when_days_remaining"])
    response = tick(
        policy["journal_directory"], controller,
        policy_sha256=policy["policy_sha256"],
        certificate_id=policy["certificate_id"], authorize_new=due,
        issuer_observation=observe,
        minimum_interval_hours=policy["minimum_interval_hours"],
    )
    if response["phase"] == "submitted":
        if not getattr(controller, "direct_selected_launch", False):
            try:
                evaluation = controller.evaluate()
            except Exception:
                raise RenewalBlocked("controller-evaluation-unavailable") from None
            if evaluation is None or getattr(evaluation, "ok", None) is not True:
                raise RenewalBlocked("controller-evaluation-failed")
        # An evaluator can have run successfully while the selected result
        # remains unavailable. Do not re-submit the same request *again*
        # during this single timer tick; reconcile on the next invocation.
        if controller.application_request_result(response["request_id"]) is not None:
            response = tick(
                policy["journal_directory"], controller,
                policy_sha256=policy["policy_sha256"],
                certificate_id=policy["certificate_id"], authorize_new=False,
                issuer_observation=observe,
                minimum_interval_hours=policy["minimum_interval_hours"],
            )
    if status is None and response["phase"] in ("idle", "verified"):
        raise RenewalBlocked("issuer-readiness-unproven")
    if response["phase"] == "verified":
        if response["outcome"] == "unchanged":
            return {**response, "publication": "unchanged-no-delivery"}
        if response["outcome"] == "renewed":
            if policy["publication_policy_file"] is None:
                raise RenewalBlocked("publication-authorization-required")
            approved = publication_policy_loader(policy)
            delivery = _publish_one(policy, controller, approved, publication_advance)
            return {**response, "publication": delivery["state"]}
    return response


def _require_approved_native_inspection(policy):
    """Fail closed before selected broker or issuer socket opens.

    Controller review 2026-10-16 rejects an unmanaged persistent inspector.
    This gate may be retired only after the finite selected inspect program
    and privileged invocation-bound reader have an approved concrete API.
    """
    if policy["controller_backend"] == "selected-broker":
        raise RenewalBlocked("selected-inspection-runtime-not-approved")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        _require_approved_native_inspection(policy)
        if policy["controller_backend"] == "selected-broker":
            from .certificate_issuer_inspection import read_policy as read_inspection_policy
            from .certificate_issuer_observer import read_policy as read_observer_policy
            from .certificate_issuer_lifecycle import SelectedIssuerController
            inspection = read_inspection_policy(policy["issuer_inspection_policy_file"])
            observer = read_observer_policy(policy["issuer_observer_policy_file"])
            expected = os.geteuid()
            if (expected == 0 or inspection["caller_uid"] != expected
                    or observer["caller_uid"] != expected
                    or inspection["issuer_uid"] != observer["issuer_uid"]
                    or inspection["certificate_id"] != observer["certificate_id"]
                    or inspection["policy_sha256"] != observer["policy_sha256"]
                    or inspection["certificate_id"] != policy["certificate_id"]
                    or inspection["policy_sha256"] != policy["policy_sha256"]
                    or expected == pwd.getpwnam(policy["controller_user"]).pw_uid
                    or expected == pwd.getpwnam(policy["issuer_user"]).pw_uid
                    or inspection["issuer_uid"] !=
                       pwd.getpwnam(policy["issuer_user"]).pw_uid):
                raise RenewalBlocked("split-identity-authorization-mismatch")
            controller = SelectedIssuerController(policy["issuer_lifecycle_socket"])
        else:
            user = pwd.getpwnam(policy["controller_user"])
            if os.geteuid() != user.pw_uid or os.geteuid() == 0:
                raise RenewalBlocked("controller-identity-mismatch")
            verify_controller_runtime({
                "root_control_socket": policy["root_control_socket"],
                "python_executable": policy["python_executable"],
            })
            controller = build_controller(policy)
        # Split-UID inspection goes only through the separately authenticated
        # issuer-UID socket. No private issuer file access from this caller.
        result = run(policy, controller=controller)
        print(json.dumps({"schema": SCHEMA, **result}, sort_keys=True))
        return 0
    except Exception:
        # No private Certbot data, raw AWS/systemd error or host path disclosure.
        print(json.dumps({"schema": SCHEMA, "phase": "blocked",
                          "safe_to_publish": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
