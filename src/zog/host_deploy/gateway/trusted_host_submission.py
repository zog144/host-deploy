"""Trusted-host SSM submission for a frozen, allowlisted image-build operation.

The installed host-registry administrator is the local trust boundary. AWS
credentials are acquired normally from its existing instance role. The FIFO
request, selected compiler target, source, recipe and command are validated
before an irrevocable *local* send-intent is written by generic_pipeline.

This adapter never accepts an SSM document, instance, shell text, or
credentials from a GitHub request. An uncertain SendCommand reply is NOT a
reason to try again.
"""
from .image_build_execution import CONTROL_TIMEOUT_SECONDS, remote_script
from .image_build_dispatch import verify_current_target

DOCUMENT = "AWS-RunShellScript"
STAGES = frozenset(("capabilities", "snapshot", "submit", "inspect"))


class TrustedSubmissionDenied(RuntimeError):
    pass


def selected_command(gateway_root, binding, step, stage_binding):
    """Revalidate target/lane and derive server-owned operation bytes."""
    if (type(step) is not dict or step.get("name") not in STAGES
            or type(stage_binding) is not dict
            or stage_binding.get("remote_request", {}).get("operation") not in (
                "capabilities.inspect", "recipes.snapshot",
                "pipeline.submit", "pipeline.inspect")
            or type(binding) is not dict or not binding.get("task")
            or not binding.get("task_catalogue_identity")
            or stage_binding.get("source") != binding.get("source")
            or stage_binding.get("task_catalogue_identity") !=
               binding.get("task_catalogue_identity")):
        raise TrustedSubmissionDenied("unapproved trusted-host SSM selection")
    operation_for_stage = {
        "capabilities": "capabilities.inspect",
        "snapshot": "recipes.snapshot",
        "submit": "pipeline.submit",
        "inspect": "pipeline.inspect",
    }
    if stage_binding["remote_request"]["operation"] != operation_for_stage[step["name"]]:
        raise TrustedSubmissionDenied("SSM stage does not match fixed operation")
    # Reopen the *current* owned workspace/lane and compare with the immutable
    # dispatch, not an instance ID or shell supplied by the GitHub issue.
    target = verify_current_target(gateway_root, binding)
    if (type(target) is not dict
            or type(target.get("instance_id")) is not str
            or not target["instance_id"].startswith("i-")
            or type(target.get("region")) is not str
            or not target["region"]):
        raise TrustedSubmissionDenied("selected compiler host unavailable")
    script = remote_script(stage_binding)
    if type(script) is not str or not script:
        raise TrustedSubmissionDenied("invalid derived image-build command")
    return target, script


def submit_once(host, *, script, seconds):
    """Called only AFTER generic_pipeline fsyncs its unique local send claim."""
    if (type(script) is not str or not script
            or type(seconds) is not int
            or seconds != CONTROL_TIMEOUT_SECONDS):
        raise TrustedSubmissionDenied("SSM command/time must be server-selected")
    # Host.submit_command fixes AWS-RunShellScript and one SDK send attempt.
    # No arbitrary document or credentials parameter crosses this boundary.
    return host.submit_command(script, seconds=seconds)
