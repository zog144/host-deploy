"""Fixed Fonts gateway dispatch -> protected root-control Task C SSM owner.

The gateway authenticates and retains the ORIGINAL GitHub/SQS request, owns the
compiler Workspace and selects the Project/controller. Root-control's existing
trusted-Host root-owned local journal is the ONE authorized SSM send boundary.
This module does not expose a generic shell relay or create new authorization.

Do not invoke the owner until the gateway's own dispatch intent is durable.
Never fall back to Host.submit_command if the protected journal is unavailable.
"""
from .image_build_execution import _binding
from .ledger import load_dispatch, load_request
from .project_current import validate as validate_current
from .project_current_observation import CONTROL_TIMEOUT_SECONDS as PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS
from .protocol import request_digest


class ProtectedOwnerUnavailable(RuntimeError):
    pass




def _owner_factory(journal_factory):
    if journal_factory is not None:
        return journal_factory
    try:
        from zog.root_control.task_c_trusted_host import LocalTaskCJournal
    except ImportError as error:
        raise ProtectedOwnerUnavailable(
            "protected root-control Task C owner is not installed") from error
    return LocalTaskCJournal


def ready(request_id, *, journal_factory=None):
    """Read-only owner preflight before creating gateway SendCommand intent.

    A missing root-owned owner must leave an already-prepared request intact,
    rather than converting a purely local installation failure into an
    uncertain SSM submission. Existing owner intent never permits a retry.
    """
    factory = _owner_factory(journal_factory)
    try:
        journal = factory()
    except (OSError, ValueError, RuntimeError) as error:
        raise ProtectedOwnerUnavailable(
            "protected root-control Task C owner is unavailable") from error
    try:
        if any(item is not None for item in journal.inspect(request_id)):
            raise ProtectedOwnerUnavailable(
                "original Fonts operation already claimed by protected owner")
    finally:
        journal.close()

def submit_once(gateway_root, request_id, *, binding, configuration,
                host, script, seconds, journal_factory=None):
    """Submit an already authorized fixed task through root-control's owner.

    The root-owned LocalTaskCJournal must have been installed by the
    protected Host administrator. It writes an O_EXCL/fsynced operation
    intent before calling the approved fixed-document Host sender. Neither
    the incoming GitHub request nor an IPC client supplies an SSM script.
    """
    record = load_dispatch(gateway_root, request_id)
    state = load_request(gateway_root, request_id)
    if (record is None or record["phase"] != "submitting"
            or state["states"]["admission"] != "admitted"
            or state["request_id"] != request_id
            or state["request_sha256"] != request_digest(state["request"])
            or record["request_sha256"] != state["request_sha256"]):
        raise ProtectedOwnerUnavailable("original Fonts admission or send intent is unavailable")
    selected = _binding(record)
    if (selected.get("schema") != 4
            or selected.get("direct_forward") is not True
            or selected != binding):
        raise ProtectedOwnerUnavailable("protected owner requires frozen Project-current Fonts operation")
    validate_current(selected)
    if "controller_sha256" not in selected:
        # Independent defense in depth: no direct caller can drive the root
        # owner with an unchecked historical prepared binding, even if it
        # bypasses simple_forward.advance(). Readback of already-submitted
        # historical CommandIds uses a separate non-sending path.
        raise ProtectedOwnerUnavailable(
            "digestless historical Fonts dispatch has no new send authority")
    if (state["request"]["operation"] != "build.submit"
            or state["request"]["parameters"] != {
                "lane": "gateway-first-fonts-runtime",
                "task": "graphics-fonts-image-v1",
            }
            or state["request"]["workspace_id"] != selected["workspace_id"]):
        raise ProtectedOwnerUnavailable("original Fonts task and lane authorization differ")
    target = selected["target"]
    if (not isinstance(configuration, dict)
            or any(configuration.get(k) != target[k] for k in target)
            or getattr(host, "instance", target["instance_id"]) != target["instance_id"]):
        raise ProtectedOwnerUnavailable("owner SSM Host is not the selected compiler")
    from .project_current import remote_script
    if (script != remote_script(selected)
            or type(seconds) is not int
            or seconds != PROJECT_CURRENT_CONTROL_TIMEOUT_SECONDS):
        raise ProtectedOwnerUnavailable("owner script or execution deadline differs from fixed Fonts task")
    journal_factory = _owner_factory(journal_factory)

    # The owner has an independent root-owned operation journal. If an intent
    # already exists, its submit_once will reject reuse, including after an
    # acknowledgement is lost. Never call Host directly in that case.
    try:
        journal = journal_factory()
    except (OSError, ValueError) as error:
        raise ProtectedOwnerUnavailable(
            "protected root-control Task C journal is unavailable") from error
    try:
        return journal.submit_once(
            operation_id=request_id,
            request_sha256=state["request_sha256"],
            script=script,
            target={k: target[k] for k in ("instance_id", "region", "account_id")},
            seconds=seconds,
            sender=host,
        )
    finally:
        journal.close()
