# Recovery, reboot and runbooks

## Durable identity before execution

Host-deploy owns a long-running EC2 host/workspace identity and can outlive an individual Work container. An operator checkpoint is not an EC2 machine image; it preserves exact workspace, job and reboot-workflow records so that a subsequent authorized controller can **inspect and continue the same work**, not invent a successful job or a new owner identity.

The normal [checkpoint handoff](../RECOVERY.md) uses an explicit retiring export (`checkpoint-export --handoff`) and restoration into a new workspace. The prior controller is retired before publishing that handoff. A non-retiring snapshot is a backup only: restoring it into two simultaneously active writers would split ownership. Credentials are stored separately, and source/downloaded result archives are not included automatically in a checkpoint. A durable checkpoint must therefore be stored outside ephemeral scratch along with any separately retained partial transfers.

## Handoff is preferred; adoption is exceptional

Where the original authentic checkpoint can be recovered, use the handoff mechanism. The [lost-workspace adoption contract](../GATEWAY-ADOPTION.md) exists only when that checkpoint is genuinely unavailable and the operator authorizes adoption. It binds the historical workspace and exact AWS account/region/instance, saved-state hashes, acknowledged quiescence of **all expected old writers**, and an authoritative remote ownership epoch.

Adoption cannot invent past jobs, a launch manifest, generations or a successful request result. The remote marker's presence does not fence writers that disregard host-deploy; human/operator quiescence is a separate precondition. A lost SSM marker-write response produces uncertainty, not permission to submit another write. Read-only reconciliation must establish the original marker, or the operation remains blocked. The adopted host's permitted guarded SSM operations do **not** imply general lifecycle start/stop/termination rights.

## SSM and remote result uncertainty

A remote dispatch freezes its source checkout revision, monthly pin, lane, argv, workspace/host identity and exact request/result destinations **before** `SendCommand`. A recorded `submitting` state may have already caused a side effect. If the returned SSM CommandId is lost, automatic second submission is forbidden; inspect authoritative remote/AWS evidence and reconcile the same command identity.

After a command is known, observation/wait must never silently resubmit it. A terminal SSM result without an exact image-build receipt leaves the gateway `recovery_blocked`. Lost local publication of an already frozen result receipt can be repaired from that receipt without another remote execution. See [gateway dispatch](../GATEWAY-DISPATCH.md) and [gateway execution boundaries](compiler-gateway-and-dispatch.md).

## Normal reboot is a two-phase test, not an automatic rerun

For [two-phase reboot acceptance](../REBOOT.md), host-deploy preserves source and dedicated test STATE across one **normal reboot**, records pre/post boot IDs, reconnects by the same owned host identity, then runs the distinct verification phase. The component under test—such as box-control—owns its assertions. This mechanism does not emulate abrupt power loss, and an interrupted build service is not restarted merely because the VM came online.

Evidence includes command outputs, the persistent state directory, phase status, boot identity and bounded log artifacts. A failure or ambiguous reboot connection must be reported as such rather than converted into successful acceptance. This normal-reboot test is distinct from start-up management of a production station application.

## Build jobs, cancellation and shutdown

A [generic background job](../JOBS.md) is a trusted source ZIP and argv recipe executed on a provisioned development host under a systemd service. This **is not a sandbox for untrusted code**. Jobs may survive controller disconnection but still obey host deadlines and explicit stop policy. Status/collection queries use the original job ID; cancellation records intent and retains completed outcomes and logs.

Routine host stop/terminate inspects remote jobs and blocks active or uncertain work; inspection failure is not a reason to assume safety. Explicit force is emergency authority, not a convenience for running builds. The guest systemd uptime timer is the currently documented protection, not a guaranteed AWS-side cost ceiling; the [cloud deadline proposal](../CLOUD-DEADLINE.md) is marked investigated but not enabled. Operators must not claim an EventBridge stop schedule exists without separate evidence.

## Transfer integrity and retained artifacts

The [artifact transport contract](../ARTIFACTS.md) uses content-bound identities and resumable local/SSM transfer state. Interrupted transfer should verify existing byte prefixes and resume rather than start another unrelated publication. SSM transport size bounds and the separate S3 backend's acceptance limits remain explicit. Frozen collected archives remain stable for retry; a checkpoint does not include partial local transfer data unless independently preserved.

## Recovery decision guide

| Observed condition | Safe direction |
|---|---|
| Original owned checkpoint is available | Retire the prior controller, restore the same workspace via handoff |
| Historical checkpoint irretrievably missing | Stop old writers; follow explicit operator-authorized adoption and marker verification |
| SSM submission may have occurred, CommandId absent | Keep uncertainty; investigate original command; do not resubmit |
| Exact SSM identity known | Inspect or wait on the same command, verify exact bounded result receipt |
| Normal reboot workflow incomplete | Reconnect and resume recorded phase, preserving before/after boot evidence |
| Host jobs active or status unavailable | Block routine stop/terminate until authorized resolution |

### Detailed contracts

- [Checkpoint integrity and controller handoff](../RECOVERY.md)
- [Lost-workspace adoption and owner epoch](../GATEWAY-ADOPTION.md)
- [SSM dispatch/recovery](../GATEWAY-DISPATCH.md)
- [Reboot evidence and test phases](../REBOOT.md)
- [Job submission, shutdown and cancellation](../JOBS.md)
- [Resumable artifact transport](../ARTIFACTS.md)
- [Cloud-side deadline not enabled](../CLOUD-DEADLINE.md)

This chapter is a runbook synthesis, not authorization to alter a live compiler host or deploy the gateway.
