# Original graphical SSM operation recovery — source correction and native gates

**Date:** 2026-11-03. **Owner:** host-deploy Regular. **Review inputs:** PR #15 `5c9a728c4c253ecf8929cb9c520b7b9ae3b25485`, independent replay audit PR #16 `a83601bba15b3eda6e89907e6c32223b3480bfbc`, issue #17. **Scope:** source-level, offline synthetic tests only, with no AWS credentials, SSM commands, compiler jobs or protected Host/STATE changes.

## What was wrong

PR #15 rebuilt each immutable `pipeline.submit` request from the original task. However, the original unchanged `prepared` journal could still be restored after SendCommand, and a coherently rewritten locally retained `recipes.snapshot` receipt could substitute a new snapshot SHA without an independent readback. Both were demonstrated as strict XFAIL security obligations (217 passing, two XFAIL) in [PR #16 review CI #41690685850](https://github.com/zog144/host-deploy/actions/runs/41690685850).

## Source corrections

### Per-operation exclusive send intent

The existing `generic_pipeline.advance` keeps its original request and per-request lock. A new fixed, gateway-owned `graphics_operation_send_intent` module stores immutable per-operation intents **outside** the rollbackable `generic-pipeline.json`, in `generic-operation-send-intents/<request-id>--<operation-id>.json`.

The intent is an exclusive O_CREAT|O_EXCL/O_NOFOLLOW, 0600 owner-only, nlink=1 regular file. It binds the complete frozen binding digest, task and catalogue SHA, source revision, selected immutable generation and target arguments through the entire task object and request SHA, lane/target, monthly pin, original request and phase/ordinal/operation ID. The directory is 0700, opened using retained directory descriptors with exact ownership checks. New directory creation fsyncs the parent; file and directory are fsynced before external SendCommand. The marker is never deleted, overwritten, or retried. A partial, unexpected, or existing marker means **HOLD**, not a second send.

`advance` now checks for any existing intent before preflight, writes a retained `submitting` journal, and persists the exclusive intent before the *compiler operation* SendCommand. Restoring the original byte-identical valid `prepared` stage cannot grant a second send while the separate intent survives. The existing operator request lock serializes the path. It does not create a second public submission route or auto-retry.

**Original SSM CommandId companion:** On the first successful SendCommand response, a separate O_EXCL/0600/fsynced `<request-id>--<operation-id>.command.json` binds the actual returned CommandId to the SHA of that specific send intent. A nonmatching, missing, symlinked or replaced command record denies later submitted/completed history. A command record surviving a missing intent still blocks reuse. If the response is lost, or an intent or command receipt publication fails after the send, the state remains uncertain and **cannot** automatically send again. The source can inspect the same original command in a subsequent explicitly authorized recovery flow, but cannot fabricate an original CommandId.

### Live original snapshot observation before pipeline.submit

Before a new pipeline.submit SendCommand, `_authenticate_snapshot_before_submit` requires exactly one completed source-bound `recipes.snapshot` stage with a matching exclusive send intent **and** original immutable CommandId receipt. It creates a fresh `Host.inspect_command(original_command_id)` readback via the existing SSM interface, rejects non-success and missing or changed `CommandId`, and calls the existing `image_build_execution.parse_receipt` using the **original frozen snapshot request binding**. It then verifies that the original observed result exactly matches the locally selected receipt and recomputes the snapshot `recipe_identity` with the original producer result validator.

Therefore a forged internal `recipe_identity`, `artifacts.recipe_snapshot`, prepared submit request and recomputed unkeyed SHA cannot authorize a different snapshot unless the *independent SSM original command observation* also supports it. The check is performed again for each new submit authorization, not on a cached callback or a locally copied JSON receipt. The snapshot readback **itself is read-only** and is not a new compiler job.

## Source regression evidence

The branch retains all earlier PR #14/#15 gateway, attester, selected-catalogue and typed-submission regressions. Former PR #16 strict XFAIL proofs are now mandatory **PASS**:

1. Old byte-identical prepared journal restored after synthetic original `pipeline.submit` operation -> **second SendCommand denied**.
2. Coherently forged local snapshot producer result and submit hash -> **denied before submit**.

Additional regressions cover lost SendCommand acknowledgement and old prepared replay; exclusive original intent+CommandId, partial/mode/symlink intent and command record, command ID substitution, surviving command record after missing intent, wrong/missing SSM CommandId, stale/wrong returned producer snapshot result and unavailable SSM readback. All use in-memory SSM Host simulators and ephemeral local files.

## Important remaining native security/rollover limitations — NO-GO

This source implementation protects **journal-only rollback** and original SSM result identity; it does **not** make ordinary local filesystem paths a genuinely independent monotonic authority. Rollback of the entire gateway storage including `generic-operation-send-intents` can erase both records. Local files may also be replaced by a sufficiently privileged local writer who controls that same UID. The existing selected graphical stage-once owner, root-protected current Host key, external checkpoint/issuer and original signed authority must be integrated into a **separately protected monotonic send-intent owner** before native activation.

A protected native owner and root-control Work must independently install/attest the exact original authority, ensure monotonic no-replace operations on a different rollback domain, cross-process ownership and lock identity, current Host/installation/STATE/epoch/revocation/rollback fencing, crash-safe parent fsync and recovery of original CommandId, and prove rejection of missing or rollbacked original ledger. The new `Host.inspect_command` is a documented SSM API readback and cannot by itself prove a genuine issuer or original native installed-byte/worker attestation. A compromised SSM producer, expired SSM output, source-checkout replacement or entire external trust-domain rollback remains outside source CI. Native review must test genuine receipt binding, replay/revocation, unknown ACK and reboot.

**Disposition:** source-only regressions for two previously observed gaps can be considered corrected **with this branch**, subject to exact-head CI and independent root-control source re-review. **Native compiler submission remains NO-GO.** No automatic expansion/replacement of authority. No EC2, SQS, SSM or protected STATE changes performed.
