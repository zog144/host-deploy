# November 14 historical SSM command readback — protected source candidate

**HOLD: no original command IDs or script hashes have been accepted.**

This source-only successor to [PR #59](https://github.com/zog144/host-deploy/pull/59)
implements **read-only historical CommandId observation**, not SSM submission.
The original November 14 migration ran before the current Gateway protected
root-control send-once path; the two old migration commands might not have
corresponding root-control journal records. **If so, this readback necessarily
HOLDS rather than manufacturing a provenance chain.** A successful old SSM
result alone is not evidence of the later replacement of the active lane by
`certbot-seed`.

## Fixed trust boundary

`fonts_lane_historical_ssm_readback.inspect()` requires, before any AWS call:

- A fresh valid, nonauthorizing PR #59 registry audit that binds the
  **current** active schema-5 `certbot-seed` lane, its raw SHA, the
  distinct November 14 destination, the immutable original schema-4 digest,
  and the retained `installing` migration intent.
- A previously existing protected Workspace file named
  `first-fonts-nov14-historical-commands-v1.json`, with **externally
  reviewed exact raw SHA-256**, whose canonical JSON contains two distinct
  `operation_id` and `CommandId` pairs, original request/script SHA-256,
  target Workspace/account/region/instance, exact selected-lane digest,
  retained intent SHA and bounded original execution deadlines.
  **No code here creates, signs, imports, copies or approves this file.**
- Each operation's **existing** root-control `*.intent.json` and
  `*.command.json`, root-owned, mode 0600, full O_NOFOLLOW/one-link and
  canonical-JSON validation, under the existing root-owned 0700
  `/var/lib/zog-task-c/operations` and its existing read-only locked
  `.lock`. The command must equal the original journal's CommandId,
  request SHA, fixed script SHA and exact compiler instance. Cancelled,
  incomplete, missing, foreign, or uncertain original sends HOLD.
  There is **no** `LocalTaskCJournal()` construction because its
  initializer may create `.lock` and fsync a journal.

Only after both protected original command entries match does this contract
use the AWS read APIs `sts:GetCallerIdentity`, `ssm:ListCommands`
(by exact original CommandId) and `ssm:GetCommandInvocation`
(by original CommandId and fixed compiler instance). AWS account and
selected region must match the frozen registry binding. The AWS-reported
original `AWS-RunShellScript` instance-only target, exact shell script
SHA-256, execution timeout, document and November 14 requested timestamp
must match the original immutable journal. The accepted invocation must
be terminal and agree with the command status; wrong Target, foreign script,
partial output, missing AWS retention, or permission denial HOLD.

Only bounded output **prefix** SHA-256 and byte lengths are returned; the
observer does not redistribute stdout/stderr, follow S3 URLs, or claim that
the original complete output was retained. Successful command status proves
**the command's historical SSM status**, not a verified original migration
receipt, later lane replacement, or source authority.

The method has **no sender**, `SendCommand`, shell invocation, controller,
installer, source selection or file-writing API; it also performs a fresh
Gateway-lane and original root-journal readback after AWS access. It always
returns `supersession-unproven`, no writer, no migration-to-active-lane
transition verification, `mutation=false`,
`ssm_send_authorized=false`, `execution_authorized=false` and
`compilation_authorized=false`.

## Crucial native status and next requirements

**The existence of the exact two original November 14 root-control journal
records is NOT established.** The original `fonts_lane_migration.activate`
used `Host.command()` which in the older source can call general SSM
without recording a protected journal. Do not create root-control intents
after the fact or reclassify a generic Work command as root-control
authenticated. A separate independently reviewed, nonreplay proof
path may be required using original cloud histories/CommandIds and any
available Work receipts. That path must distinguish evidence of an old
command from authority for the present lane.

PR #51's host-install controller-present source must independently pass
review and native installed-byte checks before its observations can be
treated as compiler evidence; likewise PR #59's fixed two-Project native
candidate has no approved SSM send path. Nothing in this source allows
running it on the protected Gateway with new IAM permissions without a
separate native principal/permission review.

Source regression fixtures create a **synthetic** original protected pair
and mocked SSM ListCommands/GetCommandInvocation results, test two exact
original command statuses, changed Gateway, wrong account/region, forged
script/instance, source and command mismatch, missing/cancelled original
records, foreign files and no replay. Their fake CommandIds are NOT real
historical IDs and must not be treated as original Nov14 evidence.

**No live Gateway/SSM/Host change, unknown old operation replay, native
reconciliation, controller activation, lane JSON rewrite, new build, or
pipeline resume is authorized by this development.**
