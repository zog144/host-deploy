# GitHub Actions → FIFO SQS → retained gateway → typed compiler restart
## Source-only audit and regression extension — 2026-11-02

**Scope:** candidate based on host-deploy PR #2 at
`5d5a0c3469e42d0a5a6ff79a92d5b680e0b414b6`, against host-deploy #5.
No AWS session, real GitHub OIDC token, SQS request, SSM command, compiler,
state or protected Host mutation. The existing dispatcher remains the only
public route; no new issue trigger, submission CLI or retry path was added.

## Existing controls confirmed

- `gateway.github_configuration` requires exact repository identity,
  original `issues/opened` event and run attempt one, original actor,
  configured actor and operation allowlist, matched AWS queue/account role.
- `gateway.github_dispatch` constructs origin from GitHub event rather than
  issue text; validates exact typed operation fields; uses FIFO request ID
  as deduplication ID and Workspace ID as message group. SQS send remains a
  single call, not an automatic lost-ack retry.
- `gateway.consumer` durably accepts an original request *before* queue
  delete; lost delete acknowledgment is recorded; repeated original request
  is idempotent and conflicting same-ID message is never acknowledged.
- `gateway.toolchain_supervisor` persists `submitting` before SSM and
  retains uncertain original operation identity after crash/lost response.
  No new submission is authorized from `uncertain`.
- Task admission is two-stage: issue protocol only selects
  `self-hosted-c-cxx-toolchain-v1`, while the protected server-side task
  binds producer revision, October source lock, lane, owner and seed
  generation; historical task sources cannot be used for new work.
- Existing project/source compatibility tests pin a reviewed image-build
  Git revision and October SHA-256; fresh cross-bootstrap remains a
  separately approved operation and is not submitted by source CI.

## Added negative and recovery regression scenarios

1. SQS send loses its acknowledgment after a synthetically recorded send:
   only one attempt, original FIFO message group/ID and canonical bytes.
2. SQS deletion uncertain; a *different consumer instance* receives the
   identical typed toolchain envelope and recovers the original durable
   request without preparing or advancing an additional compiler job.
3. Re-delivery of the same request ID with altered source commit, task,
   lane or original issue number is refused; original ledger remains.
4. Unreviewed tasks in the GitHub issue envelope fail protocol validation.
5. Typed journal crash while submitting: original request and operation ID
   survive repeated reconciliation and cannot auto-resume.
6. Stale seed generation, wrong source and changed predecessor are rejected
   even when a journal edit recomputes the unkeyed request SHA.
7. Forged unsupported worker phase is rejected despite an internally
   consistent operation ID, request bytes and digest.
8. Exact GitHub-hosted CI provenance check fetches image-build producer
   `31e6121cdf9fd05336286529666e2c35cdbe0831` and verifies original
   `2026-10-01` source-pin SHA
   `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.

The journal audit revealed a source gap: an unkeyed request SHA alone was not
sufficient to bind the remote request back to the frozen seed-generation,
predecessor and finite phase selection. `toolchain_journal.read` now
reconstructs the original authorized request from the immutable binding and
rejects changed inputs or invented phases before any SSM operation.

## Boundaries and future native acceptance

These are **offline source tests**, not proof of real GitHub OIDC/STS role
assumption, SQS durable delivery, true AWS restart/SSM recovery or Native
systemd 252 containment. The PR #2 protected worker and #5 one-off
cross-bootstrap still require their independent approved installed source
and policy attestation, exact new-lane identity, durable lock/cost/30+2 GiB
and six-hour budget, fresh original request ledger and a single separately
authorized native canary.

No change was made to the historical request #4. Lost or ambiguous
submission remains HOLD/reconcile only; never replace the original request.
Keep this patch and PR #2 draft pending exact-head source CI and native
independent review.
