# Task C trusted-Host SSM submission — source reconciliation (2026-11-11)

**Decision:** use existing trusted `host-registry` administrator and its normal AWS IAM permissions for a single allowlisted SSM send. No new S3 checkpoint, independent anchor, operator-signed per-operation approval, installer signature, trust broker, signing key, separate owner-only IAM role, or dedicated EBS volume. The existing GitHub Actions → SQS FIFO → dispatcher process and managed image-build source selection remain.

## Exact source selection

- host-deploy PR #30 trusted-Host implementation: `src/zog/host_deploy/gateway/trusted_host_submission.py`, `generic_pipeline.py`, local `graphics_operation_send_intent.py`, `runner.Host`.
- root-control PR #47 companion: `6a545931a79e3f700dbf769b8a87fe33f9a6e620`, `task_c_trusted_host.py`. Its `LocalTaskCJournal` documents the same operation ID, local write-once, cancel and uncertain-result semantics. It is **not a second active sender or extra service** in this selection.
- host-install PR #35 ordinary single-service successor: `bdd6c449cf8943598bc0a269716d24c3982b24af`. Selects one `zog-task-c-gateway.service`, ordinary local Python environment and `/var/lib/host-deploy-gateway`, no socket owner, broker, S3, signed approvals or extra volume. Its native staging keeps service disabled until Work checks the real installation.
- The source-pinned companion checkouts are required to resolve to these exact Git SHAs. Later branch-head changes require independent re-review and exact-pin update.

## Active code path

1. Existing GitHub `issues.opened` → GitHub OIDC → FIFO SQS retains original issue, actor, request ID/digest, explicit allowed `build.submit` task and single-attempt queue preparation. Gateway `_base` requires admitted request, prepared dispatch, immutable reviewed task catalogue/source/month pin, and stage-once record. No arbitrary GitHub issue shell, AWS target or document.
2. `generic_pipeline.advance()` reconstructs each fixed operation (`capabilities.inspect`, `recipes.snapshot`, `pipeline.submit`, `pipeline.inspect`), checks original frozen request provenance under its request lock and calls `trusted_host_submission.selected_command`. That reopens the selected owned workspace/lane and exact frozen compiler instance/region/account through `verify_current_target`; it validates stage operation and source/catalogue identity and generates script bytes using the reviewed `remote_script(stage_binding)`. It accepts no caller-provided SSM document or generic shell. All existing source/recipe, predecessor, task limits and canonical output parsing remain in place.
3. Under the same gateway request lock, `generic_pipeline` **fsyncs the stage as `submitting` and then exclusively fsyncs a 0600 per-operation local send-intent BEFORE SendCommand**. The only authorized SSM mutation uses `runner.Host.submit_command`, which fixes `AWS-RunShellScript` and the prepared compiler target and configures botocore `total_max_attempts=1`. If AWS gives no CommandId, it remains `uncertain`; no retry or recreated operation. If a CommandId is returned, an exclusive receipt is fsynced and later `Host.inspect_command` performs read-only reconciliation.
4. Process restart, concurrent local attempts, duplicate SQS delivery and ordinary Host reboot must use the retained local journal/intent, never a second SendCommand. Cancellation of an unsubmitted operation is handled as a local journal decision; cancellation of an already-issued command is a separate bounded selected action. The existing producer capability, snapshot, submission and result-observation contracts remain. No full-disk adversarial rollback defense is claimed, by explicit trusted-Host decision.

The original signed-v2/v3 S3 history and broker source remains only historical draft code in the stacked branch and **is no longer referenced by the active generic pipeline**. The three obsolete graphical broker systemd templates and their signed-v2/external-history/owner-only SSM CI selection workflows were removed from this branch. Host-install's one-service path supersedes them. Do not accidentally activate historical broker units or claim their signing approval as a native prerequisite.

## Exact-head source CI

[Trusted Host SSM source and three-owner compatibility run #43078662978](https://github.com/zog144/host-deploy/actions/runs/43078662978): **48 PASS on Python 3.12 and 48 PASS on Python 3.13**. This includes:
- selected compiler instance/account/region, catalogue and immutable source, allowed document and operation, bounded script/timeout;
- original request provenance, original remote stage/tamper/recipe selectors and retained source limits;
- root-control's actual `task_c_trusted_host.intent()` contract, file/fsync ordering, one-attempt and cancellation vocabulary;
- host-install's actual one-service disabled installation selection;
- missing acknowledgement/reboot/duplicate journal and read-only result reconciliation;
- real `runner.Host` source fixed document and single SDK SendCommand attempt.

All source tests use fake Hosts/disposable local records. **They are not AWS/SSM or native installation evidence.**

## Native installation and acceptance — Work next

Work should use host-install's ordinary one-service installer, reconcile/stop any preexisting command-center gateway, verify the real source/venv/units, retained local gateway state and root account, and check the existing EC2 instance IAM role's actual SSM permissions. **Host-install's disabled unit intentionally starts the ordinary queue consumer without Fonts auto-submission.** Work must separately select the immutable root-owned one-task catalogue plus its exact SHA-256 and explicitly configure the reviewed `--advance-reviewed-generic --approved-task-catalogue PATH --approved-task-catalogue-sha256 SHA256` options (or invoke the individually supervised `generic-advance` command). Neither an arbitrary SQS message nor merely starting the unit authorizes compilation. No additional policy/role/S3 setup is requested. Verify the exact target compiler EC2 instance and approved `AWS-RunShellScript` policy; original GitHub OIDC role should still only submit the approved FIFO SQS message, with dispatcher queue receipt/visibility/DLQ permissions reviewed. A trusted shared Host may have SSM rights; do **not** impose the superseded gateway direct-SSM denial.

Prove from the real installed service: original GitHub/SQS validation, immutable Fonts one-task catalogue, exact compiler source/reader identity, libpng → FreeType → Fontconfig dependency closure, source rights, 30 GiB work + 2 GiB external reservation and six-hour budget, one successful CommandId capture, read-only inspection and cancellation. Negative/recovery checks must show a duplicate queue message, reboot, incomplete journal and lost SendCommand acknowledgement never produce a second command. Actual production IAM and resource admission are not established by GitHub source tests.

**Disposition:** source-compatible trusted Host sender and one-service installer contract PASS; native installation/AWS IAM and Fonts execution **NOT PERFORMED**. The integration no longer blocks on S3, signature approvals, extra roles or protected storage. No host, IAM, SQS, SSM, STATE or compiler changes occurred in this source review.
