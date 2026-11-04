# Independent all-SendCommand review — graphical protected owner, 2026-11-04

**Exact selected contracts:** root-control PR #30 `ad5985ee602f24cbb5d45ef259c31d6c5a13e386` and host-deploy PR #22 `12f9fbf8bf9b6800b2a23039c12997c72f2cc0ea`. This draft stacks source corrections on PR #22, keeping production source selection and IAM unchanged.

## Critical additional bypass discovered

The initial protected gateway source removed `generic_pipeline.advance -> host.submit_command` but left `producer_runtime_preflight(host, stage_binding)` preceding selected-owner admission. **That preflight calls `Host.command(...)`, which internally invokes `Host.submit_command` and AWS SSM SendCommand.** A denial after this preflight was therefore too late and could submit an unfenced command.

The correction requires a separately selected `_selected_protected_owner_preflight` **and** selected owner for the stage before any Host is created or any remote action. There is deliberately **no native source implementation** for the protected preflight, so runtime default fails closed. A protected preflight must have its own separately preapproved original operation and irreversible independent claim; it may NOT borrow the stage's claim or use read-only assertions as an IAM send permit. Synthetic tests inject only a fixture-level attested result. The local `host.command` preflight path has been removed from the graphical stage advance.

## Other SendCommand entry points

The complete AST-based Python callsite census additionally identifies `image_build_execution.submit_prepared -> host.submit_command`, `toolchain_supervisor.advance -> host.submit_command`, `runner.Host.submit_command / Host.command`, the fixed-purpose `gateway.adoption` ownership-marker submission and `station.StationDeployment`'s packaged fixed-operation SendCommand. The adoption and station routes are NOT graphical build grants and remain distinct fixed-purpose operations; their installed AWS credentials must not be reusable by the graphical gateway. The legacy one-shot image-build path now rejects any currently selected first three graphical-chain tasks **before** creating a Host or invoking preflight; the existing generic capability gate is separately retained. Typed toolchain uses a different `toolchain.submit` contract and is not eligible to use the graphical original-operation ID or its frozen claim. `runner.Host` remains a general AWS helper for separately authorized older tasks and must be denied SendCommand IAM capability in the actual graphical gateway installation. Source guards **alone** cannot prevent an actor with AWS credentials from directly importing and calling it; native IAM separation is mandatory.

The root-control PR #30 owner retains a separately approved exact original operation ID→request SHA, Host/installation/STATE/fingerprint/registry/controller/target/authority epoch, signed short-lived send and revocation approvals, single owner-side serialized claim before the sole trusted SSM call, no-release/never-retry history, and fresh read-only signed observation.

This review adds cross-source tests for owner unavailability before preflight, missing protected preflight despite stage owner, unauthenticated preflight response, restored gateway records after lost ACK, concurrent duplicates, signed revocation, alternate legacy graphical route, and SSM mutation call-site audit.

## Native NO-GO

A positive synthetic result cannot establish that the real signed original approver, protected external monotonic CAS, current native Host/installation/STATE/boot and actual installed owner-selected preflight/SSM sender exist. Before any native execution, prove independent current-authority authentication, nonrollbackable claims for *each* preflight and stage send, exclusive revocation ordering, protected socket peer, and gateway IAM denial (no direct SendCommand on old or alternate routes). Reboot/power-loss and remote command ID reconciliation remain Work-only. No AWS, SSM, signing keys, canonical STATE or production pins were touched.
