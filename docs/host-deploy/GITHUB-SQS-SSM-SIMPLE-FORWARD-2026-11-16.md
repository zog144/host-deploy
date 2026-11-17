# GitHub Actions → SQS → SSM: finite forwarding (source candidate)

This is a **command transport**, not a second compiler admission service.
The old `host-deploy-first-fonts-install` and
`/etc/zog/host-deploy/first-fonts-native/compiler-selection.json` are **not
prerequisites** for the forwarding route below. No origin-lane, Ed25519
compiler-base approval, issuer-policy file, generation-digest dossier or
root-owned signed catalogue must be installed merely to forward a request.
Those historical issuer/catalogue tools are not used by this mode.

## Selected route

1. GitHub Actions accepts an **original** `issues.opened` event on
   `zog144/host-deploy`. It binds the author to the workflow actor, the
   original issue number to the deterministic request ID, and requires an
   operator-controlled allowed-operation list and `FONTS_ENABLED`.
   The source revision is not a lane or GitHub request selection: the
   selected Project supplies its current image-build checkout when SSM runs.
2. It submits one strict v1 request to the existing FIFO SQS target, grouped
   by Workspace. Duplicate delivery retains the same request ID and bytes.
3. A gateway service on the trusted Host runs:
   ```sh
   host-deploy-gateway run --queue-target "$ZOG_BUILD_REQUEST_QUEUE_URL" \
     --dead-letter-target "$ZOG_BUILD_DEAD_LETTER_QUEUE_URL" \
     --forward-supported
   ```
   The default service does **not** send work until this explicit mode is
   configured. Do not enable the legacy `--advance-reviewed-generic`,
   `--approved-task-catalogue` or signed graphical chain flags together with
   this mode. No custom command, SSM document, shell text or machine IP is
   taken from the GitHub issue.
4. Only `build.submit` with task `graphics-fonts-image-v1` and the active
   `gateway-first-fonts-runtime` lane is enabled in the finite mapping.
   The lane selects its **existing Project and controller**; the trusted
   Workspace supplies the configured compiler Host and the gateway supplies
   the fixed `AWS-RunShellScript` transport. The producer runs the Project's
   **current image-build checkout** with `mode=image` and exactly
   `libpng-final, freetype-final, fontconfig-final` targets.
5. The GitHub issue and SQS request contain **only** the fixed `lane`
   and `task` fields. The forwarded image-build request contains `mode=image`
   and the fixed Fonts targets, with **no** `selection` or `recipe_snapshot`.
   The compatible image-build producer (PR #26) reads the Project's current
   active image or toolchain generation. For this implicit image submission,
   its normal pipeline preparation loads the Project's **current package
   definitions and pins** and durably snapshots them into that pipeline.
   It does not require a prior published recipe snapshot. A missing usable
   compiler generation or missing recipe is an ordinary image-build error,
   not an authorization requirement. No `kind=toolchain` label gate,
   cross-Project search, manual copy, compiler-selection file, or added
   gateway preflight is introduced.
6. The original durable gateway ledger records the authorized request,
   frozen target/operation, **fsynced send intent before SSM**, returned
   CommandId, bounded invocation observation and remote result. Lost
   CommandId acknowledgement is `submission_uncertain` and never
   automatically retries. If the CommandId is known but the result is lost,
   inspect that same command and persist the observed result, without another
   SendCommand. A successful SSM invocation means the **transport invocation**
   finished: the retained image-build receipt may report `status=pending`,
   meaning the actual compilation has **not** completed. Use the original
   producer pipeline ID and its `pipeline.inspect` operation to determine
   subsequent build completion, not a second gateway compiler-dossier check.

## Request

The original issue template now supplies the supported operation's arguments:

```json
{
  "schema": 1,
  "workspace_id": "<existing-Workspace-32-hex>",
  "operation": "build.submit",
  "parameters": {
    "lane": "gateway-first-fonts-runtime",
    "task": "graphics-fonts-image-v1"
  }
}
```

No GitHub issue may supply `selection`, `recipe_snapshot`, `source`,
`request_id`, a shell string, account/instance ID, AWS role, SSM document,
or arbitrary producer operation. The gateway selects the fixed operation,
Workspace Host, Project and controller; the Project's checkout and package
pins are used at execution rather than validated against saved lane metadata.

## Native-only gates

This source change **does not** send a Fonts compilation. Before turning on
`--forward-supported`, Work must review and install this exact source,
confirm the owned compiler Workspace/Host, correct active schema-5 Fonts
execution lane and selected Project controller, AWS role permissions, FIFO
queue and SSM document. The native Project's **current** image-build checkout
must support the implicit `pipeline.submit` contract from image-build PR #26;
the former `620378bd...` checkout does not. There is **no** lane revision or
pin selection to update, and no new Project to create. Updating the existing
Project's checkout/packages via their supported installation process is
independent of the lane; do not rewrite historical lane records or build
outputs. Readiness must inspect the selected Project and controller, not use
a saved source revision or package pin as an authorization gate.

If the Project has no usable active generation or its current recipe closure
cannot compile Fonts, report the normal producer error. The source-only work
does not establish that the real Project has those prerequisites.

Run source/integration tests and use the existing `queue-status` and
SSM read-only inspection facilities for non-mutating connectivity checks;
this direct route enables only a mutating `build.submit`, so **do not**
exercise its live SSM path merely to test connectivity. Inspect durable
request/CommandId/result evidence and lost-result recovery. Do not replace
the real signed compiler receipt, generation, or active Fonts lane; do not
invoke a compilation from these source tests.

The legacy catalogue paths and historical read-only modules remain available
only for already deployed separately approved workflows; they are never
loaded by the direct forwarding path and should be retired separately once
any retained users are reconciled.
