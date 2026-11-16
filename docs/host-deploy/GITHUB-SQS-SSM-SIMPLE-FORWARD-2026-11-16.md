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
   The immutable original image-build source identity is assigned by the
   dispatcher, **not** the issue body.
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
   The source+lane binding selects the configured compiler Host, installed
   source checkout, existing Python/runtime companion and fixed
   `AWS-RunShellScript` transport. The generated image-build remote operation
   is `pipeline.submit` with `mode=image` and exactly
   `libpng-final, freetype-final, fontconfig-final` targets.
5. The request includes the **normal image-build arguments** `selection`
   (64-character existing generation ID) and `recipe_snapshot`
   (`sha256:` plus 64 hex characters). These are not gateway provenance
   certificates. They are explicit inputs already required by the selected
   image-build `pipeline.submit` API; image-build itself checks the
   generation, snapshot, recipes and build prerequisites. A historical
   `build.submit` request containing only `lane` and `task` remains valid
   for older separate supervised flows but is **not direct-forwardable**.
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
    "task": "graphics-fonts-image-v1",
    "selection": "<accepted-generation-64-hex>",
    "recipe_snapshot": "sha256:<existing-image-build-snapshot-64-hex>"
  }
}
```

No GitHub issue may supply `source`, `request_id`, a shell string,
account/instance ID, AWS role, SSM document, or arbitrary producer operation.
The existing trusted server controls the allowed source/Host and exact lane.

## Native-only gates

This source change **does not** send a Fonts compilation. Before turning on
`--forward-supported`, Work must review and install this exact source,
confirm the owned compiler Workspace/Host, correct active schema-5 Fonts
execution lane and installed runtime companion, AWS role permissions, FIFO
queue and approved SSM document. Confirm the existing image-build producer
actually supports `pipeline.submit` with an existing recipe snapshot and
generation (a missing producer snapshot requires image-build work, **not**
another host-deploy compiler dossier).

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
