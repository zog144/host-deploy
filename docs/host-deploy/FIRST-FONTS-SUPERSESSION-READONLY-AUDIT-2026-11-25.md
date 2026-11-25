# November 14 first-Fonts supersession: read-only source audit

**Source-only; not a native recovery or build authorization.** This audit
addresses [issue #58](https://github.com/zog144/host-deploy/issues/58),
stacked on the read-only Project-current PR #57. It does not depend on
host-install PR #50 being selected on the compiler. The existing active
`certbot-seed` lane and both native Projects are left untouched.

## Conflicting historical identities

- The November 14 *prepared initialization destination* is
  `/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`.
  Its immutable initialization manifest records image-build
  `620378bdd8075daeb5eaad45eedea4af7db36423`; historical old
  schema-4 specification SHA `sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2`.
  It reportedly now has a controller and a later checkout, so PR #36's
  original controller-free `--verify` and PR #50's restore preconditions
  cannot be silently used as a workaround.
- The retained *active* schema-5 `gateway-first-fonts-runtime` lane
  selects the DIFFERENT existing Project
  `/home/certbot-build-owner/certbot-seed`, its lane-specific controller,
  and retains a separate `phase=installing` migration intent. This
  active lane has **no** `fonts_migration` ancestry. A missing historical
  schema-4 archive is recorded as **missing**, never fabricated.
- A successful return from one historical November 14 activation command
  may describe the initialized destination at that moment. It cannot prove
  the writer, source revision, installed controller, or later transition
  that selected `certbot-seed`. The retained original Gateway build request
  and its image-build pipeline are independent and NEVER replayed here.

## Supported phase 1 — registry-only read-only inspection

The following command executes ONLY against the existing protected
Gateway workspace filesystem; it does not invoke AWS, host-deploy's
`Host.command`, SSM, a root-control sender, host-install, the compiler,
or a source checkout. The three SHA values require independent native
review. Do not reuse the example as a native acceptance without checking
their actual current values.

```sh
host-deploy fonts-lane-supersession-inspect \
    --workspace /var/lib/host-deploy-gateway/workspaces/<reviewed-workspace> \
    --expected-original-specification-sha256 <exact-original-sha256> \
    --expected-corrected-specification-sha256 <exact-prior-migration-sha256> \
    --expected-selected-specification-sha256 <exact-current-active-sha256>
```

The CLI requires an **existing** protected root-owned workspace and
`workspace.lock`, opens the lock **read-only** and uses a nonblocking
shared flock. It cannot initialize a workspace, create a lock, receipt,
archive or intent, or change a live lane. It walks from the absolute
filesystem root through no-follow directory descriptors. The fixed
`workspace.json`, `host.json`, selected lane and migration intent
are opened through anchored descriptors, checked for owner/mode,
regularity, one-link custody, size and inode/readback stability, then
rechecked under the lock. A symlink, foreign file, writable ancestor,
mismatched selected specification, changed Host/Workspace or altered
intent is a hard HOLD.

The report always has:

```json
{
  "schema": "host-deploy-first-fonts-supersession-audit-v1",
  "status": "supersession-unproven",
  "historical_ssm_result_status": "not-authenticated",
  "selected_controller_observation": "not-authenticated",
  "initialized_destination_controller_observation": "not-authenticated",
  "superseding_writer": null,
  "evidence_transition_verified": false,
  "mutation": false,
  "ssm_send_authorized": false,
  "execution_authorized": false,
  "compilation_authorized": false
}
```

Additional fields hash the **actual retained raw lane and intent bytes**,
bind Workspace/account/region/instance ID, expected immutable current
controller bytes, both selected Project roots, the original and reviewed
corrected specification SHAs, and optionally authenticate a genuine
archived schema-4 raw record. No signed historical archive or accepted
success is inferred from its absence. An arbitrary local JSON claiming
SSM Success is **not** trusted and cannot turn this report into a
verified supersession.

This is a *diagnostic audit*, not a completion receipt. It does not
invoke `fonts_lane_recovery.publish()` or bypass
`gateway.project_current.verify_approved_lane()`. An old
`first-fonts-mixed-state-recovery-v1.json` likewise never becomes
new admission authority.

## Outstanding phase 2 — native independent proof (HOLD)

A separate source-reviewed read-only compiler inspection is needed for
both existing Project paths. The initialized destination's
controller-present condition must be reportable **without** treating it
as successful controller-free first initialization. Its immutable
manifest, source Git checkout, controller inode/bytes and original
STATE must be independently observed. The active `certbot-seed`
Project's lane-specific controller, source/current installed runtime,
project identity, permissions and mounted STATE require a separate
bound readback, under the actual compiler effective identity.

Native Work must also identify the **exact two original November 14
SSM CommandIds**, original instance/account/region, protected dispatch
intent and command outcomes, original operation/Workspace and their
verified stdout/result hashes; it must compare those to the current
protected lane's *source of mutation* (original and replacement raw
records, write/activation receipts, preserved journal/command history
where available). Neither a copied SSM JSON blob nor the successful
status of an old command is enough to prove the current writer.

The actual Gateway and compiler are **different Hosts**. Any fresh
compiler inspection must use a separately reviewed fixed read-only
inspection principal and protected, durable SSM send intent; **do not**
give the Gateway a direct general-purpose `AWS-RunShellScript`
fallback. Await host-install Regular's source-owned controller-present
destination inspector and independent acceptance before introducing a
native inspection route. Until phase 2 and authenticated transition
history exist, status remains `supersession-unproven`.

**No native writes, replacements, chown, manifest repins, controller
activation/restart, SSM replay, Gateway start, new issue, build.submit,
pipeline.resume or Fonts compilation are authorized by this source.**
