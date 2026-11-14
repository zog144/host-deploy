# First Fonts — retained lane evidence, NOT execution authority (reconciled 2026-11-14)

This replaces the earlier 2026-11-13 activation handoff following the decision to
**remove alternate build-owner/build-worker accounts and selectable execution UID/GID**.
The former schema-4 activation and native-controller recovery procedures in that
handoff are **withdrawn**. No source test or inspection authorizes compiling.

## Immutable historical evidence

The authoritative original, if recoverable, is
`OWNER/image-build-lanes/gateway-first-fonts-runtime.json`. Its historical values
remain evidence rather than a new execution policy:

| Field | Retained historical value |
| --- | --- |
| Lane/schema | `gateway-first-fonts-runtime`, schema 4 |
| Host | `i-00ad300038a599044` in the authenticated owning workspace |
| Historical project root | `/home/certbot-build-owner/gateway-first-fonts-runtime` |
| Original specification digest | `sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2` |
| Producer | `zog144/image-build@1f07e83dbd80dacb9bed0d6494c697375f0e26cd` |
| Monthly pin | `project/pins/2026-10-01/commit-pin.py` — SHA-256 `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36` |
| Compatible build-record source | `a866c9c4b0dd385045f00ce2de7d809f5b67c104` |

No program may use the old record's execution UID/GID to select a user. Do not
write an alternate `controller.json`, alter the old source/digest or loosen the
old private home's permissions. An absent original record is a HOLD, not evidence
to recreate one.

## Supported read-only commands

```sh
host-deploy fonts-lane-profile
host-deploy fonts-lane-verify --workspace OWNER
host-deploy fonts-lane-prepare --workspace OWNER
host-deploy fonts-lane-migration-plan --workspace OWNER
host-deploy lane-inspect --workspace OWNER --lane gateway-first-fonts-runtime
```

`fonts-lane-verify` now checks the **local** original workspace/Host binding,
source/pin, full specification digest and collisions. It returns
`execution_authorized=false` and `migration_required=true`. It does **not**
contact SSM, read a live controller or save a fresh installed-facts snapshot.
`fonts-lane-prepare` returns the same historical record without writing it.
No `/etc/zog/first-fonts-controller-facts-v1.json` or configured execution-user
lookup is required.

`fonts-lane-migration-plan` produces a distinct **non-executable candidate**
(schema 5), removing the identity selectors and calculating the proposed
specification hash from the actual original record. Its new project root is
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime` (the reviewed
host-install project-copy destination). This is a proposed
migration destination, not an installed directory or permission grant. The
returned candidate digest is **not a final executable approval**: the original
producer does not accept inherited-identity controller configuration, and
root-control, box-control and image-build must first publish compatible
reviewed source. A supported native migration must then verify every original
artifact, source, persistent state, Project identity, running operation and
old/new binding before changing any active record. Never overwrite old state.

## Activation and installed-controller boundaries

**Old schema-4 first-Fonts lanes cannot activate or dispatch, even if their
record says `active`.** `fonts-lane-activate` is intentionally held. The old
remote installation-intent function also refuses to create a new intent. Any
old stored installed-facts file is historical material, not fresh authority.

For the future schema-5 runtime, the `fonts_lane_runtime` probe uses the
actual process `geteuid/getegid`, verifies normal filesystem/socket access
and reports the process's observed effective UID/GID, including UID 0. It does
not resolve an account name, switch users, chown files or accept caller-supplied
UID/GID. When invoked through SSM, this is the SSM **probe** process's identity,
not automatically the identity of the eventual compiler child. Root-control's
own service/child effective credentials must be read back independently. Runtime
source testing does not prove native compiler identity, source compatibility
or per-compilation enforcement.

## Separate existing acceptance

The accepted compiler base remains generation
`3805294fc8ccd9589aa75d3a6c5cb9367b7baf84b6ce131a84adafed7d34f9dc`,
`kind=image`, retained receipt
`sha256:a205c07bde4e6cf61e48061affd9a0b40c3a101e18dff67a9871995a3a2afafc`.
The gateway's two-file catalogue has its own identical-installation and
interrupted-receipt recovery rules. None of these records alone authorizes a
compilation. Default-branch GitHub submission remains an administrator opt-in
and must stay disabled until native readiness is accepted.

Do **not** restore the retired special Fonts 30 GiB/2 GiB/21,600-second
admission prerequisites. Ordinary disk admission remains. The independent
per-compilation `memory.max` investigation is not a new Fonts acceptance gate.

See [inherited-identity migration](FIRST-FONTS-INHERITED-IDENTITY-MIGRATION-2026-11-14.md)
for the remaining actual native filesystem/state and companion-source work.
