# First Fonts — retained approved lane and controller recovery (2026-11-13)

**Scope:** source implementation and native Work handoff. No GitHub submission, SQS
receive, live SSM operation or compiler run was performed in this source pass.

## Authoritative retained identity

`host-deploy fonts-lane-profile` selects the original approved record, **not a
replacement prepared lane**. The exact reviewed compatibility binding is:

| Authority | Required value |
| --- | --- |
| Lane | `gateway-first-fonts-runtime`, managed schema-4 |
| Compiler EC2 Host | `i-00ad300038a599044` in its authenticated owner workspace |
| Retained project root | `/home/certbot-build-owner/gateway-first-fonts-runtime` |
| Retained specification SHA-256 | `sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2` |
| Producer | `zog144/image-build@1f07e83dbd80dacb9bed0d6494c697375f0e26cd` |
| October pin | `project/pins/2026-10-01/commit-pin.py`, `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36` |
| Build-record compatible source | `a866c9c4b0dd385045f00ce2de7d809f5b67c104` |

The `source-owned` mechanism **does not** move this project to the new-profile
`/var/lib/zog/image-build-lanes/...` location, synthesize its original controller
settings, change its existing Project identity or rewrite the approved
specification. The approved digest covers the **entire** existing specification,
including controller settings, Python executable, resource-policy fields and
provenance identities. A different value, even a reasonable-looking default,
**must fail closed**. Historical controller/Project identity comes from the
original `OWNER/image-build-lanes/gateway-first-fonts-runtime.json`, not a new
root-owned configuration assembled by an operator.

The new v3 compatibility profile supersedes the uninstalled v2 first-Fonts
source-owned profile. A v2-generated lane must not be silently migrated. The
ordinary lane record schemas and their digest calculation are unchanged.

## Installed facts producer and read-only inspection

The original record is the **lane-owned authority** for Project identity,
controller policy and source/pin selection. `image_build_lanes._controller`
is the **host-deploy-owned producer** of the exact `controller.json` bytes.
The selected compiler Host supplies independent read-only installed facts:
root-control socket type/path, passwd execution UID/primary GID, executable
Python file, observed state directory (when used), project path status, and
exact bytes of an existing `controller.json`.

This arrangement is consistent with the current root-control socket and
box-control Project model; it does not invent a separate installation
interface. It does **not** use or require a manually written
`/etc/zog/first-fonts-controller-facts-v1.json`. A future NEW lane identity
may require an installer-owned producer/exporter approved by root-control and
box-control; that is **not** a prerequisite for using this retained lane.

After recovering the original authoritative owner workspace and retained
record, run these supported commands:

```sh
host-deploy fonts-lane-profile
host-deploy fonts-lane-verify --workspace OWNER
host-deploy fonts-lane-prepare --workspace OWNER
host-deploy lane-inspect --workspace OWNER --lane gateway-first-fonts-runtime
```

`fonts-lane-verify` uses read-only SSM on the *workspace-selected Host*; it
checks live installed facts against the retained controller and writes only
`OWNER/first-fonts-verified-facts-v2.json`, with binding, spec digest,
observed controller hash and timestamp. The observation is valid for one hour.
The no-manual-JSON `fonts-lane-prepare` is **read-only and idempotent** for this
retained lane. It verifies the record and fresh installed evidence, checks
**every** retained record for name/root/Project conflicts and returns the
original record unchanged. If the original prepared record does not exist,
this operation **HOLDs**; it never creates a substitute with a different
Project root or identity.

## Explicit activation and interruption recovery

Only after exact digest and owner review, run:

```sh
host-deploy fonts-lane-activate --workspace OWNER \
  --expected-specification-sha256 \
  sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2
```

The activation path uses an exclusive remote controller installer and a
separate installed readback. It **never** uses generic lane `Host.upload` to
replace an existing controller. Every attempt authenticates the Host, exact
spec digest, original project root and saved inspection before contacting the
Host. Read-only inspection distinguishes:

- **Active + installed complete:** verify exact directories/controller and
  return the existing record without rewriting any Host/workspace state.
- **Prepared + installed complete:** authenticate all identities and safely
  finalize the original local record as `active`, preserving the specification.
  This is the recovery for an interruption **after** remote controller creation
  and **before** the workspace active-state update (including old installations
  made before an activation intent existed).
- **Prepared + installed absent:** check the ordinary aggregate **disk**
  admission (not RAM reservations), durably save
  `OWNER/first-fonts-activation-intent-v1.json`, then create only the absent
  project directories and controller file using exclusive/non-replacing
  operations. Independently read back the exact bytes before setting `active`.
- **Intent exists + installed absent/partial:** **HOLD**, inspect the original
  SSM command ID and remote evidence; never blindly send another command.
- **Unexpected partial/foreign/malformed controller or different Host/identity:**
  **HOLD**. Do not unlink, replace, chmod or import an unrelated directory or
  configuration to make a retry pass.

The activation intent has the original specification digest and workspace
Host binding; it is durable before remote mutation. The original retained
specification is never changed. An already-active matching lane's repeated
activation only verifies and returns the current record.

Native Work must check the selected compiler's account ownership, root-control
installation, source checkout/companion compatibility and genuine accepted
compiler-purpose receipt independently. If the original workspace/record is
missing, **do not invent a new one** or interpret an absent remote directory as
proof that the record never existed.

## Catalogue and submission boundaries

`graphics_catalogue_owner.install_native` authenticates the managed execution
lane, the original separately accepted compiler project/receipt, source bytes
and host/installation identity **before** inspecting the two root-owned files.
It accepts an identical complete catalogue+receipt unchanged, and can finish
an exact catalogue-only interrupted write by creating just the missing receipt.
Conflicting bytes, symlinks, malformed metadata or receipt-only state remain
visible errors. No alternate catalogue, migration or overwrite is permitted.

The compiler base remains generation
`3805294fc8ccd9589aa75d3a6c5cb9367b7baf84b6ce131a84adafed7d34f9dc`,
accepted `kind=image`, receipt
`sha256:a205c07bde4e6cf61e48061affd9a0b40c3a101e18dff67a9871995a3a2afafc`.
Do not reissue its receipt, rewrite its original project or mistake catalogue
installation for compilation authorization.

**The old Fonts-specific 30 GiB work, 2 GiB external and 21,600-second
acceptance prerequisites remain removed.** The general lane disk-admission
check is retained. Effective per-compilation `memory.max` enforcement is a
separate investigation and is **not** an additional first-Fonts blocker.

The default-branch workflow is prepared independently in [host-deploy PR #34](https://github.com/zog144/host-deploy/pull/34).
It removes the literal submission hold but remains administrator opt-in via
`ZOG_GATEWAY_SUBMIT_ENABLED`. Work must keep that disabled until original
lane, two-file catalogue, receiver readiness and queue identity are genuinely
accepted. Only then open **one** genuine authorized Fonts GitHub issue and
trace issue → Actions → FIFO → durable gateway acceptance → SSM command ID →
actual image-build compilation result. A lost acknowledgement is reconciled by
its durable identity, **not** by opening another issue or resending blindly.
Previously accepted IAM evidence is reused unless observed failure disputes it.

Source tests and CI do not establish any native installation or successful
compilation. No live Host/queue mutation is authorized by this document.
