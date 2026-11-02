# Graphical attester and cross-Host issuer hardening — 2026-11-01

Scope: draft source correction stacked on host-deploy PR #8, not native acceptance.

## B1: root Python / immutable import trust

The privileged adapter no longer invokes root Git against the mutable Project checkout or runs the Project's frozen `python_executable` / `PYTHONPATH`. Root Git itself was unsafe because a Project-controlled Git configuration may execute fsmonitor/filter helpers. Source revision, Project and companion identities remain validated as frozen provenance in the request/dispatch; they are **not** an executable import grant.

The only permitted privileged Python launch is from an independently installed **root-only 0600** `/etc/zog/host-deploy/graphical-attester-import-v1.json` authority containing the exact producer source `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`, original October SHA, executable path/content digest, ordered protected module roots and a SHA-256 inventory of **all files**, including ignored/dotfiles. Module roots must be under `/usr/lib/zog/graphical-attester/`, exclusively root-owned, non-writable by group/other and without symlinks, hardlinks or writable ancestors. The inventory includes file bytes, mode, inode and device. `-I -S -B -c` bootstraps the reviewed module with only these roots; a second inventory check after execution refuses an in-flight change. A missing/uninstalled policy, invalid interpreter, injected ignored file, symlink or inode swap is NO-GO. The importer/source installer is a distinct protected host-install/root-control native prerequisite; source tests do not install these bytes.

## B2: true protected catalogue and receipt

The previous `sign_host_export(payload, keybytes)` root callable is retired and fails closed. `issue_native_step_export(task, time)` instead holds the existing native worker admission lock, validates the root 0600 original chain policy, current worker-owner/boot, root-owned native epoch, source/pin and independently pinned issuer key. It then calls the real protected `load_installed_step` and reopens the exact root 0600 receipt (original fonts or immutable successor), revalidates SHA and policy, and signs their complete canonical catalogue+receipt. The command-center verifier rejects any mismatched signed receipt content, hash, source, installation, Host, lane, boot, toolchain or policy. No test-injected signer is an installer grant.

## B3: authenticated gateway admission/dispatch

A copied directory called `authenticated-gateway-history` is not a trust root. Before invoking the producer reader, the root adapter now requires a separately signed `gateway-history-issuer-v1.json` authority and one exact signed request grant. The grant binds the original command-center request ID, request bytes, frozen dispatch SHA, completed progress/pipeline SHA, Host/installation/boot, owner epoch, lane, task, exact producer source, original October pin and protected chain policy. Wrong signer, missing grant, altered request/dispatch, changed completion state, foreign boot and ambiguity are rejected. A root-only native receiver provides an O_EXCL/fsynced original grant and permanent stage-once marker under the **same worker-admission lock**; a partial crash never permits a replacement or second stage on the compiler Host. Command-center signing authority, authenticated transport, issuer revocation and protected creation of the transferred ledger are still native installation prerequisites.

## B4: reboot, revocation and no replay

The command-center cannot consume a cached signed catalogue by itself. Every `load_selected_step` now requires a new random nonce and a signed online compiler-Host epoch response binding the exact export digest, task, installation, Host, boot, epoch, policy and a positive sequence. The local relay must pass exact Unix `SO_PEERCRED` UID from the protected public pin; the Host signature remains authoritative. A stale/replayed nonce, changed boot/epoch, old public pin, altered catalogue, missing/offline relay, excess lifetime, or foreign signer fails closed. The relay transport and protected remote live-epoch issuer, epoch/rotation transaction and acknowledgment retention **are not installed**. Native gateway use is intentionally NO-GO without those facilities. Independent root-control reviewer must check that live response is produced by the protected actual Host, not signed by the relay or answered from a cache.

## Acceptance and remaining gates

Source-only CI includes cryptographic negative tests, missing-pin and mutation-after-check refusal, ignored Python shadow, symlink/inode mutation, source interpreter replacement, live nonce/epoch/revocation, exact request+dispatch grant, existing gateway/compatibility suites and sudo ephemeral root-owned receipt and interrupted-history-grant regressions. These are fixtures only, not real compiler-Host signing/registration/installation.

Preserve original October digest `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`, three-task finite allowlist, original accepted stage-two toolchain, 30+2 GiB, 21,600 seconds, no automatic submission, uncertain retry, historical Host mutation or native activation.

**Do not merge or run native compiler based on this source patch.** Root-control Regular must independently re-review the exact current head. Host-install/root-control Work must verify genuine protected signer/public pin, immutable importer snapshot, issuer and signed-history bootstrap, live authenticated relay, current boot/revocation and root-owned one-shot grants. Only later may native systemd252 Worker/containment/quotas/reboot acceptance authorize a compiler test.

## Mandatory external graphical antirollback checkpoint (2026-11-01)

**Source integration, not native authority installation.** Host-deploy
`graphics_chain_export.load_selected_step` now **always** invokes
`graphics_external_checkpoint.require_current` before accepting the signed
Host export and again after checking a fresh Host-issued live nonce and
reopening the locally selected current key. The online checkpoint response
must be independently signed with the installed distinct Ed25519 external
checkpoint issuer, bound to a **fresh random 192-bit nonce**, current Host and
installation, exact SHA-256 of the canonical current public-key pin, exact
current epoch and external monotonic sequence. A coherent rollback of both
local current pin and local 0600 journal cannot authorize the old key when
the externally retained highwater has advanced.

The verification key and peer identity come exclusively from a protected
root-owned 0444 installation at
`/etc/zog/host-deploy/graphical-external-checkpoint-pin-v1.json`, with a
fixed Unix transport
`/run/zog/host-deploy/graphical-external-checkpoint.sock`. No caller may
choose external key material, a checker callback, an endpoint, or an offline
fallback. The relay is not the signing issuer; it can only carry fresh,
signed responses and must have the separately pinned Unix peer UID.
Missing or malformed external pin, an unavailable relay, old-key signature,
wrong Host/installation/epoch/pin digest, nonce replay or changing external
highwater causes HOLD before returning an accepted graphical catalogue.
The second independent checkpoint read catches advancement during the
remote Host live-epoch exchange, while the separate current-key pin
reread catches local rotation.

On the companion side, host-install's ordinary `rotate_source` now
requires its own fixed independently pinned checkpoint transport, performs
fresh signed read, external compare-and-advance **before** local key
publication, then fresh signed readback before and after local commit. The
formerly public uncheckpointed `rotate_source` facade is gone; its basic
filesystem crash test helper now resides only in `tests/`. The lower-level
`rotate_checked_source` remains a synthetic callback-driven contract
harness, and must **not** be selected as a protected native entrypoint.

**Exact source selection:** host-install PR #13
`adb0a15e3defd4e34b622a3867fe19d6afadeba7`, independent
root-control source checkpoint issuer `ca8232286b0bd01bd130bb02929a9e8b494c87cf`
as pinned by the three-owner synthetic workflow. No external issuer, true
monotonic store, live checkpoint relay, current Host authorization or native
source/RECORD has been installed or accepted. A fixed root pin plus signed
source proofs are **not** evidence of genuine issuer independence, linear
durability or reboot fencing; these remain root-control and host-install
Work native gates. No compiler jobs or new permissions.
