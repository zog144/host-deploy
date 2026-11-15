# First Fonts — root-owned catalogue installation entry point

**Source candidate only; no Host has been modified by this PR.**

The supported command is installed by the ordinary host-deploy Python wheel:

```sh
sudo host-deploy-first-fonts-install \
  --lane <independently-selected-active-lane> \
  --generation <independently-accepted-64-hex-generation>
```

It is **not** a second gateway, request sender, Project initializer,
authority service or compiler admission path. It calls the existing
`graphics_catalogue_owner.install_native` and preserves its two permanent
root-owned 0600 files under `/var/lib/host-deploy-gateway`:

- `first-fonts-catalogue-v1.json`
- `first-fonts-catalogue-receipt-v1.json`

The original signed Ed25519 compiler acceptance and retained original
October pin are unchanged. Identical complete installs return unchanged;
a matching catalogue-only interrupted install can finish its receipt.
Foreign, partial, writable or symlinked files are not deleted or replaced.

## Installed native evidence (actual source input, not new approval)

The receiving Host's independently trusted root installer must first
place three **original, independently authenticated** inputs in
`/etc/zog/host-deploy/first-fonts-native` (root:root, mode 0700, with
root-owned/nonwritable, symlink-free ancestry). Each leaf is regular,
single-linked, root:root mode 0600:

- `compiler-selection.json`: canonical JSON with the exact schema
  `host-deploy-first-fonts-installed-native-evidence-v1`; fields
  `schema`, `lane_record`, `accepted_base`, `issuer_policy`,
  `producer_binding`, `origin_lane`, `host_identity`,
  `installed_sources`. This is a root-installed **collection of the
  original records**, not an independently invented approval.
  `lane_record` is an actual active schema-5 lane record, including its
  `specification`. `origin_lane` is the original schema-4 specification
  bound to the signed compiler receipt. `accepted_base` is the exact
  independently checked generation report from the reviewed native reader.
- `compiler-base-acceptance.json`: exact original canonical signed
  compiler acceptance bytes, with no recomposition or re-signing.
- `october-commit-pin.py`: exact original reviewed pin bytes, SHA256
  `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.

`host_identity` is
`{"schema":"host-deploy-first-fonts-installed-host-identity-v1","host_id":"...","installation_id":"...","state_volume_id":"..."}`;
the original issuer and producer binding must match each field.
`installed_sources` is
`{"schema":"host-deploy-first-fonts-installed-sources-v1","roots":{...}}`
with **exactly three** keys: original producer revision
`1f07e83dbd80dacb9bed0d6494c697375f0e26cd`, inherited executable
revision `620378bdd8075daeb5eaad45eedea4af7db36423`, and original
native acceptance reader revision
`1616f192ef9d8964a8f37f32a86c69c0242a213c`.
Each value is `{"root":"/protected/root-owned/source-copy",
"tree_sha256":"sha256:<64-hex>"}`. The hash covers the complete non-symlinked
root-owned immutable tree using the same file and metadata inventory as the
existing graphical import verifier. The root installer must populate these
paths and digests from separately inspected real installed source, **not**
from an issue, RPC, historical filename or a presumed HEAD. They are
rechecked against actual bytes before and after the catalogue write.

The entry point accepts only the lane name and generation identifier.
It rejects environment/CLI path overrides and cannot choose a replacement
issuer key, source, Host, installation, origin Project or controller account.
It does not treat a root-owned copied record as evidence the original
compiler generation was successfully inspected: Work still owns that
independent producer/installed-wheel/STATE attestation.

The same signed compiler Project root and ID may be reused for the original
lane. Distinct lane names sharing one Project remain on HOLD pending a
reviewed real controller-owner compatibility reader; no boolean override is
provided. No additional memory quota, worker user or certificate requirement
is introduced.

## Native Work checks before staging

1. Independently select the actual usable retained generation and output,
   **not** the lexicographically latest ID. Confirm the original
   Ed25519 acceptance, original host/install/STATE/project identity,
   generation manifest/inventory/probe, accepted reader revision, original
   pin/source bytes, original producer binding and current nonrevoked issuer
   using the actual native producer and installed root evidence.
2. Confirm active lane record belongs to this Host and selected Project,
   actual controller and Project state, compatible source and effective
   execution identity. Do not replace an existing controller or issue another
   account.
3. Install the exact evidence files and three verified immutable source
   copies in the protected root-owned layout; verify inode/mode/hash and
   installed host-deploy wheel including the CLI's module and entry point.
4. Run the command above with the independently selected lane/generation,
   observe the output and read back both canonical files. Re-run to establish
   identical no-replacement behavior. Exercise a copied/partial/foreign
   receipt or revoked/mismatched authority in a disposable tree, not live
   state.
5. Then configure the existing `zog-task-c-gateway.service` with the
   installed catalogue path and exact digest; run readiness and inspect
   real IAM/queue/SSM and controller identities before starting it.
   Enabling the currently static unit at boot remains a separate reviewed
   decision.

**Native NO-GO until all of these checks are demonstrated.**
This source does not issue an SSM command, start the gateway or grant Fonts
compilation. If the independently verified evidence cannot be installed at
these paths, report the actual missing native input rather than introducing
synthetic trusted-reader callbacks.
