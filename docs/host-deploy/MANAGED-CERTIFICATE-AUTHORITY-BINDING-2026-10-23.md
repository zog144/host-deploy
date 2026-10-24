# Managed hostname authority → protected local nginx delivery

**Owner:** host-deploy Regular  
**Status:** source-only candidate, native Gate B/C and production HTTPS **NO-GO**  
**Review branch:** `regular/certificate-owner-delivery-20261020` (draft PR #3)

## Producer trust boundary

The managed certificate authority source is the **original** detached
Ed25519-signed `zog-certificate-assignment-envelope-v1`, carried only by
the root-checkpointed host-discover observation
`zog-host-discover-certificate-authority-observation-v1`.
Host-deploy **does not** read UID-970 files, private station keys,
unprivileged beacons, browser requests or command-center JSON.

The installer must independently deliver these **three local root-owned
records**, all from reviewed native host-install enrollment/installation:

| Input | Canonical path | Mode | Content |
| --- | --- | --- | --- |
| Managed signer pin | `/etc/zog/host-install/certificate-assignment-authority.json` | root:root `0444` | The exact command-center Ed25519 public key, registry and SHA-256 fingerprint |
| Root authority checkpoint | `/state/host-discover-certificate-authority/authority.json` | root:root `0600` | Signed assignment, root history, host and installation identities, STATE ID |
| Independent local consumer binding | `/etc/zog/host-deploy/certificate-managed-binding.json` | root:root `0600` | Reviewed local nginx service and issuer policy, host/installation/STATE/registry/signer identity, hostname, DNS, ACME and credential revision |

All directories on these paths must be root-owned and not group/other
writable. Reads are root-only, descriptor-based with `O_NOFOLLOW`, exact
mode/UID/link-count/type and size checks. All path components, not just the
leaf, are opened relative to a retained and verified `dir_fd` from `/`.
A former `lstat`-then-open on absolute path could otherwise race against
a parent directory replacement; the corrected readers reject ancestor and
leaf symlinks rather than following them. No caller provides an alternate
path. These file paths and modes are versioned integration requirements;
this PR **does not install or create the records**.

The local binding contract,
`zog-host-deploy-managed-certificate-consumer-binding-v1`, contains exactly:

`schema, host_id, installation_id, state_volume_id, registry_id,
authority_key_id, consumer, service_id, certificate_id, hostnames,
policy_sha256, challenge, dns_mode, dns_zone, credential_id,
credential_revision, contact_email, acme_directory`.

`consumer` must be the reviewed managed source value
`host-nginx-https`; it is **not** a systemd unit. The separately
installed `service_id` selects only the host-owner's exact local
delivery policy and nginx unit. The root installer derives and verifies
`policy_sha256` from its independently approved issuer policy; it is
never selected by an assignment signer or browser. No Cloudflare token,
ACME private state, nginx key or credential bytes appear in these records.

## Consumer verification

`certificate_managed_authority.py` independently checks:

1. Root signing pin contract and fingerprint against the actual raw
   Ed25519 public key.
2. Root checkpoint schema, Host/installation/STATE UUIDs, registry,
   signer key, current revision and unique root operation-history entries.
3. The exact signed assignment, Ed25519 signature (canonical assignment
   bytes prefixed by `zog-certificate-assignment-v1\0`), content SHA-256,
   root operation ID and revision.
4. Signed exact certificate ID, DNS/acme challenge, FQDN list, credential
   identity and revision, ACME directory, contact email and fixed
   `host-nginx-https` consumer against the independently installed local
   binding. It rejects wrong origin, stale or mismatched identity and
   unreviewed field additions, including secret-bearing extensions.
5. Native owner receipt derivation under
   `zog-host-deploy-certificate-owner-authority-v1` and existing
   `compare_revision` anti-rollback *validation*. A higher signed
   revocation or expiry is never permission to deliver.

**Important:** deriving a candidate does NOT install a new root owner
receipt, certify native STATE durability, or establish a second durable
monotonic ledger. Host-install must own the atomic fsync'd publication,
retained highest accepted revision/operation/fingerprint and interruption
fencing. The signed root observation already has host-discover's own
independent monotonic root history; host-deploy must not silently replace
that with any UID-970 state.

## Protected delivery

The **opt-in** `--owner-authority` certificate delivery listener retains
the root-owned delivery policy and Unix `SO_PEERCRED` peer validation.
For a managed owner receipt, it now reopens all three exact root inputs
before Unix socket bind, and again **on every authorized delivery
request**, reconstructs the current signed managed receipt and requires
byte-equivalent semantic fields to the installed owner authority. If root
signing key or installation changes, the local policy differs, a newer
revocation supersedes an earlier approval, root records are missing,
permissions drift, or a signature/history is invalid, publication blocks
before any new nginx certificate generation or reload.

Standalone-local mode remains a separate reviewed
`authenticated-local-admin` producer/install path, not transformed into
a managed Host UUID. An existing legacy v1 listener without explicit
`--owner-authority` remains untouched for historical compatibility; it
is **not** a deployment GO for new managed HTTPS.

The established delivery engine remains responsible for issuer UID peer
authentication; strict staged PEM/chain/key verification; root-only
fsync'd consumer generations; exact nginx configuration test and service
reload; local SNI/CA/hostname/fingerprint validation; idempotent unchanged
certificates; and explicit rollback/uncertainty retention.

## Source tests and native acceptance gates

`tests/test_certificate_authority_anchored_paths.py` exercises both
managed and local owner readers on real Linux files/directories with symlinked
ancestors and leaves, exact file modes and bounded reads. GitHub Actions
simulates root file ownership for this unprivileged filesystem regression;
it does **not** claim installed root ownership or native storage/mount
acceptance.

`tests/test_certificate_managed_authority.py` uses **real synthetic
Ed25519 signatures** and covers valid checkpoint conversion, wrong
signer/host/installation/STATE, tampered payload, altered DNS/ACME/credential,
signer key mismatch, revocation/expiry, independently selected nginx
service and policy, and rejection when a current root checkpoint is
missing or differs from the installed owner receipt. Public CI declares
`cryptography>=44,<49`; this is a separately installed dependency, not
a bundled license grant.

**Required native follow-up:**

1. station-access: authenticated current assignment signing-key producer
   and explicit installation/Host authority, including local mode.
2. host-install + host-discover: independently pin signer key, verify
   managed root checkpoint and install local binding and owner monotonic
   publication on canonical STATE. Reject stale/rotated/foreign key,
   interrupted root publication, altered install ID, rollback and
   credential-revision drift, including across reboot.
3. certify-manage + controller owners: installed issuer immutable view,
   protected split UID/GID, selected renew/inspect/stage, invocation-bound
   evidence, isolated Cloudflare credential grant and local challenge route.
4. host-deploy Work: isolated real-owner native Gate B; then an explicitly
   approved staging FQDN and challenge for real nginx Gate C. Exercise
   authentic SO_PEERCRED, controller InvocationID, root observation and
   owner receipt continuity, interruption/reboot, unchanged certificate,
   failed nginx -t/reload, rollback and actual localhost SNI/CA chain.

There is **no approval** to issue public CA certificates, modify production
port 80/443 routing, enable unattended renewal, install issuer secrets,
or change production nginx/ACME state by merging or testing this draft PR.

## Historical gateway issue

[host-deploy issue #1](https://github.com/zog144/host-deploy/issues/1)
is a **one-shot October 19 read-only `build.status` request**, unrelated
to hostname authority or protected certificate delivery. It should be
dispositioned administratively against its historical gateway request
receipt rather than added to this PR's implementation dependencies.

## Source review follow-up — 2026-10-24

An additional review of both privileged authority readers found a path
replacement window: checking ancestry with `Path.lstat` followed by
`os.open` of the entire filename did not prevent a parent from being
renamed or replaced between those steps. The managed root checkpoint, root
signer pin, local consumer binding and owner receipt now use an explicit
`openat`-style descriptor walk for **all** directory components and a
final `O_NOFOLLOW` file open relative to the pinned parent.

The change does not broaden authority, modify the installed issuer policy,
or bypass the native-inspection guard. It does not establish atomicity
across an externally changing signed root checkpoint, owner receipt and
nginx reload: host-install still owns the durable root publication,
revision fencing and source-of-truth installation, and native Work must
test the full selected renew→inspect→stage→deliver operation under
interruption and concurrent revocation. The source gate alone cannot
authorize real TLS activation.
