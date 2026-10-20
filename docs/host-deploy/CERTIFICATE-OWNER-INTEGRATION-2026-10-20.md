# Host-owned HTTPS certificate integration — source checkpoint (2026-10-20)

**Status:** source tests passed; **native/live deployment NO-GO**. Branch:
`regular/certificate-owner-delivery-20261020`, draft PR #3, based on
public `unstable@eba1b6eaae0e73b2469404243a15bc7fcad37b3e`.
The live 80/443 listener, nginx systemd unit, DNS, Cloudflare credentials,
ACME directories, renewal timers, production assignment policy and issuer
state have not been changed by this source branch.

## Existing host-owned delivery components (retained)

The existing `certificate_delivery.py` implements
`zog-host-deploy-cert-delivery-v1`, a root-owned Unix socket delivery bridge
with `SO_PEERCRED` issuer-UID authentication. The client request is limited
to exact service/certificate/fingerprint (no caller-selected file, nginx unit
or shell). It reads a protected `certify-manage stage` generation, verifies
strict metadata, private key, X.509 chain, fingerprints, file ownership and
sizes, writes an fsynced consumer generation, atomically switches the
generation symlink, runs a pinned `nginx -t -q -c <approved configuration>`,
reloads only the configured nginx unit and validates the active local
SNI endpoint with CA chain/hostname and exact leaf fingerprint. It retains
the previous generation and journal, and supports explicit rollback and
uncertain-state recovery. Unchanged previously installed certificates do
not trigger a second reload.

The new `publish_authorized` entrypoint requires an additional root-owned
`zog-host-deploy-certificate-owner-authority-v1` receipt binding the exact
local consumer/certificate/hostname/issuer policy. The old v1 API remains
unchanged; any activation of this versioned authority gate must explicitly
select it and provide the separately verified protected root policy.

## Selected inspection consumer changes

`SelectedIssuerController` now recognizes exact
`certify-manage/{renew,inspect,stage}`; the new inspection reader is only
enabled with an explicitly installed numeric `controller_uid`, passed to the
upstream `IssuerLifecycleClient` for Linux `SO_PEERCRED` verification before
calling `inspect-result`. The selected-inspection journal persists its
distinct inspection request identity before launching and correlates the
result to the original saved renewal ID; uncertain request status never
authorizes minting another ID.

The dedicated host correlation validator consumes the actual
`zog-trusted-issuer-inspection-v1` envelope, not the older proposed
`zog-controller-selected-inspect-evidence-v1`: exact inspect request and
runtime IDs, program, boot/invocation IDs, issuer UID/GID, grant/storage,
policy digest and X.509 inspection fingerprint/SAN/validity, **15-minute**
freshness, plus the independent `zog-trusted-issuer-observation-v1`
record from the original renewal. A verified issuer read is NOT proof that
nginx serves the certificate. An authenticated reader cannot be replaced
by a caller-supplied callback.

## Hostname/DNS owner scope

`certificate_hostname_authority.py` adds a versioned local owner
**validation contract** with managed or standalone-local origin, exact
installation/host/operation UUIDs, monotonic revision, revocation, maximum
31-day authority validity, DNS-01 credential *identity and revision*, zone
binding and exact local consumer. Its `read_owned` requires a private
root-owned file and non-writable trusted ancestry. This does not accept
browser requests, arbitrary station user IDs or Cloudflare token bytes.

Managed mode requires a separately authenticated signed host-discover
assignment, and standalone-local requires an authenticated local
station-access admin intent converted by the host owner. These producer
attestation and policy-install integrations are **not connected** in this
branch. Direct provider token delivery/rotation is not enabled.

## Cross-owner blocks for native acceptance

1. **box-control Regular:** pinned reader revision
   `dec2def825a474675def51df44d75d534e76508f` and root-control
   `3a2dd9c935e332e811adaccedf04b16bd2de1ea7`. The inspected
   `box-control/issuer_lifecycle_client.py` currently includes
   `inspect` in launch but only `renew,stage,None` in
   `application_request_result`, rejecting the genuine inspected
   operation. The producer owner must correct and test this before native
   integration. Controller service UID must be approved by host-install.
2. **host-deploy Regular:** the existing renewal timer's selected-broker
   entrypoint is still deliberately guarded by
   `_require_approved_native_inspection`; connect the newly authenticated
   selected-inspection coordinator and retained journal observer only
   after cross-owner review, and remove the guard only under explicit
   enablement. In particular, the older `certificate_issuer_inspection`
   persistent issuer-UID socket is not a substitute for the finite
   authenticated controller result.
3. **host-discover / station-access:** authority producer and owner install
   handoff for approved signed/revoked FQDN assignments, including
   standalone-local binding and install identity.
4. **host-install / issuer owner:** protected issuer-only Cloudflare
   `dns/cloudflare.ini` secret provisioning, rotation/revocation, actual
   authenticated owner UID/mounts and pinned immutable Certbot view.
5. **host-deploy Work:** independent isolated native acceptance of 0600
   staged key, root consumer generation, nginx configuration guard,
   rollback/reboot uncertainty and local TLS SNI/CA chain with an explicitly
   approved staging FQDN/challenge. No live CA issuance, port-80/443
   change, Cloudflare token/credential writes or unattended renewals
   without separate authorization.

## Source-only verification

Run `.github/workflows/certificate-renewal-contract.yml` and
`.github/workflows/pytest.yml` on the exact reviewed feature-branch commit.
The former tests controller request identities; the latter compiles all
shipped Python and runs certificate renewal/inspection, delivery and
hostname authority tests plus source wheel packaging. The root-owned
filesystem/peer tests may skip on unprivileged CI; **CI PASS is not a
native-security or public HTTPS acceptance**.

Publication/delivery gates remain distinct:
`issuer-verified` -> `staged` -> `delivered` ->
`nginx-loaded` -> `browser-verified`.
No command-center or nonterminating relay receives a TLS private key.
