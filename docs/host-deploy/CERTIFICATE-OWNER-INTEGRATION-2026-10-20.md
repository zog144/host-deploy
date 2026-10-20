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

1. **box-control producer corrected (source gate PASS):** 
   `zog144/box-control@a3e939b7a22ef6277ae9712961ffbd5a18ccac39`
   now admits `inspect` in the exact request result reader and rejects
   borrowed identities or malformed program values. Previous source
   checkpoint `dec2def825a474675def51df44d75d534e76508f` is superseded
   for this **new** selected-inspection source binding, not rewritten in
   historical deployments. root-control remains pinned for separate native
   acceptance at `3a2dd9c935e332e811adaccedf04b16bd2de1ea7`.
   Controller UID, installed checkout identity and invocation-bound systemd
   observations still require host-install/Work Gate B.
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

## Post-interruption continuation: authority-gated root delivery mode

The reviewed branch now adds `--owner-authority /absolute/root/owned.json`
to the certificate-delivery CLI and `serve(policy_path,
authority_path=...)` for a **separately selected versioned local
consumer mode**. The protected `zog-host-deploy-certificate-owner-authority-v1`
receipt is validated before opening the Unix socket, then reloaded and
validated on every issuer request before invoking the unchanged root-owned
certificate generation, nginx test/reload and local SNI probe.

This opt-in path does not change the already installed legacy listener,
does not authorize public port 80/443 routing and does not give a
command-center or network-traverse relay access to the private key.
`tests/test_certificate_hostname_authority.py` exercises rejection before
socket bind, CLI selection, and rejection of a foreign consumer. The
protected authority receipt must ultimately be installed by the approved
host-owner producer and correlated with the **local** host and installation
identities; no caller-supplied unsigned web assignment is sufficient.

A separate cross-owner issue is tracked as
[zog144/box-control#9](https://github.com/zog144/box-control/issues/9):
the controller lifecycle result client accepts renew/stage but not inspect,
even though the broker can launch inspect. Native selected-inspect Gate B
remains blocked until this producer fix is reviewed and pinned.

## Exact box-control producer correction and independent source acceptance

**New reviewed selected-inspection source pin:**
`zog144/box-control@a3e939b7a22ef6277ae9712961ffbd5a18ccac39`
(source file `box-control/src/zog/box_control/issuer_lifecycle_client.py`).

The host-deploy adapter now records the reviewed commit in
`ISSUER_LIFECYCLE_BOX_CONTROL_REVISION`; the certificate-controller
workflow explicitly checks out that **full SHA** and refuses a different
Git HEAD. `tests/test_certificate_box_control_source_pin.py` loads and
executes the genuine checked-out `issuer_lifecycle_client.py`,
`role_broker_client.py` and its inspection-evidence sanitizer, with an
isolated transport/broker contract stub to exclude unrelated image-build
package dependencies. It checks exact source-file location, selected
`inspect` request/result, saved request-ID correlation, malformed/borrowed
IDs, sanitized invocation evidence, and rejection of the inspection reader
without an authenticated controller UID. The stub is **not a native
SO_PEERCRED, systemd, issuer or nginx acceptance test**.

The workflow runs the new pinned-source acceptance under both Python
3.11 and 3.12. The historical production service paths, old source pin,
completed request identities, and renewal journals have **not** been
rebound. The selected-broker timer's explicit native inspection guard
remains, pending the separately approved root-control/installed controller
Gate B and end-to-end certificate Gate C.

**Next host-deploy Work checks:** verify exact box-control source and
installed immutable generation on an isolated host; confirm actual
SO_PEERCRED owner UID, distinct durable renew/inspect IDs,
controller-owned boot/invocation and journal evidence, 15-minute freshness,
recovery across interruption/reboot, and approved stage/nginx SNI delivery.
Do not enable production renewal or change ports 80/443.
