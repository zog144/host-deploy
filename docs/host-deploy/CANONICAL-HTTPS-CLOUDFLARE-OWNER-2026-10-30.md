# Canonical Cloudflare credential consumer and Host owner policy — source handoff

2026-10-30. Owner: host-deploy Regular, draft PR #6.
Tracking: station-access PR #10, root-control PR #16, host-install PR #5.

## One protocol, never a bridge between draft wire schemas

The **sole** wire-format owner is `zog.host_identify.credential_delivery`
version 0.3.5, source `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`,
module blob `02332127defe565e00e398b71ada50d5c2bdd4d6`.
The enrolled Host's protected root-control PR #16 receiver owns:
- independently pinned Credential Authority-signed
  `zog-credential-authorization-envelope-v1`, separate from TLS trust and
  the signed certificate assignment;
- HostIdentity RFC9421-signed `zog-credential-request-v1` POST to fixed
  `/.well-known/zog/credential-delivery/v1`;
- Ed25519 Credential Authority-signed
  `zog-credential-delivery-envelope-v1` containing a bounded secret;
- anonymous-FD-only root-to-issuer installation using the existing
  `issuer_credentials.install_from_fd`, with dedicated UID and private
  persistent STATE;
- HostIdentity RFC9421-signed `zog-credential-installation-receipt-v1`
  POST to `/.well-known/zog/credential-delivery/v1/receipt`, and optional
  canonical cancellation to `.../cancel`;
- root-owned durable `zog-credential-delivery-ledger-v1`, separate
  signature-nonce replay tracking and conservative uncertain-delivery and
  cancellation/rotation behavior.

Host-deploy's old custom `zog-protected-credential-delivery-request-v1`
and `zog-protected-credential-delivery-receipt-v1` are **NOT** aliases
or authorized fallbacks. `certificate_cloudflare_https_consumer` is now
an inert tombstone: all previous `prepare`, `check_receipt`, and
`deliver_selected` entry points fail before contacting any network,
journal or installer. Station-access PR #9 raw-token ingress stays disabled.
No SSH bridge remains in this new interface.

## What host-deploy contributes: canonical nonsecret *owner-policy* adapter

`certificate_cloudflare_canonical.py` is a **pure preflight** layered
over existing `certificate_cross_host_admission.validate()`. Before a
native root-owned selected transfer, source provenance MUST show:

1. current genuinely signed host-discover certificate assignment and its
   monotonic authority, exact approved managed FQDN/DNS zone, owner status,
   HostIdentity fingerprint, Host/installation/STATE/registry and independent
   station signer pin;
2. host-install's independent, current protected second owner ledger,
   matching nginx delivery policy digest and locally approved consumer;
3. station vault authorization/projection and matching credential revision;
4. root-control's reviewed and installed issuer grant/storage UID/GID,
   immutable software view and controller record, with actual installed
   bytes and wheel RECORD attested by host-install;
5. protected exact root-control HTTPS receiver profile (same local
   approval hash **distinct from** the Credential Authority signed UUID),
   origin/TLS CA pin, and independently installed Credential Authority pin;
6. *actual Ed25519 verification* of the current signed v1 authorization:
   issuer origin, approved status, Host/STATE binding, fixed
   `consumer=certify-manage`, fixed `purpose=issuer-cloudflare-dns01`,
   Cloudflare credential ID/revision, signed authorization UUID/revision.
   The current root-owned canonical ledger cannot roll backward or conflict
   with that signed authority.

`verify_owner_binding()` returns ONLY nonsecret policy and verification
metadata. `plan_selected()` constructs the exact **canonical**
`zog-credential-request-v1`, using an externally selected UUID and
`deliver` or separately approved credential-rotation `renew` action.
It returns the shared state machine's next pending ledger as a candidate.
Only the native root owner can **durably fsync that state before network**;
the pure function cannot authorize network by returning a dictionary.
It rejects reuse of an existing request ID or a pending request.

`verify_native_installation()` is a final nonsecret comparison requiring
the root-control-confirmed delivered metadata (no secret fields), exact
credential and assignment revision in a native installer receipt, a
canonical installation receipt and a canonical already-`delivered` ledger.
It returns a candidate installed ledger, **not** proof that the receipt
was signed/transmitted, not a persisted ledger, and not permission to run
Certbot. Root-control must independently sign and transmit the receipt;
the Command-Center must authenticate it and durably commit installation
before acknowledging the result.

## Division of authority and source pin adoption

- **station-access PR #10:** public canonical source interoperability and
  vectors, but producer PR #9's old listener/raw response may NOT be
  activated. Station SecurityGate, signed authorization producer, protected
  vault reader and durable nonce/ledger/HTTP route must be reviewed
  independently.
- **root-control PR #16:** actual canonical receiver/FD/receipt owner.
  `LIVE_NETWORK_ACTIVATION=False` stays enforced until independent
  native acceptance. Do not expose a generic remote secret reader.
- **host-install PR #5:** currently pins **old** host-deploy PR #6
  `9ed396c...` and the old consumer module blob; its pin and wheel RECORD
  manifest MUST be updated to the exact final reviewed canonical adapter
  and inert tombstone before claiming a source/installation match.
  Host-install must not silently treat older install as compatible.
- **certify-manage PR #3:** read-only issuer Cloudflare `0600`
  `dns/cloudflare.ini` observation only. No auto-fetch on issue,
  renew, recover or inspect; persisted Certbot renewal account,
  challenge/credential revision checks and selected `inspect` stay in place.
- **host-deploy PR #3:** exact protected certificate-to-nginx delivery,
  readiness, reload and policy binding still required; credential receipt
  is NOT a certificate or nginx readiness record.

## Verification and independent native release

A separate exact-pin GitHub workflow checks host-identify 0.3.5 on
Python 3.12/3.13, untouched host-identify public state-machine tests,
station-access PR #10 public vector tests and host-deploy owner-policy
signature/rollback/purpose/replay/receipt negatives. The ordinary
host-deploy public suite tests that legacy custom transport is inert.

Native acceptance remains **NO-GO** until the complete root-owned source
and RECORD pins and the Command-Center canonical producer are installed;
then a separately approved disposable test verifies signed request/response,
durable nonsecret nonce and delivery ledgers, interrupted/duplicate
operations, cancellation/rotation, actual private-FD 0600 STATE and
reboot, zero secret leakage, issuer selected inspection and separate nginx
delivery. No real token, Cloudflare write, Certbot, ACME, nginx, retained
host operation, PR merge or network activation in this change.
