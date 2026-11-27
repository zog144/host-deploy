# Cloudflare DNS-01 credential consumer — approved Option B, source gate

2026-10-29 · host-deploy draft PR #6 · host-deploy PR #3 · certify-manage draft PR #3 · host-install #2

## Protocol ownership and trust boundary

The **Command-Center Host** is the HTTPS Credential Authority. A different
**Enrolled Host** runs the protected root credential receiver and the
non-root certify-manage issuer. These terms do not confuse the two roles as
"stations". The selected consumer is **issuer-cloudflare-dns01** ONLY.

This source-level implementation does NOT add a second credential exchange
protocol or an HTTP server. `certificate_cloudflare_https_consumer`
constrains one request and response of the common versioned
`zog-protected-credential-delivery-*-v1` protocol. The separate
host-identify/host-discover and station-access owners must provide the
authenticated TLS client and protected server/broker, with actual signed
wire-message verification, durable station-side anti-replay, revocation,
and source/installed-byte attestation. They are not implemented here.

The previous SSH client schema and `ssh_host`/`ssh_user`/`ssh_identity`
fields are replaced **in host-deploy PR #6** by a fixed `https_origin`,
`tls_authority_pin_sha256`, destination HostIdentity fingerprint, issuer
UID/grant/storage, credential revision and purpose. No SSH command,
SSH key-to-UID mapping or forced-command assumption is required.

### Protected owner decision BEFORE network

`certificate_cross_host_admission.validate` continues to match the
nonsecret, independently authenticated inputs from PR #3 and PR #6:
- host-discover signed approved, nonexpired/unrevoked **current** assignment
  (the cryptographic signature and monotonic owner ledger must actually be
  checked by host-discover/host-install before calling this pure function);
- exact Host/installation/STATE/registry/pinned independent station signer,
  the current FQDN and canonical DNS zone, DNS-01/local-cloudflare;
- host-install's separate protected monotonic owner ledger, root-approved
  grant, storage identity, issuer UID/GID, immutable software view and
  controller record;
- fixed nginx consumer binding and SHA256 of the selected protected
  certificate-to-nginx delivery policy;
- station credential authorization, current assignment and credential
  revisions, registered zone, local signer projection and active receipt;
- dedicated HTTPS authority pin and the approved Cloudflare consumer purpose.

A caller-supplied "verified" boolean is not trusted. The root-owned
selected operation must obtain these values via protected independently
authenticated file descriptors, trust roots and installed-byte gates.

### One selected HTTPS request and protected FD installation

`prepare` creates a **nonsecret** canonical, at-most-60-second request
binding the exact HostIdentity, host/installation/STATE/registry,
certificate/FQDN/zone, signed assignment receipt/revision, credential
id/revision, owner authority digest, policy, nginx delivery policy digest,
issuer UID/grant/storage, station HTTPS origin and independently pinned
TLS trust, plus a fresh 128-bit one-time request ID.

`deliver_selected` requires a native root caller to:
1. validate policy before contacting the Command Center;
2. persist a one-time pending/uncertain request under a protected root lock
   **before network activity**, with no secret material;
3. invoke the **common authenticated HTTPS client capability** on port 443,
   which must independently authenticate peer and verify the signed response
   bindings. A callback returning merely a JSON success flag is NOT proof;
4. receive at most one bounded private anonymous file descriptor of raw
   Cloudflare token bytes and a separate STRICT nonsecret receipt. No token
   appears in JSON, argv, environment, logs, shell, browser or diagnostics;
5. re-read/reverify current signed and second owner ledger plus actual issuer
   UID, grant/storage/view after transfer, rejecting expiration, revocation,
   rotation and source drift;
6. invoke the *existing* root-control `issuer_credentials.install_from_fd`
   with the exact canonical Project and `expected_authorization_id`.
   root-control performs the trusted private 0700 STATE, issuer UID/GID,
   atomic 0600 `dns/cloudflare.ini`, durable pending/installed ledger and
   credential revision checks. The FD is closed even on failure.
7. return a nonsecret **provisional** installation receipt. Separately
   selected native issuer readback/inspect and original certificate-to-nginx
   policy checks remain required for issuance or publication.

The consumer source has NO live transport, no generic remote root RPC and no
automatic secret fetch in issuer operation retries. **No implicit retries**
on HTTP, signature, root readback, journal or installation failure; preserve
pending/uncertain record for explicit reconciliation. Native root-control and
Credential Authority implementation remains a separate gate.

## Issuer/Certbot remains unchanged

certify-manage's new `cloudflare_https_contract.verify_installed` is a
read-only current root installation/revision + existing private Certbot
Cloudflare 0600 file observation. It is NOT part of arbitrary
`issue`, `renew`, `recover`, `inspect` or staging fetch.

Existing Certbot `dns-cloudflare` plugin uses the same absolute STATE
`dns/cloudflare.ini` path. Renewal still validates the persisted ACME
account/server/authenticator, and compares the file+inode credential
snapshot before and after the selected Certbot operation. `inspect`
remains selected InvocationID-bound and secret-free; root-control still
checks the installed grant, software view, STATE, UID and policy. Host-deploy
PR #3's atomic certificate-to-nginx delivery and readiness/reload gates
are neither bypassed nor enabled.

## Source tests and native NO-GO

Tests include approved exact DNS zone/FQDN, exact host/boot-independent
installation/STATE, policy/ledger/grant/UID/view, credential rotation, stale
assignment, revoked authorization, HTTPS downgrade, unrelated purpose,
one-time nonce and replay metadata, post-network issuer change,
before-network refusal, synthetic FD handoff, automatic fetch negatives,
private 0600 mode and secret-free result.

**Source-only**: test transport and installer callbacks are artificial; they
are NOT proof of common HTTPS TLS, signed envelope, dual-host anti-replay,
root privileges or installed source. CI and test evidence in GitHub PR #6
and certify-manage PR #3.

**Not authorized / NOT RUN**: real Cloudflare tokens, credential transport,
native privileged installation, DNS writes, Certbot execution, ACME issuance,
certificate delivery, nginx reload, EC2/SSM mutation, or PR merge. The
Command-Center HTTPS authority producer and root-control protected native
receiver must be installed, independently attested and exercised with
synthetic credentials first.
