# Host-deploy certificate delivery bridge v1 — owner implementation

**Status: source-only candidate.** Root-controlled host policy and exact consumer service must be approved before installing or starting the bridge. The bridge has **no ACME issuance capability**, does not route HTTP-01/DNS-01, and does not touch an archive lease, compiler ownership, station state, or a production ingress configuration on its own.

## Ownership and topology

\`certify-manage stage\` produces an **issuer-private-unbound** candidate under its isolated application mount:
\`<issuer_state>/publications/<certificate_id>/<certificate_leaf_sha256>/\`.
It contains \`receipt.json\`, \`fullchain.pem\`, and \`privkey.pem\`. The issuer does not authorize a TLS consumer or select nginx.

A root-owned **host-deploy certificate delivery service** must independently authorize exactly one application/service ID, exact SAN set, certificate policy digest, issuer UID, trusted Unix peer UID, TLS probe, and nginx unit. This reference bridge assumes the authorized issuer private state is accessible **on the same machine** to the root-owned host bridge. A separate-host transfer is NOT implemented; do not mount issuer state broadly or copy it across hosts to bypass that boundary. If the issuer is separate from the front-door nginx host, Work must design an authenticated, narrowed, source-attested transport and return that integration request before live acceptance.

The bridge's Unix-domain protocol accepts **only**:
\`\`\`json
{
  "schema": "zog-host-deploy-cert-delivery-request-v1",
  "service_id": "candidate-nginx",
  "certificate_id": "station-web",
  "fingerprint": "<64-lowercase-hex-leaf-fingerprint>"
}
\`\`\`
No arbitrary source paths, DNS provider credentials, raw PEM payloads, commands, AWS parameters, Certbot account/renewal metadata, service unit overrides, hostnames, or nginx configuration are accepted from the caller. On Linux the bridge authenticates \`SO_PEERCRED\` exact UID (not just socket access), and checks the root-controlled policy identity before processing. The requested fingerprint only addresses an already staged, immutable candidate under the fixed issuer subtree. Root/administrator direct CLI execution remains separately privileged. The root-owned socket parent must be non-writable to unprivileged users; the socket is mode 0660 and assigned only to the issuer's reviewed group. **No existing box-control/root-control general-purpose socket access is granted** by this arrangement.

The socket protocol is not exposed to station-access or browsers. nginx sees only the consumer-owned \`current\` files, never the issuer mount. Treat the issuer UID as a privileged issuance principal; compromise of that principal is not a general-purpose nginx policy override because SAN/service/receipt and root policy are independently checked, but it may compromise its own allowed certificate key.

## Root-controlled policy (template; not deployable without substituted approved values)

Example \`/etc/zog/cert-delivery-station-candidate.json\`, **root-owned regular mode 0600**, with secure non-symlink ancestors and exact fields:
\`\`\`json
{
  "schema": "zog-host-deploy-cert-delivery-v1",
  "service_id": "candidate-nginx",
  "certificate_id": "station-web",
  "hostnames": ["candidate.example.org"],
  "policy_sha256": "<exact-64-hex-certify-manage-policy-fingerprint>",
  "issuer_state": "/var/lib/zog-certify-manage",
  "issuer_uid": 15001,
  "peer_uid": 15001,
  "consumer_root": "/etc/zog/tls/station-candidate",
  "socket_path": "/run/host-deploy-cert-delivery/bridge.sock",
  "socket_gid": 15001,
  "nginx_unit": "zog-candidate-nginx.service",
  "nginx_binary": "/usr/sbin/nginx",
  "nginx_config": "/etc/zog/nginx/station-candidate.conf",
  "nginx_config_sha256": "<reviewed-candidate-config-sha256-64-hex>",
  "systemctl_binary": "/usr/bin/systemctl",
  "probe_host": "127.0.0.1",
  "probe_port": 18091,
  "probe_ca_file": "/etc/ssl/certs/ca-certificates.crt"
}
\`\`\`

All example FQDNs, service names, owner UIDs and GIDs are placeholders. Work must select the **actual operator-authorized real FQDN**, certificate ID, source/consumer identities, CA trust, resolved candidate HTTPS address, and approved nginx unit. The owner must independently approve the exact root-owned candidate nginx configuration and pin its SHA-256 in the protected policy. Missing, changed, unsafe, symlinked or default `/etc/nginx/nginx.conf` selections are rejected before publication. Every validation for activation, rollback and recovery uses `nginx -t -q -c <approved-candidate-config>`, not the ambient nginx defaults. **Work must independently confirm that the authorized systemd nginx unit loads and reloads that same -c configuration**, including effective unit drop-ins and nginx include files. Merely testing a different configuration does not prove that a service loads it. The source code deliberately has no hardcoded authority for those choices. For isolated acceptance, configure the separate candidate endpoint through the reviewed 18090 HTTP and 18091 HTTPS composition; do not alter the existing production ports 80/443. If the CA is ACME staging-only, public browser trust will not pass by default: record \`issued\` and \`delivered\` distinctly from live CA-trusted presentation, or use an explicitly test-scoped CA bundle. Staging issuance alone is not permission for a trusted production deployment.

Before enabling service, root-control/box-control must prove the issuer mount owner and mode, fixed consumer root inode/path, root-owned policy, persistent grant, and nginx unit. The root bridge needs only read access to the **single candidate subtree**, private 0700 consumer root and local systemctl/nginx-test authority; do not grant nginx writable access to the issuer directory. Private keys never appear in RPC JSON or success/error logs.

## Versioned delivery states and crash recovery

- **issued** — certify-manage's locally valid certificate and \`issuer-private-unbound\` staging receipt; not delivery.
- **delivered** — host owner has validated the receipt, certificate chain order/signatures, DER leaf fingerprint, SANs, validity (minimum 24 hours), private/public key match, policy digest and source file identities; it creates and fsyncs a root-owned private \`generations/<fingerprint>/\` directory.
- **nginx-loaded** — after atomic \`current -> generations/<fingerprint>\` pointer selection, \`nginx -t -q -c <approved-candidate-config>\` and \`systemctl reload <exact-approved-unit>\` have succeeded.
- **browser-verified** — CA-verifying TLS handshake with SNI for the bound hostname and exact observed DER leaf fingerprint on the operator-approved candidate endpoint succeeded. This is a backend TLS verification gate, **not a full browser/CSRF/proxy acceptance**.

\`/etc/zog/tls/station-candidate/current/fullchain.pem\` and
\`/etc/zog/tls/station-candidate/current/privkey.pem\` are the **only** nginx consumer paths. File contents are fsynced; consumer generation directories and key files remain root-only. A private \`delivery.json\` journal records the candidate fingerprint, previous symlink target, transition state and phase; it contains no PEM/credentials. Before changing \`current\`, the bridge durably records \`phase: uncertain\`, so an interrupted reload cannot be replayed merely because a request is resent or the service restarts. A consumer lock serializes all publications/recovery.

A successful publication returns \`state: browser-verified\`. An identical fully verified generation is an idempotent no-op apart from the TLS probe.

If \`nginx -t -q -c <approved-candidate-config>\`, reload or TLS probe fails, the bridge attempts to restore the previous **known** generation pointer, test and reload the approved nginx unit, and verify previous active TLS presentation if one existed. Verified rollback is journaled as \`phase: rolled-back\`; absence of a prior generation is explicitly marked **without HTTPS attestation**. A failed or interrupted rollback remains \`uncertain\` and is a hard operational blocker. On interruption, an operator may inspect current symlink, staged files and journal, then explicitly run \`--recover-previous\` to restore the journal's exact previous target, test/reload, verify previous presentation and retain recovery evidence. There is no automatic rollback/retry on daemon startup.

For a root-operator offline invocation after approval:
\`\`\`sh
/usr/bin/python3.12 -B -m zog.host_deploy.certificate_delivery \
  --owner-policy /etc/zog/cert-delivery-station-candidate.json \
  --fingerprint '<issuer-staged-verified-leaf-sha256>'

# Only after independent inspection of a retained uncertain journal:
/usr/bin/python3.12 -B -m zog.host_deploy.certificate_delivery \
  --owner-policy /etc/zog/cert-delivery-station-candidate.json \
  --recover-previous
\`\`\`

For a dedicated peer-authenticated service, use the same module with \`--listen\`, under a **reviewed root-owned systemd unit**. The root-controlled socket parent must be prepared safely and be group-traversable for the issuer. The service must have a private bounded write grant to only its consumer root; \`NoNewPrivileges\`, filesystem confinement and fixed import/version pins must be reviewed on the target OS. Do not enable a broad privileged service or mount an issuer private directory into nginx to work around a missing service boundary.

## Challenge selection and external route ownership

**host-deploy Work** must retain a separate reviewed routing decision and grant for authorized DNS names. HTTP-01 requires the exact port-80 \`/.well-known/acme-challenge/\` route from the public FQDN to the fixed issuer challenge webroot, without arbitrary reverse-proxy file access. DNS-01 requires an issuer-only, 0600 Cloudflare token with minimum permissions and no credential injection into this bridge. Neither is selected by the delivery RPC or publication CLI. Prefer staging ACME for initial issuance tests and record CA trust limitations and rate-limit risks.

A candidate may only be bound to the explicitly approved HTTPS consumer and its front-door owner. The signed archive lease/role decides which archive target nginx is permitted to proxy; this bridge must **never** change target selection, archive election, externally controlled launch, or routing. Keep the original portal nginx 80/443, production archive writer, and adopted compiler untouched until the explicit E–F cutover review.

## Acceptance gates and return to certify-manage

Offline: fail closed on missing/wrong policy, SAN, key, chain, digest, symlink/race, file owner/perms, bad peer UID, invalid request, duplicate generation conflict, concurrent publication, default-path or changed candidate nginx configuration, explicit `-c` on every validation, reload failure, TLS fingerprint/CA mismatch, interrupted journal and manual rollback. A same-process socketpair reflects the creating process credentials, not a simulated issuer principal; a distinct unprivileged Unix peer is tested separately. Test exact native staging format from certify-manage.

Work: stage exact issuer/view and protected policy in an isolated deployment; verify live Certbot staging issuance/renewal with reviewed policy/account and selected authenticator; inspect operator-approved DNS/port-80 routing; verify kernel mount/grant identities and root-controlled key access; exercise peer UID restriction, one approved candidate nginx, reload, HTTPS SNI/CA/fingerprint, renewal swap, known-failure rollback, interrupted-recovery and restart/reboot; retain issue/renewal receipts, generation IDs and traffic-switch boundaries. Publish redacted evidence (never private key, ACME account or provider token).

**No public CA trust, HTTPS readiness or production cutover is claimed by source-level tests.** This reference does not solve cross-host issuer-to-owner transfer or create nginx front-door composition automatically. If live topology has distinct hosts, a separate reviewed mutually authenticated transport is required; do not silently mount issuer private state across the network.

Return: actual approved FQDN and consumer, challenge/authenticator and authorization evidence, root owner policy binding, exact source revisions, issuance/staging/bridge receipts, rollback history, nginx/TLS/browser observations, and any needed certify-manage API changes.
