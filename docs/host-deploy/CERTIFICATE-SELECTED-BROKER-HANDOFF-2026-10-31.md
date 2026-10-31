# Source-only selected broker authentication and inspection correction

Owner: host-deploy Regular. Review handoffs: box-control PR #14 comment 6550650750, host-deploy PR #3 comment 6550652453.
Producer: certify-manage c8760c71d5af297e2f592c891805fc51f803ea64. Box-control corrected client: 9111606eef306292d70fd4d941eeb73f48b33ff1.

## Selected broker UID is independently pinned

SelectedIssuerController now REQUIRES a non-root controller_uid; it always passes that pin into the exact box-control IssuerLifecycleClient, which checks kernel SO_PEERCRED before sending each request. A caller-provided JSON reply/socket cannot supply its own UID. Wrong-peer source regression uses a real AF_UNIX socket.

Unprivileged renewal timer needs nonsecret readable root-owned broker policy, not direct access to protected 0600 STATE. A fixed /etc/zog/host-deploy/certificate-issuer-broker-authority.json projection is 0444, opened through retained root-owned no-symlink ancestor descriptors; only host-install's protected owner may install it after independently validating the private consumer binding and native Host/installation/STATE/issuer. It pins exact box-control revision, local controller/caller/issuer UID, issuer GID, socket, policy, Host, installation, STATE volume, certificate SAN, storage/grant, Host policy digest, and SHA-256 of private consumer binding. The root/host-install owner MUST implement and native-test no-replacement install, revision/revocation/rollback fencing; this source-only consumer does NOT install or authenticate a broker authority by itself.

## Selected post-renew inspection before publication

After original one-shot renewal journal proves issuer success, the selected-broker path now requires a DIFFERENT retained controller inspect ID and the controller's authenticated inspect-result before either unchanged finalization or renewed stage. The exact saved runtime, program inspect, PID1 InvocationID, issuer UID/GID/storage/grant, host-policy digest, original renewal ID, leaf fingerprint/SAN/outcome and <=15-minute freshness are enforced by the existing trusted correlator and selected inspection journal. Unsatisfied, unknown, stale, foreign, unverified or missing proof never authorizes stage. A renewed result still requires separately selected stage and independent nginx/CA/SNI verification. Generic evaluator, direct issuer private state and reassigned original ID remain forbidden.

## Native remain NO-GO

The timer deliberately continues to reject controller_backend=selected-broker at _require_approved_native_inspection BEFORE socket access. Source tests and unprivileged synthetic fixtures do not grant native compiler/systemd/Certbot/Cloudflare, role issuer, credentials, DNS, HTTPS or timer activation. The root-owned broker projection has no native installation receipt yet. Box-control/root-control Regular must independently re-review exact PR #3 head/CI before any protected Work acceptance.
