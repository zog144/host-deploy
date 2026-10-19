# Authorized certify-manage renewal coordinator — source handoff

**Status:** SOURCE-ONLY. The library `zog.host_deploy.certificate_renewal.tick`
implements exact selected-program replay; it is **not wired into a running
systemd timer** and does not issue or renew a live certificate.

Producer selected-program contract:
- box-control `acbdf3896281d83d14a2c0cdba0267586b42f3d9`
- root-control `60e61aded8c4fdfdc689a6fa6f915aac24b0c3f1`
- certify-manage issuer at or after `caae72c3f2f6a79c860d4f05f0470f6ddd8eacda`.

## Owner API and state machine

A reviewed host-deploy runner calls `tick(journal_directory, controller,
policy_sha256=..., certificate_id=..., authorize_new=...,
issuer_observation=...)`. The existing BoxControl object is used, with
`issue_application_request_id()`, `request_application_launch(
"certify-manage", program_name="renew", request_id=...)`, and
`application_request_result(request_id)`. No other program is selected.

The standalone journal directory must be on durable storage, mode 0700,
owned by the trusted service identity (not station-access). Each first
request ID is fsynced **before** submitting to BoxControl. On lost
submission reply, reuse the saved ID; never invent a new one until the
previous request and issuer observation are verified. The controller's
own operation/result storage remains authoritative.

| Phase | Behaviour |
| --- | --- |
| issued | Retained selected request ID; may not yet have been submitted |
| submitted | Controller result pending/absent; replay exact ID and selector |
| awaiting-issuer | Controller says satisfied; wait for approved issuer observation |
| verified | Host owner verified current certificate health and exact result |
| blocked | Failed request or malformed evidence; manual review, no retry |

The scheduler's `authorize_new=True` is a **separate owner policy**
decision; the library never selects a cadence or runs a background loop.
Only the reviewed service with matching prepared controller identities may
set it. Failed, uncertain or inconclusive results leave an existing request
fenced. A successful controller result alone does **not** mean a valid
certificate, a new key, a loaded nginx generation, or HTTPS readiness.

The `issuer_observation` is deliberately an injected **trusted host-owner
capability**; it is not HTTP JSON or a UI POST. It must authenticate the
issuer UID, controller-selected runtime/request ID, prepared storage/policy
fingerprint and exact cert lineage, then produce the fixed
`zog-certify-renewal-observation-v1` redacted object. The object must
bind request_id, certificate_id, policy_sha256, health=valid,
operation=renew, outcome=renewed/unchanged, and leaf fingerprint.
A plain untrusted caller-provided object is **not** acceptable production
evidence. That observation capability remains to be built with
box-control/root-control and certify-manage. Without it the state stops at
`awaiting-issuer`, deliberately.

After a verified **renewed** fingerprint, host-deploy **must wait for
a separately approved controller stage selected-program grant** before
requesting the issuer's private `stage` step and authorized TLS delivery.
The currently accepted selected-program scope permits issue, renew and
inspect only. Never bypass it using an arbitrary command, shell wrapper,
or direct access to private issuer data.
An **unchanged** valid result needs no new publication. Controller request
completion never bypasses the existing cert-delivery trust/rollback gates.

## Systemd/ACME acceptance: still required

Owner deployment must package this coordinator with the approved immutable
view, a non-root service, protected local binding and a reviewed schedule
selected by the administrator (no default schedule is activated here).
Evaluation of pending selected requests must be explicitly integrated
with the existing box-control evaluator and root-control socket. Repeated
timer executions must not overlap (single-owner lock), and must preserve
the whole project/journal volume across restart/reboot.

Perform **native systemd** acceptance on an isolated host using real
selected `renew`, transient unit identity/UID/GID/mount/service timeouts,
failure/lost reply/reboot and request replay. Exercise **actual Certbot**
against an operator-authorized staging domain, with a valid HTTP-01 or
DNS-01 setup, and compare persisted renewal config, ACME account, SAN,
leaf/private key, changed/unchanged outcomes, staged candidate,
nginx reload/rollback and external TLS SNI. Do not substitute GitHub CI,
subprocess stubs or `certbot --version` for those tests. No production
hostname, DNS token, or cert secret is included in this repository.

**Current block:** there is no trusted host-owner issuer observation
transport bound to the exact selected request, and no native scheduler
service has been deployed. Certificate renewal remains production NO-GO.


## 2026-10-15: Root-owned timer adapter and freshness gate

The independent \`zog.host_deploy.certificate_renewal_timer\` module is now
the narrow, **source-only** adapter between a root-approved timing policy,
the existing \`certificate_renewal.tick\` ledger and the co-resident issuer's
real protected \`CertificateManager\` status.

The new coordinator journal records \`issued_at\` with the exact saved
controller request ID and refuses a missing controller result if that
request is older than **24 hours**, instead of replaying after its
authoritative retention may have expired. It also enforces a minimum
24–720-hour gap between verified attempts and archives each previously
verified request before issuing a new ID. An old journal without the
required issued timestamp cannot be silently promoted; Work must
review/migrate it explicitly rather than guessing freshness.

The timer adapter reads an immutable root-owned policy, validates the
exact project/issuer identity, uses the approved interpreter and
root-control socket, and creates a BoxControl object with a pinned
published generation. It inspects the actual Certbot lineage and saved
issuer result through certify-manage, verifies authorization, SAN,
ACME account, key match and \`outcome\` using producer-owned code, and
permits renewal only when the certificate is within the configured
due window. It attaches issuer evidence only when the Certbot operation
timestamp is not earlier than the retained request intent, and not later
than the controller's terminal result beyond a two-minute allowance.

**Topology restriction:** This v1 adapter requires the controller project
owner and the dedicated certificate issuer to be the **same reviewed
unprivileged UID**, with private issuer state already owned by that UID.
This must never be achieved by relaxing an existing isolated application's
state ownership. If production uses different UIDs, the timer is
**blocked**, pending a separately authenticated issuer observation API.
There is no general root shell proxy or grant of cert secrets to station.

### Non-deployable root policy example

\`\`\`json
{
  "schema": "zog-host-deploy-cert-renewal-timer-v1",
  "application": "certify-manage",
  "program": "renew",
  "certificate_id": "station-web",
  "policy_sha256": "<verified-issuer-policy-sha256-64-hex>",
  "project_root": "/home/<approved-issuer-and-controller>/certificate-project",
  "generation": "<verified-image-generation-64-hex>",
  "controller_user": "<approved-issuer-and-controller>",
  "issuer_user": "<approved-issuer-and-controller>",
  "root_control_socket": "/run/zog-station-production/control.sock",
  "python_executable": "/usr/bin/python3.12",
  "journal_directory": "/home/<approved-issuer-and-controller>/certificate-project/state/renewal",
  "issuer_policy_file": "/etc/zog/certify-manage/policy.json",
  "issuer_state": "/var/lib/zog-certify-manage",
  "renew_when_days_remaining": 30,
  "minimum_interval_hours": 24,
  "evaluate_queued_request": true,
  "publication_policy_file": null,
  "issuer_observer_policy_file": null,
  "controller_backend": "local",
  "issuer_lifecycle_socket": null
}
\`\`\`

The placeholder fields and socket path must be independently checked on
the target host. **Do not deploy this sample.** The JSON file must be
root-owned, non-symlinked and not group/world-writable, at
\`/etc/zog/certificate-renewal-<user>.json\`. The private journal
directory must be pre-created on durable storage with ownership of the
approved exact service UID and mode 0700. The CLI cannot create or
reinterpret that directory and never takes a program name or certificate
hostname from an untrusted request.

Packaged inert systemd templates:

- \`certificate-renewal@.service\`: one bounded timer tick, \`User=%i\`,
  no private key in argv/logs, 90-second timeout.
- \`certificate-renewal@.timer\`: hourly *observation/reconciliation*
  with jitter and persistence, **not hourly Certbot issuance**. Every new
  selected renew is subject to the issuer due check, controller singleton
  admission and 24-hour minimum interval.

Before enabling either unit, Work must confirm the exact service
identity and controller socket, actor permissions on the project and
issuer state, native root-control/single-program systemd acceptance,
a separately running controller evaluator, real Certbot
issued/renewed/unchanged results, crash/lost-reply/48-hour history and
reboot recovery, and separate authorized staging/consumer publication.
The timer is **not enabled by source-level success**. Even \`verified\`
from the issuer does **not** mean nginx is loaded, TLS is browser-trusted,
or production port 443 is ready. Those are separate host-deploy delivery
and Work acceptance gates.


### Public issuer evidence and outstanding stage boundary

At certify-manage revision \`94eacef44ca03d4e079047e440c812e04f8fca0a\`
or a separately reviewed later revision, \`CertificateManager.inspect()\`
exports bounded, secret-free \`policy_sha256\`, \`operation_updated_at\`,
\`operation\`, \`outcome\`, certificate identity, X.509 leaf fingerprint,
validity and health. The timer adapter consumes **these public fields**
rather than calling the issuer's private \`_read()\` record accessor.
The producer verifies the actual Certbot lineage, private/public key pair,
ACME account and persisted renewal authority under the issuer's dedicated
execution UID. The timer then requires a new operation completion time
after its exact retained controller request began.

This **co-resident, same-UID** source path does not solve the independent
issuer identity on a differently owned project. The box-control/root-control
owners must still deliver a reviewed authenticated observation bridge
binding the selected request, actual prepared application storage/grant
and recorded runtime. In that topology the source timer stays disabled.

For a genuinely **changed/renewed** leaf, the separately authorized
\`stage\` program and host-deploy certificate-delivery bridge remain next
steps; a verified **unchanged** operation must not force a new certificate
publication. The owner must still prove configured nginx unit identity,
candidate chain trust, SNI/leaf match and safe rollback. No timer service
was enabled and no ACME request was sent by this implementation.


### Controller evaluator wiring and selected cadence

The **proposed isolated-host cadence** is hourly reconciliation with
`RandomizedDelaySec=15min`, a 30-day certificate remaining-lifetime
trigger and **at least 24 hours between successful selected renew
requests**. Hourly polling is *not hourly issuance*. The timer remains
**disabled** until host-deploy Work approves this configuration against
the actual ACME issuer, rate limits and immutable deployed image.

The protected timer policy must now include
`"evaluate_queued_request": true`. A scheduler tick that finds an exact
`submitted` request invokes **one bounded** `BoxControl.evaluate()`
under the already bound owner project and existing controller mutation
lock, then rereads the authoritative result without issuing another ID.
An evaluator failure leaves the original ID durable and returns a blocked
unit outcome. This is a project-wide controller evaluator, not an
unrestricted process executor: Work must review all applications included
in that project before authorizing it. A separate evaluator instance may
also operate under the same controller lock, but it is **not** permission
to start another certificate writer.

The packaged unit uses **/usr/bin/python3.12** explicitly; the timer
policy now accepts only that exact path to prevent the policy claiming
another interpreter than the actual native service command. Work must
verify this interpreter and every pinned dependency exist on the
isolated host, and review the unit's `ReadWritePaths=%h` scope against
actual durable project/mount identities before enabling the template.
Do not use the template to reassign or chmod the certificate issuer's
private state.

`systemd-analyze verify` is a useful **static** gate; it does not
exercise the root-control socket, transient selected program, Certbot,
private mount or ACME. On an environment without /usr/bin/python3.12,
static verification correctly reports the missing executable. A live
native acceptance requires the reviewed host-deploy Work connection.


### Mocked renewal → stage → owner nginx-delivery integration

A separately reviewed **root-owned** publication authorization is now
supported as an optional timer binding. With `"publication_policy_file": null`,
a changed renewal remains verified but **cannot automatically stage or
publish**. The timer will refuse a later new renewal until that changed
fingerprint has passed the separate consumer acceptance or an explicit
operator recovery decision. Nothing silently makes the issuer a nginx writer.

When the root policy points to an administrator-controlled authorization,
the independent `zog.host_deploy.certificate_renewal_publication.advance`
coordinator performs the following **bounded selected operations**:

1. Confirm the authoritative `renewal.json` is `verified`, has the
   exact owner policy/certificate identity and outcome `renewed`.
   Outcome `unchanged` produces `unchanged-no-delivery` without stage,
   private-key movement or nginx reload.
2. Require exact `stage_program=stage`, `approved_stage=true`, fixed
   issuer policy/state, consumer service ID, sorted SAN names and bridge
   socket from a separate root-controlled policy. No browser/CLI argument
   selects a filesystem path, program name or nginx service. The root-control
   stage host-binding grant is an **additional** mandatory capability,
   independently enforced by box-control/root-control; this JSON approval
   alone is not sufficient production authorization.
3. Persist `renewal-publication.json` with the original renewal ID,
   fingerprint and a newly controller-issued **stage** request ID before
   submitting selected `program_name=stage`. Recover lost stage responses
   with the *same* ID, not a second stage; a missing controller result
   older than 24 hours blocks rather than replaying stale evidence.
4. Wait for the exact selected stage result to become `satisfied`.
   Under the issuer UID, inspect the private immutable staged receipt by
   the issuer's protected file reader and require exact policy, hostname,
   fingerprint and receipt digests. This receipt is **not** yet proof
   of nginx readiness; the root-owned bridge rechecks real PEM X.509,
   key pairing and hostname identities before publication.
5. Atomically record `delivery-uncertain` **before** contacting the
   SO_PEERCRED-authenticated certificate-delivery Unix socket. Submit only
   the fixed certificate/service IDs and exact leaf fingerprint. Accept only
   the bridge's matching `browser-verified` result, which requires nginx
   candidate configuration testing, authorized reload, CA/SNI/fingerprint
   probe. If a reply is lost, **never automatically replay nginx delivery**;
   retain the uncertain journal for operator inspection/recovery.
6. Retain `complete` evidence and archive any prior completed publication
   when a distinct later renewed request is accepted. Refuse policy drift,
   untrusted receipt, failed controller stage, uncertain delivery or a
   later renewal overtaking unresolved HTTPS publication.

The root-controlled publication policy has exact schema:

```json
{
  "schema": "zog-host-deploy-renewal-publication-policy-v1",
  "certificate_id": "station-web",
  "policy_sha256": "<actual-issuer-policy-sha256>",
  "service_id": "candidate-nginx",
  "issuer_state": "/var/lib/zog-certify-manage",
  "issuer_policy_file": "/etc/zog/certify-manage/policy.json",
  "socket_path": "/run/host-deploy-cert-delivery/bridge.sock",
  "stage_program": "stage",
  "approved_stage": true,
  "hostnames": ["candidate.example.org"]
}
```

**This is a non-deployable example.** Work must obtain actual reviewed
issuer and consumer IDs, exact DNS names, trust, approved root-control
stage grant and network locality. The default production disposition remains
NO-GO. There is no issuer→consumer cross-host transport in this workflow.

The focused tests run with fake controller responses, private stage receipts
and owner socket responses. They explicitly exercise no-op, changed,
request-ID recovery, wrong stage program/result, changed owner policy,
failed receipt, single accepted TLS publication and uncertain/missing delivery
response. They do **not** prove live Certbot issuance, selected root-control
stage enforcement, a real nginx reload or browser CA trust. host-deploy Work
must still conduct those isolated systemd/ACME/HTTPS acceptance gates before
enabling the native timer or modifying a production listener.


### Combined stage and nginx-delivery timeouts

The publication adapter also evaluates a controller request already in
`stage-pending` once per timer iteration; it never issues another stage ID.
The isolated candidate client waits up to 150 seconds for the root-owned
nginx validation/reload/TLS probe response, and the combined oneshot uses
`TimeoutStartSec=300s`. A systemd kill or transport timeout after an
outbound delivery attempt leaves `delivery-uncertain` durable; operators
must inspect the root bridge generation and journal and explicitly reconcile.
No scheduled retry can re-send an uncertain nginx mutation. Root-owned
certificate service and selected controller transient units retain their
own independent timeouts and privilege boundaries.


### Authenticated issuer observer — integration boundary (October 15)

Host-deploy adds the read-only
\`zog.host_deploy.certificate_issuer_observer.observe_request\` adapter
for the existing box-control
\`IssuerObserverClient(<root-approved-socket>).observe_issuer_request(<exact-ID>)\`.
The only socket request carries the saved **original renewal request ID**.
No source path, policy override, certificate data, command or service unit
may be supplied in the request.

An independent root-owned observer policy
(\`zog-host-deploy-issuer-observer-policy-v1\`) pins the exact Unix socket,
authorized *host-deploy caller UID*, certificate ID and canonical policy
SHA-256, administrator-owned \`host_policy_digest\`,
persistent \`storage_id\`, grant ID and actual issuer UID/GID.
The adapter rejects foreign controller results, wrong runtime identities,
other programs, missing/stale journal times, changed fingerprints, grant
mismatches and any observer claim that TLS is ready.

The optional renewal timer policy field
\`issuer_observer_policy_file\` accepts a root-owned policy path (or
\`null\` for the original, **same-UID-only** local inspection mode).
When configured, the timer requires \`journal-ready\` from this
authenticated observer for the exact saved request **and** separately
requires the issuer's \`inspect()\` certificate/lineage proof to agree
on the certificate fingerprint, policy and operation outcome before
marking the renewal \`verified\`. Any \`ongoing\`, \`stale\` or
\`uncertain\` trusted response leaves the existing request
\`awaiting-issuer\` and does not stage or reload nginx.

The authenticated observer intentionally authorizes a **different
host-deploy UID**. These identities may not be merged or made
world-readable to force connectivity. The selected-program client
and issuer-UID X.509 inspection consumer are now integrated in source
(see the October 16 contract below); native service and mount acceptance
remains outstanding. A successful trusted \`journal-ready\` response cannot
be silently converted into \`health=valid\` or \`browser-verified\`.

Narrow upstream signed-token compatibility fixes:
\`box-control@7396fd3777d95fc554df3f24996ffa954bb8ee33\`
and \`root-control@2a716d737afb030f74619713a075a52faa51f1eb\`
accept the producer's complete bounded (up to 200 characters)
controller request IDs. These sources must be pinned and tested
together on the isolated host. No daemon or certificate authority
service was restarted by the source change.

A root-controlled example observer policy (identities and socket
are placeholders, **not deployable**):

\`\`\`json
{
  "schema": "zog-host-deploy-issuer-observer-policy-v1",
  "socket_path": "/run/zog-issuer-observer/observation.sock",
  "caller_uid": 23001,
  "certificate_id": "station-web",
  "policy_sha256": "<canonical-64-hex-certify-policy-hash>",
  "host_policy_digest": "sha256:<root-host-policy-byte-digest>",
  "storage_id": "<32-hex-persistent-storage>",
  "grant_id": "<32-hex-issuer-identity-grant>",
  "issuer_uid": 24001,
  "issuer_gid": 24002
}
\`\`\`

Only issue this policy after Work has verified both the controller's
retained original request/runtime and the protected issuer policy
host-directory grant. Its parent path must be root-owned and never
group/world-writable. The observer service must run under the
existing controller owner, authenticate the separate exact caller UID
with \`SO_PEERCRED\`, and expose no privileged root-control socket to
host-deploy. This policy is **not an ACL or grant by itself**.


### Authenticated selected-program lifecycle broker (October 15)

The controller owners delivered \`zog.box_control.issuer_lifecycle_broker\`
and \`IssuerLifecycleClient\` at box-control \`124db5cb30dd23da72f7646f7f254b173e325209\`.
Host-deploy now has \`certificate_issuer_lifecycle.SelectedIssuerController\`
to translate the **direct selected** \`renew\` and \`stage\` broker API into
the existing saved request-id renewal/publication journals. The adapter:

- passes only the exact \`certify-manage\` application, reviewed program
  \`renew\` or \`stage\`, and original controller-issued request ID;
- rejects unknown, mismatched or foreign broker results, and binds any
  resulting runtime identity to the trusted separate issuer observation;
- does **not** expose, fabricate or invoke \`BoxControl.evaluate()\`;
- treats loss of a start reply as uncertain, allowing recovery only under
  the original durable request-ID window;
- retains selected \`stage\` request ID, receipt and uncertain TLS delivery
  exactly as in the existing publication journal.

The new root-controlled timer policy fields are
\`"controller_backend": "local"\` with
\`"issuer_lifecycle_socket": null\` for the legacy same-UID
controller mode; or \`"controller_backend": "selected-broker"\` with
an exact root-controlled AF_UNIX socket path,
\`"root_control_socket": null\`,
\`"evaluate_queued_request": false\`, and an exact mandatory
\`issuer_observer_policy_file\`. The host-deploy service user must be the
reviewed **caller UID**, not the trusted controller project owner.
The selected broker runs as that distinct controller owner and provides
no direct root-control daemon socket to host-deploy.

**Updated October 16:** The authenticated split-UID inspection consumer
is now implemented in source. The selected-broker timer does **not**
read protected Certbot state directly. Instead, it requires separate
controller-request provenance and issuer-UID certificate inspection before
accepting a renewed result. **Live native systemd/socket/mount acceptance
remains a hard prerequisite** to enabling unattended certificate renewal.

The Cloudflare station projection is **not** authored by the timer or
derived from a successful socket request. It is already implemented in
root-control's root-only \`issuer_station_transfer\` module. The host
authority must first authenticate the signed station assignment and
persist its canonical root-owned \`*.approval.json\`. Root then runs
\`publish-projection\` with a verified nonsecret JSON on an inherited FD,
using the pre-approved vault-reader UID/GID; after reviewing
\`*.station-reader.json\` ownership as 0440 root:vault-reader-group,
\`*.reader-peer.json\` as 0600 root:root, and the fixed 0600
\`/run/zog/issuer-cloudflare-reader.sock\`, root alone calls \`transfer\`.
That invokes the original FD-only issuer installer. Host-deploy must never
pass Cloudflare token bytes in an argv, environment, source patch or journal.

**No native systemd, ACME DNS-01, transfer, nginx reload, timer enablement or
production credential provisioning was performed in this source pass.**


## October 16 — authenticated issuer-UID X.509 inspection consumed

The source integration now consumes
\`zog.certify_manage.inspection_client.IssuerInspectionClient\` from
certify-manage [\`17cb68889207c769941d212e7126fd580f5f4446\`].
This supersedes the earlier **source gap** for split-UID renewal inspection,
but the issuer's socket-activated process and systemd/mount security are still
**unaccepted on a live host**.

### Owner-bound inspection policy

For \`controller_backend="selected-broker"\`, the timer's independently
root-approved policy must contain
\`"issuer_inspection_policy_file": "/etc/zog/certificate-issuer-inspection.json"\`
as well as the existing mandatory
\`issuer_observer_policy_file\`. The exact new root-owned policy schema is:

\`\`\`json
{
  "schema": "zog-host-deploy-issuer-inspection-policy-v1",
  "socket_path": "/run/zog/certify-inspect.sock",
  "issuer_uid": 24001,
  "caller_uid": 23001,
  "certificate_id": "station-web",
  "policy_sha256": "<64 lowercase hex of actual approved issuer policy>",
  "hostnames": ["candidate.example.org"]
}
\`\`\`

This is a **non-deployable** example. Work must bind the real numeric
issuer UID, host-deploy caller UID, approved certificate ID, sorted exact
SAN/hostname list, and policy digest to the independently authorized
host and installed immutable application/grant. The socket's parent and
policy ancestors must not be symlinks or writable by a non-root owner.
The inspector also requires a separately reviewed controller-owned
service with its original protected issuer state and policy view.
The root-control privileged socket and issuer private directory must
**not** be opened to host-deploy.

A selected-broker timer now checks that its process UID matches both the
independent inspection **caller UID** and the request-bound observer
caller UID, while the inspector issuer UID matches the authenticated
observer's issuer UID and the actual configured issuer Unix identity.
The host-deploy service UID must differ from the controller owner,
issuer identity and root.

### Evidence sequence and exact equality

1. **Before renewal:** host-deploy contacts the pinned issuer inspection
   socket using the existing certify-manage \`IssuerInspectionClient\`.
   The client authenticates server \`SO_PEERCRED\`, sends a fresh random
   nonce, verifies exact fields and bounded freshness; host-deploy also
   checks root-approved SANs, certificate ID and policy SHA-256, valid
   X.509 dates, positive \`issuer_verified\`, fingerprint, and
   \`tls_ready=false\`. Only this current verified certificate's
   \`days_remaining\` can determine whether renewal is due.
2. **After selected renewal:** host-deploy first retrieves the
   independently authenticated controller request-bound observer result
   for the **original retained request ID**. It must be \`journal-ready\`
   for the exact selected \`renew\` runtime, issuer grant/storage/policy,
   and completed journal; the journal must postdate the issued request.
3. **Independent re-inspection:** host-deploy requests a **new**
   issuer-UID inspection (new nonce), and requires identical
   \`certificate_id\`, \`policy_sha256\`, leaf fingerprint, outcome, and
   **timezone-normalized exact \`operation_updated_at\` equality** with
   the trusted journal observation. The certificate result must be valid,
   issuer-verified, and its operation must be \`renew\`, with outcome
   \`renewed\` or \`unchanged\`. No caller-supplied request ID enters
   the inspection socket.
4. **Publication:** for \`unchanged\`, no \`stage\` or nginx reload.
   For \`renewed\`, selected \`stage\` and the independently authenticated
   root-owned nginx delivery bridge remain separate gates. If a later
   timer invocation attempts staging an already-verified changed renewal,
   host-deploy rechecks the same original request's independent observation
   and current issuer inspection **again**, refusing changed or
   missing evidence before delivery.

Any stale, missing, untrusted, recovered-unverified, changed-policy,
wrong-UID, wrong-SAN, wrong-fingerprint, wrong-outcome, wrong journal
time, invalid certificate or inconsistent controller request **blocks
new issuance or staging**. The issuer service's positive result is
local certificate validity only, never proof of active nginx,
browser trust, revocation status or production HTTPS readiness.

### Native acceptance remains Work-owned

Only the **source consumer** and mocked tests are implemented here.
The separate issuer inspector must be mounted/activated under its
original protected UID through approved controller/root-control
composition, with correct immutable software view, policy/STATE grant,
read-only systemd socket activation, genuine peer DAC + SO_PEERCRED
allow/deny, original issuer lock, policy revocation behavior and no
secret output. host-deploy Work must perform real systemd, Certbot/ACME,
selected \`renew\`/\`stage\`, isolated nginx -c, CA/SNI/leaf TLS,
rollback, reboot and lost-reply acceptance before enabling the timer.


## October 16 runtime ownership review — selected one-shot inspect

**Updated controller decision:** [ISSUER-INSPECTOR-RUNTIME-REVIEW-2026-10-16](https://github.com/zog144/box-control/blob/unstable/docs/box-control/ISSUER-INSPECTOR-RUNTIME-REVIEW-2026-10-16.md)
rejects an unmanaged persistent systemd instance of the issuer
inspection AF_UNIX service. Neither host-deploy's earlier source-only
socket integration nor its accompanying mocks authorizes installation of
that unit. Native \`controller_backend=selected-broker\` activation is
**explicitly blocked** in \`certificate_renewal_timer.main\` with
\`selected-inspection-runtime-not-approved\` until a concrete reviewed
selected-inspect result API exists.

The preferred controller-owned route is short-lived
\`certify-manage/inspect\`, already declared in the issuer application
but **not yet allowed by the fixed lifecycle broker**. No shell fallback,
manual \`systemd-run\`, host-mounted issuer data or general \`evaluate()\`
is permitted.

The new source-only
\`zog.host_deploy.certificate_selected_inspection\` coordinator preserves
an independent inspection request ID in \`selected-inspection.json\`
**before** attempting the exact selected \`inspect\` launch. Its separate
identifier must never replace the original renewal request ID. It
rejects inspect while renewal is pending, blocks missing controller
evidence beyond the 24-hour retention bound, and will not mark the
inspection \`verified\` merely because systemd reports a successful
process exit. Without an authentic invocation-scoped result reader it
remains \`awaiting-evidence\`.

The proposed **consumer-only** result shape
\`zog-controller-selected-inspect-evidence-v1\` includes distinct
inspection request ID, runtime and systemd invocation identities,
immutable issuer storage/grant/UID/GID, certificate/SAN/policy scope,
actual leaf fingerprint, X.509 validity/expiry, operation outcome and
timestamp, plus \`tls_ready=false\`. This is **not an implemented or
approved producer contract**. box-control/root-control must agree on
the exact reader envelope and authenticate its provenance from the
saved selected inspect request, exact successful transient unit and one
strictly bounded structured result from that invocation (e.g., a
journald cursor+invocation barrier), not general logs or user-provided
JSON. Certify-manage must provide a finite, redacted one-shot output
whose correctness does not follow only from exit code zero.

The controller broker must extend its fixed program selector with
**only** \`inspect\`, retaining \`renew\`/\`stage\` admission, the single
issuer mutation/inspection interlock and a distinct durable request ID.
Results used to inspect *after* renewal must also match the
independent original request-bound \`journal-ready\` observation on
certificate ID, SANs, policy SHA-256, leaf fingerprint, outcome and
timezone-normalized issuer operation completion time. An inspection
request ID never stands in for the original renewal ID.

For ongoing due-date checks, inspection cadence must be bounded:
each finite inspect is a genuine Zog runtime/history entry, not a
cheap hourly RPC. The source proposal reuses a recent verified
inspection for at most 15 minutes, then fences repeated inspection
until 24 hours have passed, except that a distinct, already-verified
original renewal can justify a fresh post-renew inspection.
Controller and Work owners must verify that retention of both
inspection and renewal evidence cannot be pruned under the 25-entry
runtime history/48-hour request window.

Mock tests in \`test_certificate_selected_inspection.py\` verify
request-ID fsync before start, no invented second ID after lost reply,
separate renew/inspect identities, no inspect during uncertain renewal,
no promotion from successful process exit, strict proposal-envelope
matching, and failure on stale, foreign or malformed evidence.
These do not exercise a real root-control journal result reader.

**Acceptance remains NO-GO** until certify-manage, box-control and
root-control publish their reviewed producer interfaces and host-deploy
Work proves native transient systemd, issuer UID/mount ownership,
Certbot/ACME and HTTPS delivery/rollback with isolated credentials.
The discontinued unmanaged socket service must not be installed.


### Selected inspect producer alignment (certify-manage October 16)

Certify-manage's source at
\`43aa3db068389ae9d5cc424bda916ed0daa86844\`
now implements [selected-inspect-result-v1](https://github.com/zog144/certify-manage/blob/unstable/docs/selected-inspect-result-v1.md).
The one-shot \`certify-manage inspect\` process emits exactly one
ASCII/UTF-8 stdout record with marker
\`ZOG_CERTIFY_INSPECT_RESULT_V1 \`, a compact JSON object whose schema is
\`zog-certify-inspection-result-v1\`, and a 4096-byte bound. It does not
authenticate a controller request or invocation and may exit successfully
with \`issuer_verified=false\`; **exit status never substitutes for the
validated record**.

The host-deploy consumer proposal now carries that exact issuer object
as \`issuer_result\` nested inside a separately authenticated
*proposed controller envelope*. The enclosing
\`zog-controller-selected-inspect-evidence-v1\` schema is **not**
published by box-control/root-control yet. It must be revised to their
final review rather than inferred from untrusted stdout. The issuer
object's strict field set is:
\`schema\`, \`certificate_id\`, \`hostnames\`, \`policy_sha256\`,
\`health\`, \`certificate_fingerprint_sha256\`, \`valid_from\`,
\`expires_at\`, \`days_remaining\`, \`operation\`, \`outcome\`,
\`operation_updated_at\`, \`issuer_verified\`, \`observed_at\`,
\`tls_ready\`. The controller must derive the exact inspect request,
runtime, invocation, grant, storage and issuer UID/GID *outside* that
issuer object.

For a post-renew inspect the consumer also requires an independently
authenticated **original** renew \`journal-ready\` observation and matches
its separate renewal request ID, policy/certificate, grant/storage,
fingerprint, outcome and **exact timezone-normalized issuer journal
timestamp**. Neither the controller's inspect request ID nor
successful systemd exit establishes the original renewal's result.

Current source tests only mock this future trusted reader and controller.
No host-deploy production code parses raw journald streams or accepts
untrusted status JSON. The new \`certificate_selected_inspection.tick\`
has no CLI and is not invoked by the native timer. The native selected
broker guard remains active until the controller-owned reader exists,
is tested, and its final envelope adopted.
