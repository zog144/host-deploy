## Root-selected broker projection revocation source contract (2026-11-01)

host-install's root-owner source planning uses the existing private managed
consumer binding, protected owner receipt/monotonic ledger and an independently
SHA-pinned operator approval to derive this module's original root-owned
0444 \`certificate-issuer-broker-authority.json\`. It cannot be selected by
the renewal timer or issuer JSON.

**Revocation consumer change:** a separately reviewed native root owner must
commit an irreversible root-owned 0444
\`/etc/zog/host-deploy/certificate-issuer-broker-revoked.json\` tombstone
under a higher independently authenticated owner-ledger revision and
separately approved revocation intent. This module refuses the existing
projection if **either** that final tombstone **or** the transient
\`.pending.certificate-issuer-broker-revoked.json\` exists. Both names are
checked via the retained no-symlink parent fd before and after its read.
An invalid, unreadable, symlink or partial tombstone is a denial, not
self-repair. Existing projection bytes stay immutable; remove neither old
projection nor tombstone to re-enable a revoked authority.

The current source changes do **not** install these files, open a broker,
activate renewal or clear \`_require_approved_native_inspection\`.
Actual root installation, independent provenance, verified root receipts,
rollback and crash/reboot acceptance are Work-only.
