# Graphical SSM send independent-owner source interface (held)

The existing PR18 gateway-local `graphics_operation_send_intent` is a useful one-operation no-replay sidecar **only while gateway storage survives**. It does not prevent coherent rollback of gateway storage. This separate source-only contract selects PR18's original frozen operation/request identity and constructs the exact protected owner claim expected by root-control draft PR #28, `66c5e2b1ec43a6d785bb140964af3cdcf927998a`.

Claims bind original request/operation/stage/ordinal, immutable source commit, separately authenticated selected source generation identity, target and lane, monthly pin, task catalogue and original remote request SHA. A signed operator approval may authorize only that exact combination; the independently protected root owner atomically retains the operation ID and send claim before an actual external SendCommand. A gateway rollback can never delete that protected history; after lost ACK or restart the owner offers **read-only no-retry observation**.

**No SSM activation:** This draft is deliberately not wired into `generic_pipeline.advance`; it has no selected independent signer/STATE/Host boot authority and cannot safely substitute an in-process Python object for protected native root-control. Work must install/prove a separate protected single-writer CAS/storage and signer, bind exact current Host/installation/STATE authority, and only then replace the local send decision with compulsory authenticated owner admission. The protected source-generation receipt must not be fabricated from a gateway local digest.

No production source repin, service, AWS interaction or native compiler submission is authorized by this source review.
