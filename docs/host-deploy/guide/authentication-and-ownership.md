# Authentication and ownership

## Four independent questions

An operation on a Zog compiler host requires separate answers to four questions: **who requested it**, **whether that principal is authorized**, **which existing host/workspace owns it**, and **what exact side effect is being committed**. An authenticated TLS connection or correct JSON schema is necessary but never a replacement for the other checks.

GitHub-origin requests must validate the trusted event actor and narrowly authorized workflow before gaining temporary AWS capabilities. Request body fields, issue text and `origin.trigger_actor` are not authority. The closed [gateway protocol](../GATEWAY-PROTOCOL.md) limits which operation/parameters an origin may express.

## Durable owner and controller handoff

The gateway consumer admits requests only for its exact owned `workspace_id`. A normal Work-to-gateway transfer uses `checkpoint-export --handoff` / `claim-handoff`; the old controller retires before the new owner is eligible. A plain checkpoint backup must not be restored into two concurrent writers.

An explicitly approved adoption is a recovery exception only when the historical checkpoint cannot be recovered. It requires authenticated AWS inventory, preserved identity, writer stand-down evidence and a compare-and-created remote marker. The owner epoch is verified again before remote SSM mutation. Ownership failure remains blocking even if the EC2 instance responds. For the full decision tree consult [adoption](../GATEWAY-ADOPTION.md) and [controller handoff](../RECOVERY.md).

## Credentials and service principals

Temporary AWS SDK credentials and assumed roles follow provider lifetime and IAM restrictions; a development credentials file is not part of published artifacts. The [development authentication notes](../AUTHENTICATION.md) discuss a possible future approval service explicitly **not implemented** there. Do not present that proposal as the active Zog access method.

The [compiler owner RPC](compiler-owner-rpc.md) isolates administrator-configured server TLS identity from exact allowlisted client-certificate scopes. Observer principals may request only owner-ledger facts; mutation principals must be separately reviewed. An accepted station-access user session does not imply cloud/SSM authority.

## Evidence and response privacy

Receipts and statuses should expose bounded identities, phase and evidence availability rather than AWS responses, private paths, archive credentials, source bytes or keys. A host-deploy gateway result represents evidence from the owner ledger or a specific observed SSM/image-build result; it does **not** imply general live EC2 health.

### References

- [Authorization and protocol boundary](../GATEWAY-PROTOCOL.md)
- [Durable workspace ownership](../GATEWAY-CONSUMER.md)
- [Adopted owner and epoch](../GATEWAY-ADOPTION.md)
- [Compiler RPC scope contract](compiler-owner-rpc.md)
- [Credential handling and unimplemented approval design](../AUTHENTICATION.md)
