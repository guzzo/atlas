# Threat model

## Security claims of this POC

A receiving organization can check that a pinned organization root bound an agent and runtime key, delegated a bounded policy signer, and issued a short-lived capability for this exact request. It can check current revocation and policy state, optionally verify the hidden-limit predicate, apply its own acceptance rules and consume the nonce once. These claims depend on the trust assumptions below; they are not runtime attestation or a production security certification.

## Trust assumptions and boundaries

| Party/component                 | Trusted for                                                                              | Not established by its signature/proof                                          |
| ------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Acme root administrator         | Acme identities, delegation, policy commitments, revocation                              | Globex acceptance, source-data truth, legal/commercial permission               |
| Acme policy signer and worker   | Honest Cedar evaluation and issuance under Acme's chosen policy; witness confidentiality | Cumulative budget safety; arbitrary Cedar semantics inside ZK                   |
| Runtime key holder              | Possession of this private key                                                           | Identity of a particular model, code integrity, owner intent on every tool call |
| Passport registry               | Accurate, current public key/revocation/policy state                                     | New Acme authority: Acme private signing keys are absent from Passport          |
| Globex verifier/proof worker    | Correct verification of pinned encodings/program and live state                          | Delivery, settlement or truth of third-party attestations                       |
| Globex resource API/database    | Counterparty rules, atomic nonce consumption, truthful execution receipt                 | Exactly-once side effects outside its local database                            |
| Local developer and Docker host | File and container isolation, clock, networking and service binaries                     | Security against a malicious host administrator                                 |

Public roots are distributed through the local bootstrap's trust file, not discovered and automatically trusted from the registry. Real organizations need an authenticated root-distribution process. The registry's independent signing key authenticates live state, not organizational authorization.

The same local developer account owns both organizations' fixtures. A Codex instance with unrestricted shell access under that account can read local administrator files; the runtime-only MCP mount does not sandbox the rest of Codex. For hostile-agent testing, run each runtime in an OS/container boundary with no administrator checkout, restricted filesystem/network access, and no Docker socket. Counterparty privacy concerns the protocol-visible evidence, not protection from the machine's owner.

## Covered adversarial cases

- Altering request body, amount, recipient, resource, policy version, envelope kind/key/algorithm or signature.
- Presenting another issuer, another audience, an out-of-scope delegation, expired or future-dated authority, or excessive capability lifetime.
- Reusing a nonce, including concurrent submissions. Globex uses PostgreSQL rather than a process-local replay map.
- Using revoked runtime/delegation/policy/signer/root state or replacing an active policy commitment.
- Replaying a captured signed registry bundle; a new random challenge and five-second bound are enforced.
- Registry outage or invalid/missing evidence: fail closed.
- Supplying missing/forged proofs, moving a proof to another capability, selecting an unapproved proof program or using an over-limit witness.
- Trying an administrative endpoint with no credential or signing an administrator mutation with a runtime key.
- Re-enrolling a revoked key ID to clear its revocation; identifiers and signed records are immutable.
- Returning a valid Acme capability for an action Globex rejects under its own rules.

Some cases are covered by live Compose acceptance; others are in the verifier unit suite. The handoff distinguishes those from untested production claims.

## Residual risks and deliberate limits

1. **Local keys and administration.** Private keys live in ignored mode-0600 files, not HSMs. Administrative bearer credentials are random and organization-scoped but stored in plaintext local files. There is no operator SSO, fine-grained user RBAC, credential recovery or customer KMS integration.
2. **Trusted online state.** A malicious registry can suppress revocation or policy updates and sign misleading fresh state. It cannot invent signatures from an uncompromised Acme root/policy key. Offline verification and independently authenticated state transparency are not implemented.
3. **Bounded in-flight staleness.** Already verified operations can execute within the remaining five-second state window. This is intentional; zero-lag revocation would require stronger transaction/state coupling. Clock synchronization is assumed.
4. **Development transport.** HTTP inside the local Compose network and loopback is not TLS. An observer can race a captured fully signed request and receive the simulated resource first. Remote deployments require TLS, authenticated service connections and origin/identity binding appropriate to the resource.
5. **Proof composition.** The Bulletproofs library is established; the surrounding commitment/signature/request binding is new and unaudited. Proofs reveal inequality results, permit threshold inference under repeated queries and provide no assurance about hidden arbitrary programs.
6. **No spending ledger.** Only per-transaction limits are checked. Concurrent individually allowed purchases can exceed any imagined cumulative budget. There is no reservation or settlement system.
7. **Availability and growth.** There is no production rate limiting, quotas, pagination beyond bounded recent views, state garbage collection, cluster failover, high-volume registry benchmark, distributed-clock testing or circuit breaker policy. Invalid request auditing can consume storage. Registry trust bundles currently contain all records for an organization and will eventually reach response limits.
8. **Audit trust.** Receipts are signed and backed by transactional rows/outbox entries, but database owners can remove them. There is no external immutable audit store, delivery worker, acknowledgment protocol, transparency log or retention policy. Malformed unidentifiable requests are not persisted as signed denial receipts.
9. **Root lifecycle.** Root transition history is recorded and runtime renewal is exercised. Original-root retirement and unattended policy-signer rotation are unfinished. Revoking the original root causes a broad fail-closed outage.
10. **Execution scope.** The demonstrated transaction delivers a static sample report. No merchant quote authentication, invoice system, x402 payment, escrow, wallet or settlement exists. Exactly-once database execution is not exactly-once delivery over a lossy network; retrying after a committed response is lost receives a replay denial.

The next implementation should preserve default-deny behavior and explicitly update this document whenever a trust boundary changes.
