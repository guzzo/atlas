# Implementation decisions

This implements `northstar.md` (unchanged). No separate founder plan was supplied.

## Frozen v0 contract

1. First transaction: `purchase` of `globex:research-report`, audience `globex`, recipient `globex`, integer USD cents, asset `iso4217:USD`, network `simulation`. No payment or transfer occurs.
2. Runtime identity: locally generated Ed25519 keys, root-signed agent registration, runtime certificate and bounded delegation. Enrollment is an administrator operation; an agent's runtime signature never grants administration rights.
3. Acme owns its root and separately delegated capability-signing key. Passport mounts neither. Acme operates its own Cedar/proof worker. Globex operates a separate public-input-only proof verifier. Secret policy material never enters registry storage.
4. Go registry and portable Go verifier; PostgreSQL migrations and transactional outbox. Globex's TypeScript application invokes its own Go verifier deployment, using public trust pins. This is independent of Passport's decision making and requires no Acme secrets. The published verifier has an online registry dependency.
5. Every verification fetches a signed registry bundle bound to a fresh random challenge. No cache; a five-second maximum state age; recheck time after proof verification. Registry outages fail closed. An operation already in flight may complete within that five-second bound after revocation. The registry remains trusted to report state honestly; its signing key is pinned separately from Acme's root.
6. Globex atomically consumes challenges, inserts the simulated execution and signed execution receipt in one PostgreSQL transaction. This gives exactly-once local simulation under concurrent retries. It does not provide exactly-once external payments or cumulative budget accounting.
7. Wire profile `passport.v0.ed25519-jcs`: Ed25519 over RFC 8785 canonical JSON of `{profile,kind,key_id,payload}`; base64url unpadded signatures, SPKI DER public keys, SHA-256 hex digests. Unix-second integer times, no clock-skew allowance. Duplicate JSON keys are rejected. All meaningful fields are signed, including the envelope key ID and object kind.
8. Private predicate: Bulletproofs 5 / Ristretto Pedersen commitment. Prove both the committed limit and `limit - amount` are in `[0, 2^32)` in a single aggregated proof. A Merlin transcript binds the full capability payload, including exact-request digest. Acme's signed policy authenticates the commitment; its delegated signer authenticates capability public inputs. These signatures are verified outside the range proof. This is a composition, not a Cedar-to-ZK compiler or a hidden program. Program descriptor is pinned, and the feature can be disabled.
9. USD amounts and private limits are integers from 0 through 4,294,967,295. Requests must have a positive amount. Body bytes are canonical JSON; method and path are signed and checked against the actual Globex route.
10. Root rotation requires an old-root-signed transition, append-only key history, and explicit verifier re-pinning for new roots. There is no automatic root trust expansion. Immutable object IDs cannot resurrect revoked keys/delegations. Policy versions advance by a serialized predecessor compare-and-swap.
11. Local administrative authentication uses random per-organization bearer credentials in ignored mode-0600 files, plus required organization signatures on mutations. Bootstrap has a separate credential. This is a development mechanism, to be replaced with operator SSO/RBAC and KMS/HSM workflows.
12. Docker Compose is the supported development environment. AWS deployment, x402, actual money, global reputation, workload federation and cumulative budgets are deferred. Local ports bind only to loopback.

## Open product decisions

See [handoff.md](handoff.md) for implementation status, acceptance evidence and prioritized remaining work. The first external customer, intended workload assurance, production revocation SLO, privacy threat model and hosting boundary need founder/security review before a production design is claimed.

## References checked during implementation

- [Cedar authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html) and [Rust API](https://docs.rs/cedar-policy/latest/cedar_policy/).
- [Bulletproofs range proof API](https://docs.rs/bulletproofs/5.0.0/bulletproofs/struct.RangeProof.html).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).
- [Codex MCP configuration](https://developers.openai.com/codex/mcp/).
