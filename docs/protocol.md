# Passport v0 wire and verifier contract

The normative machine-readable endpoint/type contract is [OpenAPI](../api/openapi.json). TypeScript route types are generated into `sdk/generated.ts`; `sdk/api.ts` exposes an `openapi-fetch` client. Regenerate with `npm run generate`. This document defines security semantics the schema alone cannot express.

## Signing and canonicalization

All signed documents have exactly these fields:

```json
{
  "profile": "passport.v0.ed25519-jcs",
  "kind": "request",
  "key_id": "runtime-key-id",
  "payload": {},
  "signature": "unpadded-base64url-Ed25519-signature"
}
```

Sign UTF-8 bytes of the **RFC 8785 canonical JSON** of `{profile, kind, key_id, payload}`. There is no prefix, JSON whitespace or trailing newline. Signature bytes are 64-byte Ed25519, encoded as canonical unpadded base64url. Public keys are DER SubjectPublicKeyInfo for Ed25519 encoded as canonical unpadded base64url. Local private files are PKCS#8 PEM.

`kind` supplies domain separation. Its values include `organization`, `agent`, `runtime_key`, `delegation`, `policy_key`, `policy`, `request`, `capability`, `revocation`, `root_rotation`, `trust_bundle` and `receipt`. The envelope's algorithm profile, kind and key ID are authenticated. Other signature algorithms and EVM wallet signatures are unsupported.

Every SHA-256 digest in the contract is lowercase hex over RFC 8785 bytes of the identified object. The **request digest** covers the request _payload_, including body, method, path, audience, nonce and proof preference. The **evidence digest** covers the entire evidence object, including envelopes and an optional proof. A proof transcript's context digest covers the capability _payload_.

Duplicate JSON keys, trailing content and unknown fields in defined signed payloads are rejected. Non-finite numbers are unsupported. Amounts are integer minor units in `[1, 4294967295]`; private limits are integers in `[0, 4294967295]`. The v0 financial units are exactly `USD`, `iso4217:USD`, and `simulation`. No conversion or rounding occurs. Timestamps are integer Unix seconds. The profile applies no clock-skew allowance.

The published deterministic [signing vector](../api/signing-vectors.json) covers Unicode, escaping, key sorting, payload digest, canonical signing input and an Ed25519 signature. Go and TypeScript tests both consume that file. Its RFC 8032 key is public test material and never an application identity.

## Authority chain

1. The administrator registers a self-signed organization object using a separate bootstrap bearer credential. This does **not** cause a counterparty to trust it; trust roots must be pinned out of band.
2. The organization's live root signs its agent registration, runtime certificate and delegation. Runtime certificates bind agent, key, validity and delegation ID. Delegations bind exact allowed actions, resources and audiences; there are no wildcard scopes.
3. The root signs a policy-key certificate with the same scope dimensions, validity and a maximum capability lifetime of at most 60 seconds.
4. The root signs each active policy version, commitment, predicate profile, units, effective interval and predecessor.
5. The runtime signs a request. Its nonce comes from Globex's challenge endpoint and its validity must fit within its certificate/delegation windows.
6. Acme verifies live state, evaluates its validated Cedar policy, optionally proves the hidden-limit predicate, and signs the exact-request capability with its delegated policy key. The capability cannot outlive the request, signer certificate or policy.

The request includes `request_id`, `issuer_org`, `agent_id`, `runtime_key_id`, `delegation_id`, action, resource, audience, recipient, amount, units, HTTP method/path, full JSON body, nonce, issuance/expiry and `want_proof`.

The capability repeats all authority/action/financial fields, and includes `request_digest`, nonce, issuance/expiry, `policy_version` (the immutable policy ID), `policy_commitment`, unique `capability_id` and `proof_program`. Empty `proof_program` means the conventional baseline. A request with `want_proof: true` cannot be downgraded to a baseline capability.

## Fresh state and trust

`GET /v0/organizations/{id}/trust?challenge=<32 random bytes as hex>` returns a registry-signed bundle. It contains public root status, immutable signed records, revocation flags, the active policy ID, the request's challenge, issuance and expiry. The read uses one PostgreSQL repeatable-read snapshot.

Pin the registry's state-verification public key **separately** from organizational roots. Accept a bundle only if its signature, issuer, echoed challenge and maximum five-second validity match. This prevents replay of a previously captured bundle by a network intermediary. Each verification performs a fresh fetch; there is no offline fallback or cache. The registry remains a trusted live-state authority: its own compromise can conceal revocation. Organizational signatures independently prevent it from creating new grants.

Unknown root keys are never trusted merely because a bundle contains them. Root transitions are recorded, but new roots require explicit local pin updates. Full original-root retirement with stable identities is not implemented; see the handoff. Revoking a root currently rejects all grants and identity records signed by that root.

## Verification and execution

`pkg/verifier.Config.Verify` and the independent service's `POST /v0/verify` return a decision, error code, evidence digests, trace, state issuance and `valid_until`. They perform:

1. Issuer allowlist lookup against local pins and a fresh signed registry fetch.
2. Organization/agent/runtime/delegation signatures and exact registration bindings.
3. Runtime proof of possession over the entire signed request.
4. Audience, delegation scope, integer units and validity-window checks.
5. Live key, delegation, signer and policy status; active policy matching.
6. Delegated capability signature, scope, exact request binding and maximum lifetime.
7. Optional proof verification under the pinned program and active commitment.
8. A final time check after proof verification. `valid_until` is the minimum of all relevant expirations, including the five-second registry snapshot.

Globex then validates its own accepted issuer (`acme`), recipient/audience (`globex`), resource (`globex:research-report`), method/path, complete purchase-body shape and local amount maximum. It checks that the nonce belongs to its persisted challenge with matching action/resource/audience. `POST /v0/purchases` then atomically consumes that challenge, checks `valid_until` again using database time, and executes the local simulation once.

Globex's `POST /v0/verify` includes its rules and challenge validation but does **not** consume the nonce. The Go verifier's endpoint verifies evidence only. Never use a dry-run decision as a durable authorization token; reverify at execution.

Registry/network outage returns `unavailable`; missing/inconsistent evidence fails closed. Revocation or policy activation affects the next state fetch immediately. An already verified in-flight operation may finish within its remaining five-second snapshot window. Registry consistency and reasonably synchronized clocks are part of the POC trust model.

## Receipts and errors

An `authorization` receipt is signed by Acme's policy key after authorization. An `execution` receipt is signed by Globex and committed with the simulated action. Globex records a signed `denial` receipt for well-formed rejected evidence. Malformed input that cannot safely be attributed receives an HTTP error without an attributable receipt.

Receipts contain request/capability IDs, decision/code, verifier, time, policy version, request/evidence digests and verification trace. They omit private policy values and witnesses. Receipts prove the signing service's recorded assertion; this POC provides no external append-only audit anchor.

Common codes: `invalid_signature`, `expired`, `revoked`, `replay`, `policy_mismatch`, `untrusted_issuer`, `denied`, `request_mismatch`, `invalid_proof`, `invalid_nonce`, `stale_state`, `unavailable`, `invalid_request`, `unauthorized`, `conflict`. Do not base trust on an HTTP 200 or an unbound Boolean alone.

## Public proof worker contract

`POST /v0/verify` on the Rust verification worker accepts exactly:

```json
{
  "program": "passport.hidden-limit.bp5.ristretto.32x2.v1",
  "commitment": "32-byte-compressed-Ristretto-point-as-hex",
  "amount_minor_units": 1200,
  "context_digest": "sha256-of-canonical-capability-payload-as-hex",
  "proof": "range-proof-bytes-as-hex"
}
```

It returns `{"valid": true}` only after cryptographic range-proof verification. This worker response is an internal component result; the outer verifier must authenticate signatures, public inputs, active policy and time. It is never accepted as agent-supplied authority.

Acme mode additionally exposes `/v0/commit` (`limit` → `commitment`, `blinding`), `/v0/prove` (public inputs plus private `limit`/`blinding` → `program`, `proof`), and `/v0/decide` (request context plus private limit → Cedar decision). These witness-bearing interfaces are private to Acme, are not published to host ports, and must not be proxied to counterparties. Verification mode has no witness endpoints. Request bodies are bounded and CPU work is limited to two concurrent tasks per worker.
