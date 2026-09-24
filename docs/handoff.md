# Passport implementation handoff

Implementation and local validation: **2026-09-24 UTC**. The original [northstar.md](../northstar.md) is unchanged. Decisions made where the brief had gaps are in [decisions.md](decisions.md).

## Current result

The complete local Acme → Globex trust demonstration runs with Docker Compose. It includes real Ed25519 signatures, exact-request capabilities, a schema-validated Cedar policy, live revocation and policy state, durable replay prevention, separate authorization/execution receipts, an actual hidden-limit Bulletproof, and a credential-scoped MCP integration for local Codex instances.

Start and verify everything:

```sh
make demo
./bin/passport identity codex-local
./bin/passport connect codex-local
```

The dashboard is at **http://127.0.0.1:8080**. The connection command prints the exact Codex registration command for this checkout. Run it, restart the Codex session, and use `/mcp`. Ask the agent to verify its identity and a 1200-cent purchase; ask explicitly to execute if an execution receipt is wanted. No OpenAI API key is required by Passport.

The **Get Started** page at `/get-started/` introduces the trust problem, illustrates the Acme → Globex request flow, and provides copyable setup commands and a verification prompt. Overview remains the default at `/`. Navigation works on desktop and mobile. Its passport illustration is explicitly an example; the page does not fetch activity or perform transactions. The optional private proof is described only as hiding the per-transaction spending limit. Page assets live in `web/get-started/` and use the existing static file server and Compose web mount.

**No machine configuration intervention is currently needed.** Docker/Compose, Node/npm, Go and Rust were available and used. npm/Go/Cargo dependencies, Docker images and the Playwright Chromium browser were downloaded successfully. The seven platform services were left running and healthy. The Codex tool connection itself was exercised through an MCP protocol client; no live model session was launched and no user-wide Codex configuration was silently changed.

## Delivered against the north star

| Area                   | Implemented                                                                                                                                                                                               | Remaining boundary                                                                                             |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Registry and trust     | Root-signed organizations/agents/keys/delegations; policy signer delegation; signed fresh public bundles; scoped admin credentials; revocation; immutable IDs; root transition history; migrations/outbox | Production admin identity, complete root retirement and signer lifecycle                                       |
| Verifier               | Portable Go package and separate Globex-owned deployment; pinned issuer/registry keys; exact request binding; fresh state; failure trace and explicit codes                                               | Offline snapshots, scalable state resolution and production availability model                                 |
| TypeScript integration | Request signing, capability acquisition, verified Globex receipts, typed generated API client, CLI and MCP tools                                                                                          | Published SDK packages, other languages and a third-party conformance suite                                    |
| Policy                 | Real Cedar evaluation; validated fixed purchase-policy schema; private integer threshold; root-signed version/predecessor/commitment; serialized activation                                               | General policy authoring/editor, policy simulation and crash-safe publication workflow                         |
| Private proof          | Rust Bulletproofs predicate; randomized Pedersen commitment; request/capability transcript binding; distinct public verification worker; feature flag; benchmark and adversarial tests                    | Independent crypto/protocol review, broader performance/adversary testing                                      |
| Counterparty           | TypeScript Globex server; its own acceptance rules/database; transactional nonce consumption, execution, signed receipt and outbox                                                                        | Actual resource integrations, retry-result retrieval and external side-effect reconciliation                   |
| Operations             | One-command Compose startup/demo; local keys; isolated mounts; restart persistence; watch configuration; health checks; dashboard; CI workflow                                                            | AWS/Terraform, KMS/HSM, service authentication/TLS, observability, backup/restore and external outbox delivery |

The purchase is a static simulated report. No money, wallet, escrow, x402 exchange, on-chain registry, cumulative spending ledger or production compliance capability was implemented. Those remain outside the first POC milestone.

## Validation actually completed

- **32 live Compose acceptance cases passed**, including successful baseline/proof requests; wrong audience/issuer; altered amount/body/recipient/resource/policy/signature; expiry; replay; eight concurrent copies with exactly one execution; administrative misuse; Globex denial despite valid Acme authority; over-limit Cedar/prover denial; proof forgery/transplant/missing/unapproved program; policy update/stale commitment; runtime/delegation revocation; runtime renewal; and prevention of revoked-ID resurrection.
- Go verifier/wire tests passed with the race detector, including additional root, policy and signer revocation, stale/future state, final freshness recheck, signing profile and canonicalization attacks.
- TypeScript tests passed against the same published canonicalization/Ed25519 vector used by Go.
- Rust tests passed for commitment hiding, changed public-input rejection and actual proof/Cedar conformance at integer boundaries.
- TypeScript checking, Go vet and Rust formatting checks passed.
- The actual MCP stdio client discovered all four tools and successfully called `passport_identity` and `passport_verify` with a proof.
- Stopping the registry made Globex reject with `unavailable`; the outage script restored the service.
- A browser check passed for desktop/mobile live data, receipt expansion, filtering, lack of horizontal page overflow and browser errors. Screenshots are in `.local/reports`.
- Get Started browser checks passed at ten widths from 320 to 1920 pixels, including desktop/mobile navigation, interactive diagram steps, keyboard activation, clipboard success/fallback, direct links/reload and reduced motion. The existing Overview smoke check also passed after the navigation update. Screenshots: `.local/reports/get-started-desktop.png` and `get-started-mobile.png`.
- The proof benchmark produced **672-byte proofs**; initial median generation **7.68 ms**, verification **2.93 ms**, including local HTTP round trips. See [the benchmark discussion](proof-experiment.md).
- Rebuild/restart and repeated bootstrap/demo runs preserved existing installation state.
- A fresh isolated checkout with independently generated keys and an empty database also passed the single-command `make demo` flow and all 32 acceptance cases.
- With the private-proof feature disabled, baseline verification still passed and proof requests failed closed with `feature_disabled`.

Reproduce with `make check test`, `./bin/passport demo`, `./bin/passport benchmark`, `node --import tsx scripts/mcp-smoke.ts`, `bash tests/outage.sh`, and `node --import tsx scripts/ui-smoke.ts`. Raw local acceptance/benchmark reports are in `.local/reports`. CI is defined in `.github/workflows/ci.yml`; a remote CI run has not been observed because no repository publication was requested.

## Next work, in priority order

### 1. Review the protocol before an external pilot

Have a security/cryptography reviewer examine the custom signed-envelope profile, trust distribution, registry state assumptions, capability binding and Bulletproofs composition. Add adversarial fuzzing/property tests for both wire decoders and a larger independent conformance-vector corpus. Review whether five-second in-flight revocation staleness is acceptable.

Acceptance: an independent verifier implementation rejects the same negative vectors; documented review issues are resolved; cryptographic dependencies and the proof profile have a release/versioning policy.

### 2. Complete key lifecycle and enrollment

Runtime renewal works. Organization root transitions are stored, but **revoking the original root currently invalidates the original organization/agent records as well as authority grants**. The implementation deliberately fails closed; stable-identity root retirement needs versioned/reissued identity bindings or a reviewed historical-root model. Do not treat the rotation-record endpoint as a finished operational rollover ceremony.

Policy-signing certificates expire after 30 days and bootstrap uses an immutable initial signer ID. Add delegated-signer renewal, root re-pinning/recovery, overlapping validity, lost-runtime recovery and explicit emergency revocation workflows. The local administrator generates runtime keys; production enrollment should let the runtime generate its key and prove possession before receiving credentials.

Acceptance: rotate each key type, revoke the previous key, preserve intended stable identities, reject old authority, and prove that Passport never obtains an organization root or an undelegated signer.

### 3. Make policy publication recoverable

The registry transaction and Acme's private witness file are separate. A crash after registry activation but before the file replacement leaves a safe denial state requiring operator reconciliation. Design a staged/private version store and explicit activation/recovery protocol. Add races, crash injection, monotonic version checks across concurrent administrators and a recovery command. Decide whether to allow arbitrary Cedar policy editing or keep a narrow supported policy family.

Acceptance: every injected interruption either preserves the previous usable policy or recovers to the new one without losing the authenticated witness; no silent permissive fallback.

### 4. Establish real organizational and runtime isolation

Replace local administrative bearer files with operator authentication/RBAC and customer-controlled signing or explicitly scoped hosted signing. Add TLS and authenticated service boundaries, request-rate limits and audit access controls. Move actual runtime agents into isolated users/containers; a Codex instance with unrestricted access to the developer's checkout can read developer-owned keys. Separate Acme and Globex onto independent hosts/accounts and independently provision their public pins.

Acceptance: a Globex deployment receives only public Acme material; a runtime cannot read administrator material or reach administration with privileged credentials; separate accounts can execute the same contract tests.

### 5. Improve replay, audit and state operations

PostgreSQL provides concurrency safety for all Globex instances using the same database, but multi-instance/failover/load behavior has not been measured. Add authenticated result lookup so clients can recover the original receipt after a response is lost, nonce/receipt retention, pagination/targeted trust-state resolution, outbox dispatch/acknowledgment, structured metrics/tracing, backup/restore and operational SLOs. Current trust bundles include every organization record and are bounded by the verifier's four-MiB response cap; use signed targeted bundles before high enrollment volume.

Acceptance: restart/failover/retry tests prove no duplicate local action; outbox retries are safe; audit export is durable; large organizations cannot hit unbounded bundle/receipt growth.

### 6. Decide the next product transaction

Choose a first customer/counterparty, a genuine resource and acceptance/assurance requirements. Current Globex accepts a narrow simulated purchase body and a local maximum; it does not authenticate a merchant quote or invoice. Decide whether a simple real resource-access integration or simulated/testnet x402 adapter best validates the thesis. Keep actual payments behind an explicit settlement design.

If cumulative budgets are needed, build an authoritative reservation ledger with expiry, atomic concurrency handling and execution/cancellation reconciliation before claiming spend safety. A static hidden-limit or remaining-balance proof is insufficient.

Acceptance: the external resource owner accepts a protocol-bound request using independently provisioned trust, and settlement/budget behavior has its own tested state machine if introduced.

### 7. Plan production deployment only after the above decisions

The north-star AWS target remains ECS Fargate, RDS, KMS, an outbox/SQS bridge and CloudWatch/OpenTelemetry, with Terraform. No infrastructure was deployed. Verify KMS's supported algorithms/encodings against the pinned profile before choosing a key substitution. Decide regions, expected volume, cost/resource budget, customer-hosted versus hosted authority/prover, and availability/freshness SLOs. Pin deployment images by digest, publish SBOMs, add dependency/security scanning and independent threat review.

## Founder decisions still open

1. Who is the first external counterparty, and what exact action/value are they willing to accept?
2. Is a delegated SDK runtime key sufficient assurance, or is workload attestation/federation needed?
3. Should Acme always operate its own authority/prover? What hosted signing delegation, if any, is acceptable?
4. Is mandatory online verification with up to five seconds of in-flight staleness acceptable?
5. Is hiding the numeric threshold enough, including what repeated authorization results disclose?
6. Is x402 important to the first customer validation, or can resource access establish trust first?
7. What production resource budget, regions and operational ownership should guide deployment?

No separate founder plan was provided. The current defaults and unresolved gaps are recorded rather than silently presented as production-ready decisions.
