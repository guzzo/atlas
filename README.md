# Passport

A runnable implementation of [northstar.md](northstar.md): independently operated agents prove their organization, live runtime authority, and authorization for an exact request. Acme issues authority; Globex independently verifies it and makes its own decision. The optional private proof hides a per-transaction limit.

This is a local proof of concept with real signatures, Cedar evaluation and Bulletproofs, and a **simulated resource purchase**. It does not move money. Start with [the handoff](docs/handoff.md) for verified implementation status and remaining work.

## Run the platform and acceptance demo

Prerequisites: Docker Engine with Compose, Node.js 22+, and Make. Go and Rust are only needed for native development/tests; the services build inside Docker.

```sh
make demo
```

This generates local development keys and administrator credentials, builds the containers, migrates PostgreSQL, registers Acme and Globex, enrolls `codex-local`, and runs positive and adversarial scenarios. Re-running it preserves the database, keys and receipts. Demo agents have fresh IDs; the policy-update scenario advances Acme's active policy and invalidates previously issued capabilities.

- Dashboard: **http://127.0.0.1:8080**
- Globex resource API: `http://127.0.0.1:8081`
- Acme authority: `http://127.0.0.1:8082`
- Independent Go verifier: `http://127.0.0.1:8083`
- OpenAPI: [api/openapi.json](api/openapi.json), also served at `/api/openapi.json`
- Acceptance report: `.local/reports/demo.json`

To start without running the scenarios, use `./bin/dev`. Ports and the experimental proof flag are in the generated `.env`. Published ports bind to loopback; PostgreSQL and proof workers have no host ports. There are no cloud credentials, wallet connections, or OpenAI API keys to configure.

## Connect a local Codex instance

The default agent is already enrolled after startup:

```sh
./bin/passport identity codex-local
./bin/passport connect codex-local
```

The second command prints a ready-to-run `codex mcp add` command with the absolute path to this checkout. Run that command, restart the Codex session, and use `/mcp` to check the connection. This follows [Codex's documented local stdio MCP configuration](https://developers.openai.com/codex/mcp/).

Then ask Codex:

> Verify my Passport identity, then verify a 1200-cent Globex purchase with a private proof. Show the verification trace without executing the purchase.

The MCP tools are `passport_identity`, `passport_verify`, `passport_purchase`, and `passport_receipts`. `passport_verify` issues an authorization receipt but does not consume the purchase nonce. `passport_purchase` executes the simulation and returns a signed execution receipt.

Give each additional runtime its own identity:

```sh
./bin/passport enroll codex-researcher
./bin/passport connect codex-researcher
```

Runtime keys/delegations last 24 hours. Renew them with `./bin/passport renew codex-researcher`, then restart its MCP connection. Renewal revokes the old credentials. The default profile is automatically renewed by bootstrap when it expires. Organization policy-signing certificates and policy versions last 30 days; their full lifecycle remains a handoff item.

The MCP container mounts only its selected runtime profile, read-only. It receives no administrator token, organization root, private policy or policy-signing key. The developer account still owns all local files; this is not an isolation boundary against a Codex instance with unrestricted host-shell access.

## Verify and execute without a model

```sh
./bin/passport verify codex-local 1200 --proof
./bin/passport purchase codex-local 1200 --proof
./bin/passport benchmark
```

Amounts are integer USD cents. Omit `--proof` for the conventional signed-capability path. A verifier always checks live state, even for a valid private proof. No hidden policy parameter is returned in the evidence, receipts or benchmark.

The verify command exports public evidence for another verifier:

```sh
./bin/passport verify codex-local 1200 --proof
curl -sS http://127.0.0.1:8083/v0/verify \
  -H 'Content-Type: application/json' \
  --data-binary @.local/reports/last-evidence.json
```

Run the second command immediately: capabilities expire within 60 seconds. A successful cryptographic check is not an execution receipt; Globex must also apply its rules and atomically consume its nonce.

## Develop and test

```sh
npm ci
make check test
./bin/passport demo
node --import tsx scripts/mcp-smoke.ts
bash tests/outage.sh
```

`make check test` runs TypeScript checking, Go vet/race tests, Rust formatting/tests, cross-language signing vectors, and negative verification cases. The outage check temporarily stops this project's registry and restores it with an exit trap. CI also runs Compose acceptance, the benchmark, MCP transport and a browser smoke check.

```sh
docker compose watch           # rebuild Go, TypeScript and Rust after source changes
docker compose logs --tail=100 -f
docker compose down            # retain local keys and database
```

Web assets are bind-mounted and refresh directly. `./bin/dev` is also a complete rebuild/restart path. See [the runbook](docs/runbook.md) for recovery, port changes and credential management.

## Repository map

| Path                                | Purpose                                                                    |
| ----------------------------------- | -------------------------------------------------------------------------- |
| `cmd/passport`, `internal/registry` | Go HTTP control plane, migrations, signed live state, transactional outbox |
| `pkg/wire`, `pkg/verifier`          | Canonical signing profile and portable verifier library                    |
| `workers/policy-proof`              | Validated Cedar policy; private prover and public proof-verification modes |
| `sdk`                               | TypeScript signing/agent helpers and generated OpenAPI client types        |
| `apps/authority`                    | Acme-owned capability issuer; holds no organization root                   |
| `apps/globex`                       | Counterparty acceptance, durable replay protection and execution receipts  |
| `apps/agent`                        | Local agent CLI and Codex MCP server                                       |
| `scripts`, `tests`                  | Bootstrap, acceptance demo, benchmark and integration checks               |
| `web`                               | Live local identity and receipt dashboard                                  |

Further reading: [architecture](docs/architecture.md), [wire protocol](docs/protocol.md), [threat model](docs/threat-model.md), [proof experiment](docs/proof-experiment.md), [decisions](docs/decisions.md), and [handoff](docs/handoff.md).
