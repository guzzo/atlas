# Local operations

## Start, stop and inspect

```sh
./bin/dev
./bin/passport demo
docker compose ps
docker compose logs --tail=100 registry verifier authority globex acme-worker globex-proof
docker compose down
```

The database volume and `.local` survive normal stop/start. All service health checks must become healthy before bootstrap runs. Startup needs Docker daemon access, outbound access to image/package registries, and free host ports 8080–8083. Other projects' containers are not managed by these commands.

`node scripts/configure.mjs` runs before Compose and uses only Node built-ins. It generates `.env` and `.local` once. Host UID/GID are recorded for bind-mounted development files on a fresh installation. No organization key is regenerated on a normal restart.

The authority's and Go verifier's `/healthz` endpoints indicate process readiness, not a guarantee that every downstream dependency or current policy will permit a request. `./bin/passport identity codex-local` and `./bin/passport verify codex-local` exercise live dependencies.

## Local material

| Path                                | Contents                                                                     |
| ----------------------------------- | ---------------------------------------------------------------------------- |
| `.local/admin/installation.json`    | Developer-owned bootstrap root/key generation material and local credentials |
| `.local/registry`                   | Registry state-signing key and administrator credential map                  |
| `.local/acme/authority`             | Delegated policy key, private policy/witness, authority admin credential     |
| `.local/globex`                     | Globex receipt-signing development root                                      |
| `.local/public/trust.json`          | Public root and registry pins; suitable for the independent verifier         |
| `.local/agents/<name>/profile.json` | One runtime private key, delegation and public connection data               |
| `.local/reports`                    | Public acceptance/benchmark/evidence reports and dashboard screenshots       |

`.local` and `.env` are ignored by Git. Never attach the entire `.local` directory to a bug report or artifact upload. CI uploads only `.local/reports`.

## Ports, proof flag and rebuilds

Edit the generated `.env` and run `./bin/dev` again. Variables include `PASSPORT_PORT`, `GLOBEX_PORT`, `AUTHORITY_PORT`, `VERIFIER_PORT` and `ENABLE_ZK`.

Setting `ENABLE_ZK=0` keeps baseline signatures/Cedar working and rejects proof requests. The acceptance demo skips the proof scenarios in that mode. The dedicated MCP smoke script intentionally requests a proof and therefore expects `ENABLE_ZK=1`.

Containerized CLI/MCP use Compose service names, so host port changes do not affect them. Host-native clients must override their profile URLs or renew a profile after changing ports. Internal database passwords are initialized when the volume is first created; editing passwords in `.env` does not rotate an existing PostgreSQL user.

Use `docker compose watch` for source rebuilds. Browser assets are bind-mounted; refresh the browser after editing `web`. `npm run generate` refreshes the OpenAPI contract and generated TypeScript routes after contract-generator changes. `go.mod`/`go.sum`, `package-lock.json` and `Cargo.lock` are committed dependency locks.

## Agent lifecycle

```sh
./bin/passport enroll researcher-2
./bin/passport identity researcher-2
./bin/passport connect researcher-2
./bin/passport renew researcher-2
```

Renewal adds a fresh key and delegation under the same agent ID, saves the profile atomically, and revokes the old key/delegation. Restart that agent's MCP connection because the running process has already loaded the old key. New keys last 24 hours. The default agent is automatically renewed at bootstrap if expired or within a minute of expiry.

To disable an identity or grant, use an administrator command:

```sh
./bin/passport revoke agent researcher-2
# Other kinds: runtime_key, delegation, policy_key, policy, root_key, organization.
```

Revocation is one-way. Revoked IDs cannot be reused; a revoked agent needs a newly named registration. Do not revoke the original organization root as a routine renewal mechanism: stable-identity root retirement is unfinished and currently denies the whole chain.

## Policy updates

`./bin/passport policy <integer-limit-in-cents>` creates a fresh hiding commitment and signed successor policy, then atomically replaces the authority's local witness file. The CLI prints the policy ID/version, not the limit. The developer supplies the number and should consider shell-history exposure when using a real private value.

Publication and the local witness-file update span two storage systems. A crash between them deliberately leaves the authority fail-closed with `policy_mismatch`. Recover by inspecting the signed active bundle and reconciling the authority's private policy material; there is not yet a transactional publication coordinator or automatic repair command. Back up policy/witness files before operational changes. This recovery workflow is a prioritized handoff item.

Policy signing certificates expire after 30 days. Runtime renewal does not renew that certificate. For a long-lived environment, implement the delegated signer rollover task before that deadline, or intentionally create a fresh disposable demo installation.

## Verify failures

| Code/symptom                             | Inspect                                                                                       |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| `expired`                                | Runtime delegation, policy signer/policy validity, 60-second capability TTL and machine clock |
| `revoked`                                | The public trust bundle and ancestor/root status; revocation is transitive                    |
| `policy_mismatch`                        | Active policy pointer versus authority config and capability version                          |
| `replay`                                 | Nonce was consumed, possibly by an earlier committed request whose response was lost          |
| `unavailable`                            | Registry, verifier/proof worker, authority and PostgreSQL availability                        |
| `untrusted_issuer` / `invalid_signature` | Public pins, original `.local` installation, exact signed bytes, key IDs and algorithms       |
| `denied`                                 | Delegation/signer scope, Cedar decision, or Globex's own local acceptance rules               |
| `feature_disabled` / `invalid_proof`     | Feature flag, program profile, public-input binding and active commitment                     |
| Connection refused                       | `docker compose ps`, configured host ports and Docker daemon                                  |

For the actual fail-closed exercise, run `bash tests/outage.sh`. It stops only Passport's registry, asserts that Globex returns `unavailable`, and restores the registry with an exit trap.

## Deliberate reset

Resetting creates new identities and destroys the demo audit history. Stop the project, privately archive the matching `.local` and `.env` outside the repository, remove the **project's** database volume with `docker compose down --volumes` while its old configuration still exists, then move the old generated files out of the checkout and run `make demo`. Do not retain an old database while regenerating a different set of organization roots and passwords. This reset was not performed on unrelated local data.

## Browser and MCP checks

```sh
npx playwright install chromium
node --import tsx scripts/ui-smoke.ts
node --import tsx scripts/mcp-smoke.ts
```

The browser check writes desktop/mobile screenshots under `.local/reports`, verifies live registry data, expands a signed receipt, exercises filters and checks for browser errors/overflow. If Chromium requires OS libraries on a different machine, install Playwright's documented browser dependencies there. The MCP check uses the actual stdio protocol, lists tools, and calls identity and proof-backed verification without invoking a language model or using API credits.
