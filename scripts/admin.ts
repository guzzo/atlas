import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { AgentClient, type AgentProfile } from '../sdk/agent.js';
import {
  http,
  id,
  keys,
  now,
  randomID,
  sign,
  PROGRAM,
  type Doc,
  type Pins,
  type Policy,
} from '../sdk/wire.js';
import type { AuthorityConfig } from '../apps/authority/server.js';

export const local = process.env.LOCAL_DIR ?? '.local';
export const registryURL = process.env.REGISTRY_URL ?? 'http://127.0.0.1:8080';
export const workerURL = process.env.WORKER_URL ?? 'http://acme-worker:8090';
export interface Installation {
  acme: { private_key: string; public_key: string };
  globex: { private_key: string; public_key: string };
  policy: { private_key: string; public_key: string };
  tokens: { bootstrap: string; acme: string; globex: string };
}
export async function installation(): Promise<Installation> {
  return JSON.parse(await readFile(`${local}/admin/installation.json`, 'utf8'));
}
export async function save(file: string, value: unknown): Promise<void> {
  const temp = `${file}.${randomID('tmp')}`;
  await writeFile(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
  await rename(temp, file);
}
export async function register(path: string, doc: Doc<any>, token: string): Promise<void> {
  await http(`${registryURL}${path}`, doc, token);
}
export async function enroll(name: string, renew = false): Promise<AgentClient> {
  id.parse(name);
  const file = `${local}/agents/${name}/profile.json`;
  let previous: AgentProfile | undefined;
  try {
    previous = JSON.parse(await readFile(file, 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  if (previous && !renew)
    throw new Error(`Profile ${name} already exists; use renew to rotate its runtime credentials.`);
  if (!previous && renew) throw new Error(`Profile ${name} does not exist; enroll it first.`);
  const i = await installation(),
    pair = keys(),
    start = now() - 1,
    end = start + 86400,
    keyID = randomID(`${name.slice(0, 50)}-key`),
    delegationID = randomID('del');
  if (!previous)
    await register(
      '/v0/agents',
      sign(
        'agent',
        'acme-root-1',
        { id: name, org_id: 'acme', name, created_at: now() },
        i.acme.private_key,
      ),
      i.tokens.acme,
    );
  await register(
    `/v0/agents/${name}/keys`,
    sign(
      'runtime_key',
      'acme-root-1',
      {
        id: keyID,
        org_id: 'acme',
        agent_id: name,
        public_key: pair.public_key,
        delegation_id: delegationID,
        not_before: start,
        expires_at: end,
      },
      i.acme.private_key,
    ),
    i.tokens.acme,
  );
  const delegation = sign(
    'delegation',
    'acme-root-1',
    {
      id: delegationID,
      org_id: 'acme',
      agent_id: name,
      runtime_key_id: keyID,
      actions: ['purchase'],
      resources: ['globex:research-report'],
      audiences: ['globex'],
      not_before: start,
      expires_at: end,
    },
    i.acme.private_key,
  );
  await register('/v0/delegations', delegation, i.tokens.acme);
  const pins = JSON.parse(await readFile(`${local}/public/trust.json`, 'utf8')) as Pins;
  const profile: AgentProfile = {
    agent_id: name,
    org_id: 'acme',
    key_id: keyID,
    private_key: pair.private_key,
    delegation,
    registry_url: `http://127.0.0.1:${process.env.PASSPORT_PORT ?? 8080}`,
    authority_url: `http://127.0.0.1:${process.env.AUTHORITY_PORT ?? 8082}`,
    globex_url: `http://127.0.0.1:${process.env.GLOBEX_PORT ?? 8081}`,
    pins,
  };
  await mkdir(`${local}/agents/${name}`, { recursive: true, mode: 0o700 });
  await save(file, profile);
  if (previous) {
    await revoke('runtime_key', previous.key_id);
    await revoke('delegation', previous.delegation.payload.id);
  }
  return AgentClient.fromFile(file);
}
export async function updatePolicy(limit: number): Promise<Doc<Policy>> {
  if (!Number.isInteger(limit) || limit < 0 || limit > 4294967295)
    throw new Error('Limit must be uint32 minor units');
  const i = await installation();
  let prior: AuthorityConfig | undefined;
  try {
    prior = JSON.parse(await readFile(`${local}/acme/authority/config.json`, 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const commitment = await http<{ commitment: string; blinding: string }>(
    `${workerURL}/v0/commit`,
    { limit },
  );
  const policy = sign(
    'policy',
    'acme-root-1',
    {
      id: randomID('policy'),
      org_id: 'acme',
      version: (prior?.policy.payload.version ?? 0) + 1,
      predecessor: prior?.policy.payload.id ?? '',
      commitment: commitment.commitment,
      predicate: PROGRAM,
      currency: 'USD',
      asset: 'iso4217:USD',
      network: 'simulation',
      not_before: now() - 1,
      expires_at: now() + 30 * 86400,
    },
    i.acme.private_key,
  );
  await register('/v0/policies', policy, i.tokens.acme);
  await save(`${local}/acme/authority/config.json`, {
    org_id: 'acme',
    policy_key_id: 'acme-policy-1',
    policy,
    limit,
    blinding: commitment.blinding,
  });
  return policy;
}
export async function revoke(kind: string, target: string): Promise<void> {
  const i = await installation();
  await register(
    '/v0/revocations',
    sign(
      'revocation',
      'acme-root-1',
      {
        id: randomID('revoke'),
        org_id: 'acme',
        target_kind: kind,
        target_id: target,
        issued_at: now(),
      },
      i.acme.private_key,
    ),
    i.tokens.acme,
  );
}
