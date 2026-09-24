import { access, readFile } from 'node:fs/promises';
import { enroll, installation, local, register, updatePolicy } from './admin.js';
import { now, PassportError, sign } from '../sdk/wire.js';
import { AgentClient } from '../sdk/agent.js';
import { randomInt } from 'node:crypto';
async function main() {
  const i = await installation();
  for (const org of ['acme', 'globex'] as const) {
    try {
      await register(
        '/v0/organizations',
        sign(
          'organization',
          `${org}-root-1`,
          {
            id: org,
            name: org === 'acme' ? 'Acme Research' : 'Globex Reports',
            root_key_id: `${org}-root-1`,
            public_key: i[org].public_key,
            created_at: now(),
          },
          i[org].private_key,
        ),
        i.tokens.bootstrap,
      );
    } catch (e) {
      if (!(e instanceof PassportError && e.code === 'conflict')) throw e;
    }
  }
  try {
    await register(
      '/v0/policy-keys',
      sign(
        'policy_key',
        'acme-root-1',
        {
          id: 'acme-policy-1',
          org_id: 'acme',
          public_key: i.policy.public_key,
          actions: ['purchase'],
          resources: ['globex:research-report'],
          audiences: ['globex'],
          max_ttl: 60,
          not_before: now() - 1,
          expires_at: now() + 30 * 86400,
        },
        i.acme.private_key,
      ),
      i.tokens.acme,
    );
  } catch (e) {
    if (!(e instanceof PassportError && e.code === 'conflict')) throw e;
  }
  try {
    await access(`${local}/acme/authority/config.json`);
  } catch {
    await updatePolicy(randomInt(5000, 50001));
  }
  try {
    await access(`${local}/agents/codex-local/profile.json`);
  } catch {
    await enroll('codex-local');
  }
  const profile = JSON.parse(await readFile(`${local}/agents/codex-local/profile.json`, 'utf8'));
  if (profile.delegation.payload.expires_at <= now() + 60) await enroll('codex-local', true);
  await (await AgentClient.fromFile(`${local}/agents/codex-local/profile.json`)).identity();
  console.log('Acme and Globex are registered. Agent codex-local is enrolled.');
}
main().catch((error) => {
  console.error('Bootstrap failed:', error instanceof Error ? error.message : 'unknown');
  process.exitCode = 1;
});
