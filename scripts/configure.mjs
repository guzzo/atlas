#!/usr/bin/env node
// Only local development material is generated here. Never print private keys.
import { mkdir, readFile, writeFile, chmod, access } from 'node:fs/promises';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
process.chdir(root);
process.umask(0o077);
for (const dir of [
  'admin',
  'registry',
  'acme/authority',
  'globex',
  'public',
  'agents',
  'db',
  'reports',
])
  await mkdir(`.local/${dir}`, { recursive: true, mode: 0o700 });
async function exists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}
async function once(file, content) {
  if (!(await exists(file))) await writeFile(file, content, { mode: 0o600, flag: 'wx' });
}
function pair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    private_key: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    public_key: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  };
}
const token = () => randomBytes(32).toString('hex');
if (!(await exists('.local/admin/installation.json'))) {
  if (await exists('.env'))
    throw new Error(
      'An .env exists without local key material. Move it aside or restore the matching .local directory; setup will not overwrite it.',
    );
  const acme = pair(),
    globex = pair(),
    policy = pair(),
    registry = pair();
  const installation = {
    acme,
    globex,
    policy,
    registry,
    tokens: { bootstrap: token(), acme: token(), globex: token() },
    db: { postgres: token(), passport: token(), globex: token() },
  };
  await once('.local/admin/installation.json', JSON.stringify(installation, null, 2));
}
const i = JSON.parse(await readFile('.local/admin/installation.json', 'utf8'));
await once(
  '.env',
  `COMPOSE_PROJECT_NAME=passport\nPOSTGRES_PASSWORD=${i.db.postgres}\nPASSPORT_DB_PASSWORD=${i.db.passport}\nGLOBEX_DB_PASSWORD=${i.db.globex}\nENABLE_ZK=1\nPASSPORT_PORT=8080\nGLOBEX_PORT=8081\nAUTHORITY_PORT=8082\nVERIFIER_PORT=8083\nLOCAL_UID=${process.getuid?.() ?? 1000}\nLOCAL_GID=${process.getgid?.() ?? 1000}\n`,
);
await once('.local/registry/registry.pem', i.registry.private_key);
await once('.local/registry/admin.json', JSON.stringify(i.tokens));
await once('.local/acme/authority/policy.pem', i.policy.private_key);
await once('.local/acme/authority/admin.token', i.tokens.acme);
await once('.local/globex/root.pem', i.globex.private_key);
await once(
  '.local/public/trust.json',
  JSON.stringify(
    {
      registry_key_id: 'passport-registry-1',
      registry_public_key: i.registry.public_key,
      trusted_roots: {
        acme: { 'acme-root-1': i.acme.public_key },
        globex: { 'globex-root-1': i.globex.public_key },
      },
    },
    null,
    2,
  ),
);
await once(
  '.local/db/001-users.sql',
  `CREATE USER passport WITH PASSWORD '${i.db.passport}';\nCREATE DATABASE passport OWNER passport;\nCREATE USER globex WITH PASSWORD '${i.db.globex}';\nCREATE DATABASE globex OWNER globex;\nREVOKE CONNECT ON DATABASE passport FROM PUBLIC;\nGRANT CONNECT ON DATABASE passport TO passport;\nREVOKE CONNECT ON DATABASE globex FROM PUBLIC;\nGRANT CONNECT ON DATABASE globex TO globex;\n`,
);
// postgres reads its init SQL as the container's postgres user; this file contains
// only local DB passwords and its parent is host-private (0700).
await chmod('.local/db/001-users.sql', 0o644);
console.log(
  'Local development keys and configuration are ready. Private material stays in .local/.',
);
