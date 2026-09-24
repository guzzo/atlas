import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { z } from 'zod';
import { body, send, serve } from '../shared/http.js';
import {
  assert,
  digest,
  evidenceSchema,
  http,
  now,
  PassportError,
  randomID,
  requestSchema,
  sign,
  type Evidence,
  type Receipt,
  type Verification,
} from '../../sdk/wire.js';

const db = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
const migration = await db.connect();
try {
  await migration.query('BEGIN');
  await migration.query('SELECT pg_advisory_xact_lock(872104)');
  await migration.query(
    'CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
  );
  if (
    !(await migration.query("SELECT 1 FROM schema_migrations WHERE version='001_initial'")).rowCount
  ) {
    await migration.query(await readFile('apps/globex/migrations/001_initial.sql', 'utf8'));
    await migration.query("INSERT INTO schema_migrations(version) VALUES('001_initial')");
  }
  await migration.query('COMMIT');
} catch (e) {
  await migration.query('ROLLBACK');
  throw e;
} finally {
  migration.release();
}
const privateKey = await readFile(process.env.GLOBEX_KEY_FILE ?? '/globex/root.pem', 'utf8');
const verifier = process.env.VERIFIER_URL ?? 'http://verifier:8080';
const purchaseBody = z
  .object({
    sku: z.literal('research-report'),
    quantity: z.literal(1),
    amount_minor_units: z.number().int().positive().max(100000),
    currency: z.literal('USD'),
    recipient: z.literal('globex'),
  })
  .strict();

function receipt(
  e: Evidence,
  v: Partial<Verification>,
  type: Receipt['receipt_type'],
): ReturnType<typeof sign<Receipt>> {
  const r = e.request.payload;
  return sign(
    'receipt',
    'globex-root-1',
    {
      id: randomID('receipt'),
      receipt_type: type,
      org_id: 'globex',
      decision: v.decision ?? 'deny',
      code: v.code ?? 'denied',
      request_id: r.request_id,
      capability_id: e.capability.payload.capability_id,
      verifier: 'globex',
      issued_at: now(),
      policy_version: v.policy_version ?? e.capability.payload.policy_version,
      request_digest: digest(r),
      evidence_digest: digest(e),
      trace: v.trace ?? [],
    },
    privateKey,
  );
}
async function check(e: Evidence): Promise<Verification> {
  const r = requestSchema.parse(e.request.payload);
  const v = await http<Verification>(`${verifier}/v0/verify`, e);
  assert(v.decision === 'allow', 'denied');
  // Globex controls these acceptance rules, independently of Acme's policy.
  assert(
    r.issuer_org === 'acme' &&
      r.audience === 'globex' &&
      r.recipient === 'globex' &&
      r.action === 'purchase' &&
      r.resource === 'globex:research-report' &&
      r.method === 'POST' &&
      r.path === '/v0/purchases',
    'denied',
  );
  const b = purchaseBody.parse(r.body);
  assert(
    b.amount_minor_units === r.amount_minor_units &&
      b.currency === r.currency &&
      b.recipient === r.recipient,
    'request_mismatch',
  );
  const result = await db.query('SELECT * FROM challenges WHERE nonce=$1', [r.nonce]),
    c = result.rows[0];
  assert(c, 'invalid_nonce');
  assert(!c.consumed, 'replay');
  assert(Number(c.expires_at) > now(), 'expired');
  assert(
    c.audience === r.audience &&
      c.action === r.action &&
      c.resource === r.resource &&
      r.issued_at >= Number(c.issued_at) &&
      r.expires_at <= Number(c.expires_at),
    'request_mismatch',
  );
  assert(v.valid_until > now(), 'expired');
  v.trace.push('globex_acceptance_rules', 'globex_challenge_valid');
  return v;
}
serve(8081, async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    await db.query('SELECT 1');
    send(res, 200, { status: 'ok' });
    return;
  }
  if (req.method === 'GET' && req.url === '/v0/receipts') {
    const rows = await db.query('SELECT document FROM receipts ORDER BY created_at DESC LIMIT 50');
    send(
      res,
      200,
      rows.rows.map((r) => r.document),
    );
    return;
  }
  if (req.method === 'POST' && req.url === '/v0/challenges') {
    z.object({})
      .strict()
      .parse(await body(req));
    const c = {
      nonce: randomBytes(32).toString('hex'),
      audience: 'globex',
      action: 'purchase',
      resource: 'globex:research-report',
      issued_at: now(),
      expires_at: now() + 120,
    };
    await db.query(
      'INSERT INTO challenges(nonce,audience,action,resource,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)',
      [c.nonce, c.audience, c.action, c.resource, c.issued_at, c.expires_at],
    );
    send(res, 201, c);
    return;
  }
  if (req.method !== 'POST' || !['/v0/verify', '/v0/purchases'].includes(req.url ?? '')) {
    send(res, 404, { code: 'not_found' });
    return;
  }
  const e = evidenceSchema.parse(await body(req)) as unknown as Evidence;
  // Validate receipt identifiers before any audit persistence.
  requestSchema.parse(e.request.payload);
  assert(
    typeof e.capability.payload.capability_id === 'string' &&
      typeof e.capability.payload.policy_version === 'string',
    'invalid_request',
  );
  try {
    const v = await check(e);
    if (req.url === '/v0/verify') {
      send(res, 200, v);
      return;
    }
    const tx = await db.connect();
    let signed;
    const executionID = randomID('exec');
    try {
      await tx.query('BEGIN');
      const consumed = await tx.query(
        'UPDATE challenges SET consumed=true WHERE nonce=$1 AND consumed=false AND expires_at > EXTRACT(EPOCH FROM clock_timestamp()) AND $2 > EXTRACT(EPOCH FROM clock_timestamp()) RETURNING nonce',
        [e.request.payload.nonce, v.valid_until],
      );
      if (consumed.rowCount !== 1)
        throw new PassportError(now() >= v.valid_until ? 'expired' : 'replay');
      await tx.query(
        'INSERT INTO executions(id,nonce,request_id,capability_id,request_digest) VALUES($1,$2,$3,$4,$5)',
        [
          executionID,
          e.request.payload.nonce,
          e.request.payload.request_id,
          e.capability.payload.capability_id,
          v.request_digest,
        ],
      );
      v.trace.push('nonce_consumed_atomically', 'simulated_resource_delivered');
      signed = receipt(e, v, 'execution');
      await tx.query('INSERT INTO receipts(id,document) VALUES($1,$2)', [
        signed.payload.id,
        JSON.stringify(signed),
      ]);
      await tx.query("INSERT INTO outbox(receipt_id,topic) VALUES($1,'purchase.executed')", [
        signed.payload.id,
      ]);
      await tx.query('COMMIT');
    } catch (error) {
      await tx.query('ROLLBACK');
      throw error;
    } finally {
      tx.release();
    }
    send(res, 201, {
      decision: 'allow',
      execution_id: executionID,
      receipt: signed,
      resource: {
        title: 'Globex research report',
        content:
          'A demonstration resource delivered after independent authorization verification. No payment was made.',
        simulated: true,
      },
    });
  } catch (error) {
    const failure =
      error instanceof PassportError
        ? error
        : new PassportError(
            error instanceof z.ZodError ? 'denied' : 'unavailable',
            error instanceof z.ZodError ? 403 : 503,
          );
    const details = (failure.detail ?? {}) as Partial<Verification>;
    const denied = receipt(e, { ...details, decision: 'deny', code: failure.code }, 'denial');
    const tx = await db.connect();
    try {
      await tx.query('BEGIN');
      await tx.query('INSERT INTO receipts(id,document) VALUES($1,$2)', [
        denied.payload.id,
        JSON.stringify(denied),
      ]);
      await tx.query("INSERT INTO outbox(receipt_id,topic) VALUES($1,'purchase.denied')", [
        denied.payload.id,
      ]);
      await tx.query('COMMIT');
    } catch {
      await tx.query('ROLLBACK');
      throw new PassportError('unavailable', 503);
    } finally {
      tx.release();
    }
    send(res, failure.status, { decision: 'deny', code: failure.code, receipt: denied });
  }
});
