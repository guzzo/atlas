import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify,
} from 'node:crypto';
import canonicalizeImport from 'canonicalize';
import { parseTree, type Node, type ParseError } from 'jsonc-parser';
import { z } from 'zod';

export const PROFILE = 'passport.v0.ed25519-jcs';
export const PROGRAM = 'passport.hidden-limit.bp5.ristretto.32x2.v1';
const canonicalize = canonicalizeImport as unknown as (input: unknown) => string | undefined;
export const id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,127}$/);
export const timestamp = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
export const amount = z.number().int().positive().max(4294967295);
export const scopeSchema = z.object({
  actions: z.array(id).min(1).max(32),
  resources: z.array(id).min(1).max(32),
  audiences: z.array(id).min(1).max(32),
});
export const requestSchema = z
  .object({
    request_id: id,
    issuer_org: id,
    agent_id: id,
    runtime_key_id: id,
    delegation_id: id,
    action: id,
    resource: id,
    audience: id,
    recipient: id,
    amount_minor_units: amount,
    currency: z.literal('USD'),
    asset: z.literal('iso4217:USD'),
    network: z.literal('simulation'),
    method: z.literal('POST'),
    path: z.literal('/v0/purchases'),
    body: z.record(z.unknown()),
    nonce: id.min(32),
    issued_at: timestamp,
    expires_at: timestamp,
    want_proof: z.boolean(),
  })
  .strict();
export type RequestPayload = z.infer<typeof requestSchema>;
export interface Doc<T = Record<string, unknown>> {
  profile: typeof PROFILE;
  kind: string;
  key_id: string;
  payload: T;
  signature: string;
}
export interface KeyPair {
  private_key: string;
  public_key: string;
}
export interface RuntimeKey {
  id: string;
  org_id: string;
  agent_id: string;
  public_key: string;
  delegation_id: string;
  not_before: number;
  expires_at: number;
}
export interface Delegation extends z.infer<typeof scopeSchema> {
  id: string;
  org_id: string;
  agent_id: string;
  runtime_key_id: string;
  not_before: number;
  expires_at: number;
}
export interface PolicyKey extends z.infer<typeof scopeSchema> {
  id: string;
  org_id: string;
  public_key: string;
  max_ttl: number;
  not_before: number;
  expires_at: number;
}
export interface Policy {
  id: string;
  org_id: string;
  version: number;
  predecessor: string;
  commitment: string;
  predicate: string;
  currency: string;
  asset: string;
  network: string;
  not_before: number;
  expires_at: number;
}
export interface Capability {
  capability_id: string;
  issuer_org: string;
  agent_id: string;
  runtime_key_id: string;
  delegation_id: string;
  action: string;
  resource: string;
  audience: string;
  recipient: string;
  amount_minor_units: number;
  currency: string;
  asset: string;
  network: string;
  request_digest: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  policy_version: string;
  policy_commitment: string;
  proof_program: string;
}
export interface Proof {
  program: string;
  proof: string;
}
export interface Evidence {
  request: Doc<RequestPayload>;
  delegation: Doc<Delegation>;
  capability: Doc<Capability>;
  proof?: Proof;
}
export interface Pins {
  registry_key_id: string;
  registry_public_key: string;
  trusted_roots: Record<string, Record<string, string>>;
}
export interface TrustBundle {
  org_id: string;
  challenge: string;
  issued_at: number;
  expires_at: number;
  active_policy: string;
  roots: Array<{ key_id: string; public_key: string; revoked: boolean }>;
  records: Array<{ document: Doc<any>; revoked: boolean }>;
}
export interface Verification {
  decision: 'allow' | 'deny';
  code: string;
  request_digest: string;
  evidence_digest: string;
  policy_version: string;
  state_issued_at: number;
  valid_until: number;
  trace: string[];
}
export interface Receipt {
  id: string;
  receipt_type: 'authorization' | 'execution' | 'denial';
  org_id: string;
  decision: string;
  code: string;
  request_id: string;
  capability_id: string;
  verifier: string;
  issued_at: number;
  policy_version: string;
  request_digest: string;
  evidence_digest: string;
  trace: string[];
}
export const envelopeSchema = z
  .object({
    profile: z.literal(PROFILE),
    kind: id,
    key_id: id,
    payload: z.record(z.unknown()),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict();
export const evidenceSchema = z
  .object({
    request: envelopeSchema,
    delegation: envelopeSchema,
    capability: envelopeSchema,
    proof: z
      .object({
        program: z.literal(PROGRAM),
        proof: z
          .string()
          .regex(/^[a-f0-9]+$/)
          .max(8192),
      })
      .strict()
      .optional(),
  })
  .strict();

export class PassportError extends Error {
  constructor(
    public code: string,
    public status = 403,
    public detail?: unknown,
  ) {
    super(code);
  }
}
export function assert(condition: unknown, code: string): asserts condition {
  if (!condition) throw new PassportError(code);
}
export function canonical(value: unknown): string {
  const text = canonicalize(value);
  if (text === undefined) throw new PassportError('invalid_request', 400);
  return text;
}
export function digest(value: unknown): string {
  return createHash('sha256').update(canonical(value)).digest('hex');
}
export function now(): number {
  return Math.floor(Date.now() / 1000);
}
export function randomID(prefix: string): string {
  return `${prefix}-${randomBytes(16).toString('hex')}`;
}
export function keys(): KeyPair {
  const pair = generateKeyPairSync('ed25519');
  return {
    private_key: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    public_key: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  };
}
export function sign<T>(kind: string, key_id: string, payload: T, privateKey: string): Doc<T> {
  const header = { profile: PROFILE, kind, key_id, payload };
  return {
    ...header,
    profile: PROFILE,
    signature: edSign(null, Buffer.from(canonical(header)), createPrivateKey(privateKey)).toString(
      'base64url',
    ),
  };
}
export function verify<T>(document: Doc<T>, kind: string, publicKey: string): T {
  assert(envelopeSchema.safeParse(document).success && document.kind === kind, 'invalid_signature');
  const { signature, ...header } = document;
  try {
    assert(
      Buffer.from(signature, 'base64url').toString('base64url') === signature &&
        Buffer.from(publicKey, 'base64url').toString('base64url') === publicKey,
      'invalid_signature',
    );
    const key = createPublicKey({
      key: Buffer.from(publicKey, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    assert(
      key.asymmetricKeyType === 'ed25519' &&
        edVerify(null, Buffer.from(canonical(header)), key, Buffer.from(signature, 'base64url')),
      'invalid_signature',
    );
  } catch {
    throw new PassportError('invalid_signature');
  }
  return document.payload;
}
export function strictJSON(text: string): unknown {
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, { allowTrailingComma: false, disallowComments: true });
  if (!tree || errors.length) throw new PassportError('invalid_request', 400);
  function visit(n: Node): void {
    if (n.type === 'object') {
      const names = new Set<string>();
      for (const p of n.children ?? []) {
        const key = p.children?.[0]?.value;
        if (names.has(key)) throw new PassportError('invalid_request', 400);
        names.add(key);
      }
    }
    for (const child of n.children ?? []) visit(child);
  }
  visit(tree);
  return JSON.parse(text);
}
export function inScope(scope: z.infer<typeof scopeSchema>, r: RequestPayload): boolean {
  return (
    scope.actions.includes(r.action) &&
    scope.resources.includes(r.resource) &&
    scope.audiences.includes(r.audience)
  );
}
export function validWindow(from: number, to: number): boolean {
  return (
    Number.isSafeInteger(from) &&
    Number.isSafeInteger(to) &&
    from > 0 &&
    from <= now() &&
    now() < to
  );
}

export async function http<T>(url: string, body?: unknown, token?: string): Promise<T> {
  const response = await fetch(url, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : canonical(body),
    signal: AbortSignal.timeout(8000),
  }).catch(() => {
    throw new PassportError('unavailable', 503);
  });
  const text = await response.text();
  let data: any;
  try {
    data = strictJSON(text);
  } catch {
    throw new PassportError('unavailable', 503);
  }
  if (!response.ok) throw new PassportError(data.code ?? 'denied', response.status, data);
  return data as T;
}
export async function fetchTrust(registry: string, org: string, pins: Pins): Promise<TrustBundle> {
  assert(id.safeParse(org).success && pins.trusted_roots[org], 'untrusted_issuer');
  const challenge = randomBytes(32).toString('hex');
  const doc = await http<Doc<TrustBundle>>(
    `${registry}/v0/organizations/${encodeURIComponent(org)}/trust?challenge=${challenge}`,
  );
  assert(doc.key_id === pins.registry_key_id, 'invalid_signature');
  const bundle = verify(doc, 'trust_bundle', pins.registry_public_key);
  assert(
    bundle.org_id === org &&
      bundle.challenge === challenge &&
      bundle.expires_at - bundle.issued_at <= 5 &&
      validWindow(bundle.issued_at, bundle.expires_at),
    'stale_state',
  );
  return bundle;
}
export function trustedRecord<T>(
  bundle: TrustBundle,
  pins: Pins,
  kind: string,
  id: string,
): Doc<T> {
  const entry = bundle.records.find(
    (e) => e.document.kind === kind && e.document.payload.id === id,
  );
  assert(entry, 'denied');
  assert(!entry.revoked, 'revoked');
  const keyID = entry.document.key_id,
    publicKey = pins.trusted_roots[bundle.org_id]?.[keyID];
  const root = bundle.roots.find((r) => r.key_id === keyID);
  assert(root && !root.revoked, 'revoked');
  assert(publicKey && root.public_key === publicKey, 'untrusted_issuer');
  verify(entry.document, kind, publicKey);
  return entry.document as Doc<T>;
}
export function verifyRuntime(
  request: Doc<RequestPayload>,
  delegation: Doc<Delegation>,
  bundle: TrustBundle,
  pins: Pins,
): RuntimeKey {
  const r = requestSchema.parse(request.payload);
  assert(r.issuer_org === bundle.org_id, 'untrusted_issuer');
  trustedRecord(bundle, pins, 'organization', r.issuer_org);
  const agent = trustedRecord<{ id: string; org_id: string }>(
    bundle,
    pins,
    'agent',
    r.agent_id,
  ).payload;
  const key = trustedRecord<RuntimeKey>(bundle, pins, 'runtime_key', r.runtime_key_id).payload;
  const d = trustedRecord<Delegation>(bundle, pins, 'delegation', r.delegation_id);
  assert(
    agent.org_id === r.issuer_org &&
      key.org_id === r.issuer_org &&
      key.agent_id === r.agent_id &&
      key.delegation_id === r.delegation_id,
    'denied',
  );
  assert(
    d.payload.org_id === r.issuer_org &&
      d.payload.agent_id === r.agent_id &&
      d.payload.runtime_key_id === r.runtime_key_id &&
      digest(d) === digest(delegation),
    'denied',
  );
  assert(request.key_id === key.id, 'invalid_signature');
  verify(request, 'request', key.public_key);
  assert(
    validWindow(key.not_before, key.expires_at) &&
      validWindow(d.payload.not_before, d.payload.expires_at) &&
      validWindow(r.issued_at, r.expires_at),
    'expired',
  );
  assert(
    r.issued_at >= key.not_before &&
      r.issued_at >= d.payload.not_before &&
      r.expires_at - r.issued_at <= 120 &&
      r.expires_at <= key.expires_at &&
      r.expires_at <= d.payload.expires_at &&
      inScope(d.payload, r),
    'denied',
  );
  return key;
}
