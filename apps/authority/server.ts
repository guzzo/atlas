import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { body, send, serve } from '../shared/http.js';
import {
  assert,
  digest,
  envelopeSchema,
  fetchTrust,
  http,
  inScope,
  now,
  randomID,
  requestSchema,
  sign,
  trustedRecord,
  validWindow,
  verifyRuntime,
  PROGRAM,
  type Capability,
  type Delegation,
  type Doc,
  type Pins,
  type Policy,
  type PolicyKey,
  type Proof,
  type Receipt,
  type RequestPayload,
} from '../../sdk/wire.js';

export interface AuthorityConfig {
  org_id: string;
  policy_key_id: string;
  policy: Doc<Policy>;
  limit: number;
  blinding: string;
}
const registry = process.env.REGISTRY_URL ?? 'http://registry:8080',
  worker = process.env.WORKER_URL ?? 'http://acme-worker:8090';
const base = process.env.AUTHORITY_DIR ?? '/authority';
const pins = JSON.parse(
  await readFile(process.env.TRUST_FILE ?? '/public/trust.json', 'utf8'),
) as Pins;
const privateKey = await readFile(`${base}/policy.pem`, 'utf8'),
  token = (await readFile(`${base}/admin.token`, 'utf8')).trim();
const inputSchema = z.object({ request: envelopeSchema, delegation: envelopeSchema }).strict();
serve(8082, async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    send(res, 200, { status: 'ok' });
    return;
  }
  if (req.method !== 'POST' || !['/v0/capabilities', '/v0/identity'].includes(req.url ?? '')) {
    send(res, 404, { code: 'not_found' });
    return;
  }
  const input = inputSchema.parse(await body(req));
  const request = input.request as unknown as Doc<RequestPayload>,
    delegation = input.delegation as unknown as Doc<Delegation>;
  const r = requestSchema.parse(request.payload);
  assert(r.issuer_org === 'acme', 'untrusted_issuer');
  const bundle = await fetchTrust(registry, r.issuer_org, pins);
  verifyRuntime(request, delegation, bundle, pins);
  if (req.url === '/v0/identity') {
    send(res, 200, {
      verified: true,
      agent_id: r.agent_id,
      runtime_key_id: r.runtime_key_id,
      checked_at: now(),
    });
    return;
  }
  const config = JSON.parse(await readFile(`${base}/config.json`, 'utf8')) as AuthorityConfig;
  const policy = trustedRecord<Policy>(bundle, pins, 'policy', bundle.active_policy),
    pk = trustedRecord<PolicyKey>(bundle, pins, 'policy_key', config.policy_key_id).payload;
  assert(
    digest(policy) === digest(config.policy) && config.org_id === r.issuer_org,
    'policy_mismatch',
  );
  assert(
    inScope(pk, r) &&
      validWindow(pk.not_before, pk.expires_at) &&
      validWindow(policy.payload.not_before, policy.payload.expires_at),
    'expired',
  );
  assert(
    r.body.amount_minor_units === r.amount_minor_units &&
      r.body.currency === r.currency &&
      r.body.recipient === r.recipient &&
      r.body.sku === 'research-report' &&
      r.body.quantity === 1,
    'request_mismatch',
  );
  const decision = await http<{ allowed: boolean }>(`${worker}/v0/decide`, {
    agent_id: r.agent_id,
    action: r.action,
    resource: r.resource,
    audience: r.audience,
    recipient: r.recipient,
    currency: r.currency,
    asset: r.asset,
    network: r.network,
    amount_minor_units: r.amount_minor_units,
    limit: config.limit,
  });
  assert(decision.allowed, 'denied');
  assert(!r.want_proof || process.env.ENABLE_ZK !== '0', 'feature_disabled');
  const capability: Capability = {
    capability_id: randomID('cap'),
    issuer_org: r.issuer_org,
    agent_id: r.agent_id,
    runtime_key_id: r.runtime_key_id,
    delegation_id: r.delegation_id,
    action: r.action,
    resource: r.resource,
    audience: r.audience,
    recipient: r.recipient,
    amount_minor_units: r.amount_minor_units,
    currency: r.currency,
    asset: r.asset,
    network: r.network,
    request_digest: digest(r),
    nonce: r.nonce,
    issued_at: now(),
    expires_at: Math.min(
      r.expires_at,
      now() + pk.max_ttl,
      pk.expires_at,
      policy.payload.expires_at,
    ),
    policy_version: policy.payload.id,
    policy_commitment: policy.payload.commitment,
    proof_program: r.want_proof ? PROGRAM : '',
  };
  let proof: Proof | undefined;
  if (r.want_proof)
    proof = await http<Proof>(`${worker}/v0/prove`, {
      program: PROGRAM,
      commitment: policy.payload.commitment,
      amount_minor_units: r.amount_minor_units,
      context_digest: digest(capability),
      limit: config.limit,
      blinding: config.blinding,
    });
  // A second live read prevents issuance from a stale snapshot after a slow proof.
  const fresh = await fetchTrust(registry, r.issuer_org, pins);
  verifyRuntime(request, delegation, fresh, pins);
  trustedRecord(fresh, pins, 'policy_key', config.policy_key_id);
  trustedRecord(fresh, pins, 'policy', policy.payload.id);
  assert(fresh.active_policy === policy.payload.id, 'policy_mismatch');
  assert(capability.expires_at > now(), 'expired');
  const signed = sign('capability', config.policy_key_id, capability, privateKey);
  const receipt: Receipt = {
    id: randomID('authz'),
    receipt_type: 'authorization',
    org_id: r.issuer_org,
    decision: 'allow',
    code: 'authorized',
    request_id: r.request_id,
    capability_id: capability.capability_id,
    verifier: 'acme-authority',
    issued_at: now(),
    policy_version: policy.payload.id,
    request_digest: digest(r),
    evidence_digest: digest(signed),
    trace: [
      'runtime_verified',
      'cedar_allow',
      'request_bound_capability',
      ...(proof ? ['hidden_limit_proof'] : []),
    ],
  };
  await http(
    `${registry}/v0/receipts`,
    sign('receipt', config.policy_key_id, receipt, privateKey),
    token,
  );
  send(res, 201, {
    capability: signed,
    ...(proof ? { proof } : {}),
    authorization_receipt: sign('receipt', config.policy_key_id, receipt, privateKey),
  });
});
