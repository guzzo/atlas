import { mkdir, writeFile } from 'node:fs/promises';
const string = { type: 'string' },
  id = { type: 'string', pattern: '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,127}$' },
  time = { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
  number = { type: 'integer', minimum: 1, maximum: 4294967295 };
const literal = (v) => ({ type: 'string', const: v });
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const object = (properties) => ({
  type: 'object',
  additionalProperties: false,
  required: Object.keys(properties),
  properties,
});
const array = (items) => ({ type: 'array', items });
const scopedIDs = { ...array(id), minItems: 1, maxItems: 32 };
const scope = { actions: scopedIDs, resources: scopedIDs, audiences: scopedIDs };
const window = { not_before: time, expires_at: time };
const units = {
  currency: literal('USD'),
  asset: literal('iso4217:USD'),
  network: literal('simulation'),
};
const binding = {
  issuer_org: id,
  agent_id: id,
  runtime_key_id: id,
  delegation_id: id,
  action: id,
  resource: id,
  audience: id,
  recipient: id,
  amount_minor_units: number,
  ...units,
};
const signed = (payload, kind) =>
  object({
    profile: literal('passport.v0.ed25519-jcs'),
    kind: kind ? literal(kind) : id,
    key_id: id,
    payload,
    signature: { type: 'string', pattern: '^[A-Za-z0-9_-]{86}$' },
  });
const schemas = {
  Error: object({
    code: {
      type: 'string',
      enum: [
        'invalid_request',
        'invalid_signature',
        'expired',
        'revoked',
        'replay',
        'policy_mismatch',
        'untrusted_issuer',
        'denied',
        'request_mismatch',
        'invalid_proof',
        'invalid_nonce',
        'stale_state',
        'unavailable',
        'unauthorized',
        'conflict',
        'not_found',
        'feature_disabled',
      ],
    },
  }),
  Health: object({ status: string }),
  Created: object({ id }),
  Organization: object({ id, name: string, root_key_id: id, public_key: string, created_at: time }),
  Agent: object({ id, org_id: id, name: string, created_at: time }),
  RuntimeKey: object({
    id,
    org_id: id,
    agent_id: id,
    public_key: string,
    delegation_id: id,
    ...window,
  }),
  Delegation: object({ id, org_id: id, agent_id: id, runtime_key_id: id, ...scope, ...window }),
  PolicyKey: object({
    id,
    org_id: id,
    public_key: string,
    ...scope,
    max_ttl: { type: 'integer', minimum: 1, maximum: 60 },
    ...window,
  }),
  Policy: object({
    id,
    org_id: id,
    version: { type: 'integer', minimum: 1 },
    predecessor: string,
    commitment: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    predicate: literal('passport.hidden-limit.bp5.ristretto.32x2.v1'),
    ...units,
    ...window,
  }),
  Request: object({
    request_id: id,
    ...binding,
    method: literal('POST'),
    path: literal('/v0/purchases'),
    body: { type: 'object', additionalProperties: true },
    nonce: { ...id, minLength: 32 },
    issued_at: time,
    expires_at: time,
    want_proof: { type: 'boolean' },
  }),
  Capability: object({
    capability_id: id,
    ...binding,
    request_digest: string,
    nonce: id,
    issued_at: time,
    expires_at: time,
    policy_version: id,
    policy_commitment: string,
    proof_program: string,
  }),
  Revocation: object({
    id,
    org_id: id,
    target_kind: {
      type: 'string',
      enum: [
        'organization',
        'root_key',
        'agent',
        'runtime_key',
        'delegation',
        'policy_key',
        'policy',
      ],
    },
    target_id: id,
    issued_at: time,
  }),
  Rotation: object({ id, org_id: id, previous_key_id: id, public_key: string, issued_at: time }),
  Receipt: object({
    id,
    receipt_type: { type: 'string', enum: ['authorization', 'execution', 'denial'] },
    org_id: id,
    decision: string,
    code: string,
    request_id: id,
    capability_id: id,
    verifier: id,
    issued_at: time,
    policy_version: id,
    request_digest: string,
    evidence_digest: string,
    trace: array(string),
  }),
  Proof: object({
    program: literal('passport.hidden-limit.bp5.ristretto.32x2.v1'),
    proof: { type: 'string', pattern: '^[a-f0-9]+$', maxLength: 8192 },
  }),
  SignedDocument: signed({ type: 'object', additionalProperties: true }),
  Verification: object({
    decision: { type: 'string', enum: ['allow', 'deny'] },
    code: string,
    request_digest: string,
    evidence_digest: string,
    policy_version: string,
    state_issued_at: time,
    valid_until: time,
    trace: array(string),
  }),
  Challenge: object({
    nonce: string,
    audience: id,
    action: id,
    resource: id,
    issued_at: time,
    expires_at: time,
  }),
  Empty: object({}),
};
for (const [name, kind] of Object.entries({
  Organization: 'organization',
  Agent: 'agent',
  RuntimeKey: 'runtime_key',
  Delegation: 'delegation',
  PolicyKey: 'policy_key',
  Policy: 'policy',
  Request: 'request',
  Capability: 'capability',
  Revocation: 'revocation',
  Rotation: 'root_rotation',
  Receipt: 'receipt',
}))
  schemas[`Signed${name}`] = signed(ref(name), kind);
schemas.TrustBundle = object({
  org_id: id,
  challenge: string,
  issued_at: time,
  expires_at: time,
  active_policy: string,
  roots: array(object({ key_id: id, public_key: string, revoked: { type: 'boolean' } })),
  records: array(object({ document: ref('SignedDocument'), revoked: { type: 'boolean' } })),
});
schemas.SignedTrustBundle = signed(ref('TrustBundle'), 'trust_bundle');
schemas.Evidence = {
  ...object({
    request: ref('SignedRequest'),
    delegation: ref('SignedDelegation'),
    capability: ref('SignedCapability'),
    proof: ref('Proof'),
  }),
  required: ['request', 'delegation', 'capability'],
};
schemas.AuthorizationInput = object({
  request: ref('SignedRequest'),
  delegation: ref('SignedDelegation'),
});
schemas.AuthorizationResult = {
  ...object({
    capability: ref('SignedCapability'),
    proof: ref('Proof'),
    authorization_receipt: ref('SignedReceipt'),
  }),
  required: ['capability', 'authorization_receipt'],
};
schemas.PurchaseResult = object({
  decision: literal('allow'),
  execution_id: id,
  receipt: ref('SignedReceipt'),
  resource: object({ title: string, content: string, simulated: { const: true, type: 'boolean' } }),
});
schemas.Overview = object({
  organizations: array(object({ id, active_policy: string })),
  records: array(
    object({
      org_id: id,
      kind: id,
      id,
      revoked: { type: 'boolean' },
      document: ref('SignedDocument'),
    }),
  ),
  profile: string,
  freshness_seconds: { type: 'integer' },
});
schemas.Identity = object({
  verified: { type: 'boolean' },
  agent_id: id,
  runtime_key_id: id,
  checked_at: time,
});
schemas.Event = object({
  id: { type: 'integer' },
  topic: string,
  object_id: id,
  evidence_digest: string,
});
const json = (schema) => ({ 'application/json': { schema } });
const paths = {};
function endpoint(
  path,
  method,
  operationId,
  summary,
  input,
  output,
  port = 8080,
  admin = false,
  status = '200',
  params = [],
) {
  paths[path] ??= {};
  paths[path][method] = {
    operationId,
    summary,
    servers: [{ url: `http://127.0.0.1:${port}` }],
    ...(admin ? { security: [{ AdminBearer: [] }] } : {}),
    ...(params.length ? { parameters: params } : {}),
    ...(input ? { requestBody: { required: true, content: json(ref(input)) } } : {}),
    responses: {
      [status]: {
        description: 'Success',
        content: json(typeof output === 'string' ? ref(output) : output),
      },
      400: { description: 'Malformed input', content: json(ref('Error')) },
      401: { description: 'Administrator credential required', content: json(ref('Error')) },
      403: {
        description: 'Verification denied; may include a signed denial receipt',
        content: json({ type: 'object', additionalProperties: true }),
      },
      409: {
        description: 'Immutable ID conflict or concurrent update',
        content: json(ref('Error')),
      },
      503: { description: 'Dependency unavailable; fail closed', content: json(ref('Error')) },
    },
  };
}
const pathID = { name: 'id', in: 'path', required: true, schema: id };
endpoint('/healthz', 'get', 'health', 'Service health', null, 'Health');
for (const [path, input, op] of [
  ['/v0/organizations', 'SignedOrganization', 'registerOrganization'],
  ['/v0/agents', 'SignedAgent', 'registerAgent'],
  ['/v0/agents/{id}/keys', 'SignedRuntimeKey', 'bindRuntimeKey'],
  ['/v0/delegations', 'SignedDelegation', 'registerDelegation'],
  ['/v0/policy-keys', 'SignedPolicyKey', 'delegatePolicySigner'],
  ['/v0/policies', 'SignedPolicy', 'activatePolicy'],
  ['/v0/revocations', 'SignedRevocation', 'revoke'],
  ['/v0/organizations/{id}/rotations', 'SignedRotation', 'rotateRoot'],
  ['/v0/receipts', 'SignedReceipt', 'recordAuthorizationReceipt'],
])
  endpoint(
    path,
    'post',
    op,
    op,
    input,
    'Created',
    8080,
    true,
    '201',
    path.includes('{id}') ? [pathID] : [],
  );
endpoint(
  '/v0/organizations/{id}/trust',
  'get',
  'getTrust',
  'Fresh signed public state. Verifiers must supply a random challenge and enforce its five-second lifetime.',
  null,
  'SignedTrustBundle',
  8080,
  false,
  '200',
  [
    pathID,
    {
      name: 'challenge',
      in: 'query',
      required: true,
      schema: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    },
  ],
);
endpoint('/v0/overview', 'get', 'overview', 'Public local registry overview', null, 'Overview');
endpoint(
  '/v0/receipts',
  'get',
  'receipts',
  'Recent public authorization receipts (Globex serves execution/denial receipts at the same path on port 8081)',
  null,
  array(ref('SignedReceipt')),
);
endpoint(
  '/v0/events',
  'get',
  'events',
  'Transactional outbox cursor feed',
  null,
  array(ref('Event')),
  8080,
  true,
  '200',
  [
    { name: 'org_id', in: 'query', required: true, schema: id },
    { name: 'after', in: 'query', schema: { type: 'integer', minimum: 0 } },
  ],
);
endpoint(
  '/v0/challenges',
  'post',
  'challenge',
  'Create a Globex single-use challenge',
  'Empty',
  'Challenge',
  8081,
  false,
  '201',
);
endpoint(
  '/v0/capabilities',
  'post',
  'authorize',
  'Acme evaluates Cedar and signs an exact-request capability; runtime proof is required',
  'AuthorizationInput',
  'AuthorizationResult',
  8082,
  false,
  '201',
);
endpoint(
  '/v0/identity',
  'post',
  'identity',
  'Acme verifies runtime identity without issuing authority',
  'AuthorizationInput',
  'Identity',
  8082,
);
endpoint(
  '/v0/verify',
  'post',
  'verify',
  'Dry-run verification. Globex applies its own rules. The Go verifier on port 8083 verifies evidence only. Neither consumes a nonce.',
  'Evidence',
  'Verification',
  8081,
);
endpoint(
  '/v0/purchases',
  'post',
  'purchase',
  'Atomically consume challenge and execute one simulated purchase',
  'Evidence',
  'PurchaseResult',
  8081,
  false,
  '201',
);
const spec = {
  openapi: '3.1.0',
  info: {
    title: 'Passport local proof of concept',
    version: '0.1.0',
    description:
      'Experimental Ed25519/JCS agent authority protocol. Acme issues capabilities; Globex makes the final decision. See docs/protocol.md for signing rules and docs/threat-model.md for trusted state and outage semantics.',
  },
  servers: [
    { url: 'http://127.0.0.1:8080', description: 'Registry' },
    { url: 'http://127.0.0.1:8081', description: 'Globex' },
    { url: 'http://127.0.0.1:8082', description: 'Acme authority' },
    { url: 'http://127.0.0.1:8083', description: 'Independent Go verifier' },
  ],
  paths,
  components: {
    securitySchemes: {
      AdminBearer: {
        type: 'http',
        scheme: 'bearer',
        description:
          'Random per-organization local administrator credential; organization creation uses a separate bootstrap credential. Signed mutations are also required.',
      },
    },
    schemas,
  },
};
await mkdir('api', { recursive: true });
await writeFile('api/openapi.json', JSON.stringify(spec, null, 2) + '\n');
