import { readFile } from 'node:fs/promises';
import {
  assert,
  digest,
  fetchTrust,
  http,
  now,
  randomID,
  requestSchema,
  sign,
  verify,
  verifyRuntime,
  type Doc,
  type Delegation,
  type Evidence,
  type Pins,
  type Receipt,
  type RequestPayload,
  type Verification,
} from './wire.js';

export interface AgentProfile {
  agent_id: string;
  org_id: string;
  key_id: string;
  private_key: string;
  delegation: Doc<Delegation>;
  registry_url: string;
  authority_url: string;
  globex_url: string;
  pins: Pins;
}
export interface Challenge {
  nonce: string;
  audience: string;
  action: string;
  resource: string;
  issued_at: number;
  expires_at: number;
}
export interface PurchaseResult {
  decision: 'allow';
  execution_id: string;
  receipt: Doc<Receipt>;
  resource: { title: string; content: string; simulated: true };
}
export class AgentClient {
  constructor(public profile: AgentProfile) {}
  static async fromFile(path: string): Promise<AgentClient> {
    const p = JSON.parse(await readFile(path, 'utf8')) as AgentProfile;
    p.registry_url = process.env.REGISTRY_URL ?? p.registry_url;
    p.authority_url = process.env.AUTHORITY_URL ?? p.authority_url;
    p.globex_url = process.env.GLOBEX_URL ?? p.globex_url;
    return new AgentClient(p);
  }
  async challenge(): Promise<Challenge> {
    return http(`${this.profile.globex_url}/v0/challenges`, {});
  }
  async request(
    amountMinor = 1200,
    proof = false,
    challenge?: Challenge,
  ): Promise<Doc<RequestPayload>> {
    const c = challenge ?? (await this.challenge()),
      p = this.profile;
    const body = {
      sku: 'research-report',
      quantity: 1,
      amount_minor_units: amountMinor,
      currency: 'USD',
      recipient: 'globex',
    };
    return sign(
      'request',
      p.key_id,
      requestSchema.parse({
        request_id: randomID('req'),
        issuer_org: p.org_id,
        agent_id: p.agent_id,
        runtime_key_id: p.key_id,
        delegation_id: p.delegation.payload.id,
        action: c.action,
        resource: c.resource,
        audience: c.audience,
        recipient: 'globex',
        amount_minor_units: amountMinor,
        currency: 'USD',
        asset: 'iso4217:USD',
        network: 'simulation',
        method: 'POST',
        path: '/v0/purchases',
        body,
        nonce: c.nonce,
        issued_at: now(),
        expires_at: Math.min(c.expires_at, now() + 60, p.delegation.payload.expires_at),
        want_proof: proof,
      }),
      p.private_key,
    );
  }
  async identity(): Promise<unknown> {
    const request = await this.request(1, false, {
      nonce: randomID('identity'),
      audience: 'globex',
      action: 'purchase',
      resource: 'globex:research-report',
      issued_at: now(),
      expires_at: now() + 60,
    });
    const bundle = await fetchTrust(
      this.profile.registry_url,
      this.profile.org_id,
      this.profile.pins,
    );
    const key = verifyRuntime(request, this.profile.delegation, bundle, this.profile.pins);
    const remote = await http(`${this.profile.authority_url}/v0/identity`, {
      request,
      delegation: this.profile.delegation,
    });
    return {
      verified: true,
      agent_id: key.agent_id,
      issuer_org: key.org_id,
      runtime_key_id: key.id,
      public_key_fingerprint: digest(key.public_key),
      expires_at: key.expires_at,
      scope: {
        actions: this.profile.delegation.payload.actions,
        resources: this.profile.delegation.payload.resources,
        audiences: this.profile.delegation.payload.audiences,
      },
      authority: remote,
    };
  }
  async authorize(request: Doc<RequestPayload>): Promise<Evidence> {
    const issued = await http<{ capability: Evidence['capability']; proof?: Evidence['proof'] }>(
      `${this.profile.authority_url}/v0/capabilities`,
      { request, delegation: this.profile.delegation },
    );
    return {
      request,
      delegation: this.profile.delegation,
      capability: issued.capability,
      ...(issued.proof ? { proof: issued.proof } : {}),
    };
  }
  async verify(
    amountMinor = 1200,
    proof = false,
  ): Promise<{ verification: Verification; evidence: Evidence }> {
    const evidence = await this.authorize(await this.request(amountMinor, proof));
    return {
      verification: await http<Verification>(`${this.profile.globex_url}/v0/verify`, evidence),
      evidence,
    };
  }
  async execute(evidence: Evidence): Promise<PurchaseResult> {
    const result = await http<PurchaseResult>(`${this.profile.globex_url}/v0/purchases`, evidence);
    const publicKey = this.profile.pins.trusted_roots.globex?.[result.receipt.key_id];
    assert(publicKey, 'untrusted_issuer');
    const receipt = verify(result.receipt, 'receipt', publicKey);
    assert(
      receipt.receipt_type === 'execution' &&
        receipt.request_digest === digest(evidence.request.payload) &&
        receipt.evidence_digest === digest(evidence) &&
        receipt.decision === 'allow',
      'invalid_receipt',
    );
    return result;
  }
  async purchase(amountMinor = 1200, proof = false): Promise<PurchaseResult> {
    return this.execute(await this.authorize(await this.request(amountMinor, proof)));
  }
}
