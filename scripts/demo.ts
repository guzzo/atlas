import { readFile } from 'node:fs/promises';
import { strict as check } from 'node:assert';
import {
  enroll,
  installation,
  local,
  register,
  registryURL,
  revoke,
  save,
  updatePolicy,
  workerURL,
} from './admin.js';
import {
  digest,
  fetchTrust,
  http,
  now,
  PassportError,
  PROGRAM,
  randomID,
  sign,
  type Evidence,
  type Verification,
} from '../sdk/wire.js';

interface Case {
  name: string;
  status: 'passed';
  code: string;
  milliseconds: number;
}
async function main() {
  const results: Case[] = [],
    start = performance.now(),
    i = await installation();
  const client = await enroll(randomID('demo')),
    globex = client.profile.globex_url;
  async function pass(name: string, fn: () => Promise<string>) {
    const t = performance.now();
    const code = await fn();
    results.push({ name, status: 'passed', code, milliseconds: Math.round(performance.now() - t) });
    console.log(`PASS  ${name} → ${code}`);
  }
  async function denied(
    name: string,
    expected: string | Array<string>,
    fn: () => Promise<unknown>,
  ) {
    await pass(name, async () => {
      try {
        await fn();
      } catch (error) {
        if (!(error instanceof PassportError)) throw error;
        check.ok(
          (Array.isArray(expected) ? expected : [expected]).includes(error.code),
          `${name}: expected ${expected}, got ${error.code}`,
        );
        return error.code;
      }
      throw Error(`${name}: unexpectedly allowed`);
    });
  }
  const send = (e: Evidence) => http(`${globex}/v0/purchases`, e),
    verify = (e: Evidence) => http<Verification>(`${globex}/v0/verify`, e);
  const evidence = await client.authorize(await client.request());
  let execution: Awaited<ReturnType<typeof client.execute>>;
  await pass('allowed exact request', async () => {
    execution = await client.execute(evidence);
    check.equal(execution.decision, 'allow');
    return 'allowed';
  });
  await denied('replay of consumed nonce', 'replay', () => send(evidence));
  const pending = await client.authorize(await client.request());
  const tamper = (change: (e: Evidence) => void) => {
    const e = structuredClone(pending);
    change(e);
    return e;
  };
  await denied('edited amount', 'invalid_signature', () =>
    verify(
      tamper((e) => {
        e.request.payload.amount_minor_units++;
      }),
    ),
  );
  await denied('edited body', 'invalid_signature', () =>
    verify(
      tamper((e) => {
        e.request.payload.body.quantity = 2;
      }),
    ),
  );
  await denied('edited recipient', 'invalid_signature', () =>
    verify(
      tamper((e) => {
        e.capability.payload.recipient = 'mallory';
      }),
    ),
  );
  await denied('edited resource', 'invalid_signature', () =>
    verify(
      tamper((e) => {
        e.capability.payload.resource = 'globex:secrets';
      }),
    ),
  );
  await denied('edited policy version', 'invalid_signature', () =>
    verify(
      tamper((e) => {
        e.capability.payload.policy_version = 'policy-forged';
      }),
    ),
  );
  await denied('forged capability signature', 'invalid_signature', () =>
    verify(
      tamper((e) => {
        e.capability.signature =
          (e.capability.signature[0] === 'A' ? 'B' : 'A') + e.capability.signature.slice(1);
      }),
    ),
  );
  await denied('wrong audience', 'denied', () =>
    verify(
      tamper((e) => {
        e.request = sign(
          'request',
          client.profile.key_id,
          { ...e.request.payload, audience: 'mallory' },
          client.profile.private_key,
        );
      }),
    ),
  );
  await denied('re-signed altered request against old capability', 'request_mismatch', () =>
    verify(
      tamper((e) => {
        e.request = sign(
          'request',
          client.profile.key_id,
          {
            ...e.request.payload,
            amount_minor_units: 1201,
            body: { ...e.request.payload.body, amount_minor_units: 1201 },
          },
          client.profile.private_key,
        );
      }),
    ),
  );
  await denied('untrusted issuer', 'untrusted_issuer', () =>
    verify(
      tamper((e) => {
        e.request = sign(
          'request',
          client.profile.key_id,
          { ...e.request.payload, issuer_org: 'unknown-org' },
          client.profile.private_key,
        );
      }),
    ),
  );
  await denied('expired capability', 'expired', () =>
    verify(
      tamper((e) => {
        e.capability = sign(
          'capability',
          'acme-policy-1',
          { ...e.capability.payload, issued_at: now() - 61, expires_at: now() - 1 },
          i.policy.private_key,
        );
      }),
    ),
  );
  await denied('expired request', 'expired', () =>
    verify(
      tamper((e) => {
        e.request = sign(
          'request',
          client.profile.key_id,
          { ...e.request.payload, issued_at: now() - 61, expires_at: now() - 1 },
          client.profile.private_key,
        );
      }),
    ),
  );
  await denied('admin endpoint without credential', 'unauthorized', () =>
    http(
      `${registryURL}/v0/agents`,
      sign(
        'agent',
        'acme-root-1',
        { id: randomID('forged'), org_id: 'acme', name: 'forged', created_at: now() },
        client.profile.private_key,
      ),
    ),
  );
  await denied('runtime cannot sign an admin mutation', 'invalid_signature', () =>
    register(
      '/v0/agents',
      sign(
        'agent',
        'acme-root-1',
        { id: randomID('forged'), org_id: 'acme', name: 'forged', created_at: now() },
        client.profile.private_key,
      ),
      i.tokens.acme,
    ),
  );
  await denied('Globex rejects a valid capability outside its own rules', 'denied', () =>
    verify(
      tamper((e) => {
        e.request = sign(
          'request',
          client.profile.key_id,
          {
            ...e.request.payload,
            amount_minor_units: 100001,
            body: { ...e.request.payload.body, amount_minor_units: 100001 },
          },
          client.profile.private_key,
        );
        e.capability = sign(
          'capability',
          'acme-policy-1',
          {
            ...e.capability.payload,
            amount_minor_units: 100001,
            request_digest: digest(e.request.payload),
          },
          i.policy.private_key,
        );
      }),
    ),
  );
  const concurrent = await client.authorize(await client.request());
  await pass('eight concurrent copies execute exactly once', async () => {
    const attempts = await Promise.allSettled(Array.from({ length: 8 }, () => send(concurrent)));
    check.equal(attempts.filter((r) => r.status === 'fulfilled').length, 1);
    for (const a of attempts) {
      if (a.status === 'rejected') check.equal((a.reason as PassportError).code, 'replay');
    }
    return '1 execution / 7 replay denials';
  });
  const privatePolicy = JSON.parse(await readFile(`${local}/acme/authority/config.json`, 'utf8'));
  await denied('Cedar denies amount over private limit', 'denied', async () =>
    client.authorize(await client.request(privatePolicy.limit + 1)),
  );
  let proofEvidence: Evidence | undefined;
  if (process.env.ENABLE_ZK !== '0') {
    proofEvidence = await client.authorize(await client.request(1200, true));
    await pass('valid hidden-limit proof', async () => {
      const v = await verify(proofEvidence!);
      check.ok(v.trace.includes('hidden_limit_range_proof'));
      return 'allowed';
    });
    const forged = structuredClone(proofEvidence);
    forged.proof!.proof =
      (forged.proof!.proof[0] === '0' ? '1' : '0') + forged.proof!.proof.slice(1);
    await denied('forged range proof', 'invalid_proof', () => verify(forged));
    const other = await client.authorize(await client.request(1200, true));
    other.proof = proofEvidence.proof;
    await denied('proof transplanted onto a different request', 'invalid_proof', () =>
      verify(other),
    );
    const missing = structuredClone(proofEvidence);
    delete missing.proof;
    await denied('required proof missing', 'invalid_proof', () => verify(missing));
    const easier = structuredClone(proofEvidence);
    easier.proof!.program = 'unapproved.easier-program';
    await denied('prover cannot substitute a different proof program', 'invalid_request', () =>
      verify(easier),
    );
    await denied('prover rejects over-limit witness', 'denied', () =>
      http(`${workerURL}/v0/prove`, {
        program: PROGRAM,
        commitment: privatePolicy.policy.payload.commitment,
        amount_minor_units: privatePolicy.limit + 1,
        context_digest: digest(proofEvidence!.capability.payload),
        limit: privatePolicy.limit,
        blinding: privatePolicy.blinding,
      }),
    );
    await pass('proof-backed simulated execution', async () => {
      await client.execute(proofEvidence!);
      return 'allowed';
    });
  }
  const stale = await client.authorize(await client.request(1200, process.env.ENABLE_ZK !== '0'));
  await updatePolicy(privatePolicy.limit);
  await denied('policy update rejects previous commitment', 'policy_mismatch', () => verify(stale));
  await pass('fresh authorization after policy update', async () => {
    await client.purchase();
    return 'allowed';
  });
  const disposable = await enroll(randomID('revoked-key')),
    keyEvidence = await disposable.authorize(await disposable.request());
  await revoke('runtime_key', disposable.profile.key_id);
  await denied('revoked runtime key', 'revoked', () => send(keyEvidence));
  const delegated = await enroll(randomID('revoked-delegation')),
    delEvidence = await delegated.authorize(await delegated.request());
  await revoke('delegation', delegated.profile.delegation.payload.id);
  await denied('revoked delegation', 'revoked', () => send(delEvidence));
  const rotating = await enroll(randomID('renewal')),
    oldEvidence = await rotating.authorize(await rotating.request());
  const oldBundle = await fetchTrust(registryURL, 'acme', rotating.profile.pins),
    oldKey = oldBundle.records.find(
      (r) => r.document.kind === 'runtime_key' && r.document.payload.id === rotating.profile.key_id,
    )!.document;
  const renewed = await enroll(rotating.profile.agent_id, true);
  await denied('runtime renewal revokes old credentials', 'revoked', () => send(oldEvidence));
  await pass('renewed runtime can execute', async () => {
    await renewed.purchase();
    return 'allowed';
  });
  await denied('revoked key ID cannot be resurrected', 'conflict', () =>
    register(`/v0/agents/${rotating.profile.agent_id}/keys`, oldKey, i.tokens.acme),
  );
  const report = {
    profile: 'passport.v0.ed25519-jcs',
    completed_at: new Date().toISOString(),
    passed: results.length,
    failed: 0,
    zk_enabled: process.env.ENABLE_ZK !== '0',
    duration_ms: Math.round(performance.now() - start),
    cases: results,
    example_receipt: execution!.receipt,
    remaining_limitations: [
      'local development keys',
      'online registry trust and five-second freshness',
      'per-transaction limit only',
      'no real payment',
      'not independently audited',
    ],
  };
  await save(`${local}/reports/demo.json`, report);
  console.log(`\n${results.length} acceptance cases passed. Report: .local/reports/demo.json`);
  console.log(
    JSON.stringify(
      {
        verification_trace: execution!.receipt.payload.trace,
        receipt_id: execution!.receipt.payload.id,
        request_digest: execution!.receipt.payload.request_digest,
      },
      null,
      2,
    ),
  );
}
main().catch((error) => {
  console.error('Demo failed:', error instanceof Error ? error.message : 'unknown');
  process.exitCode = 1;
});
