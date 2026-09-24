import { readFile } from 'node:fs/promises';
import { cpus, arch, platform } from 'node:os';
import { AgentClient } from '../sdk/agent.js';
import { digest, http, PROGRAM, type Proof } from '../sdk/wire.js';
import { local, save, workerURL } from './admin.js';
async function main() {
  if (process.env.ENABLE_ZK === '0')
    throw Error('Enable the experimental proof feature before benchmarking.');
  const client = await AgentClient.fromFile(`${local}/agents/codex-local/profile.json`);
  const config = JSON.parse(await readFile(`${local}/acme/authority/config.json`, 'utf8'));
  const evidence = await client.authorize(await client.request(1200, true));
  const proveInput = {
    program: PROGRAM,
    commitment: config.policy.payload.commitment,
    amount_minor_units: 1200,
    context_digest: digest(evidence.capability.payload),
    limit: config.limit,
    blinding: config.blinding,
  };
  const generations: number[] = [],
    verifications: number[] = [];
  let bytes = 0;
  for (let index = 0; index < 11; index++) {
    let t = performance.now();
    const proof = await http<Proof>(`${workerURL}/v0/prove`, proveInput);
    const generation = performance.now() - t;
    t = performance.now();
    const verified = await http<{ valid: boolean }>(
      `${process.env.PROOF_URL ?? 'http://globex-proof:8090'}/v0/verify`,
      {
        program: PROGRAM,
        commitment: proveInput.commitment,
        amount_minor_units: 1200,
        context_digest: proveInput.context_digest,
        proof: proof.proof,
      },
    );
    const verification = performance.now() - t;
    if (!verified.valid) throw Error('Benchmark proof did not verify');
    bytes = proof.proof.length / 2;
    if (index > 0) {
      generations.push(generation);
      verifications.push(verification);
    }
  }
  const stats = (values: number[]) => {
    values.sort((a, b) => a - b);
    return {
      median_ms: +values[Math.floor(values.length / 2)]!.toFixed(2),
      p95_ms: +values[Math.ceil(values.length * 0.95) - 1]!.toFixed(2),
    };
  };
  const report = {
    program: PROGRAM,
    measured_at: new Date().toISOString(),
    cpu: cpus()[0]?.model,
    architecture: arch(),
    platform: platform(),
    build: 'Rust release, Docker Compose, HTTP round trip included',
    samples: 10,
    warmup: 1,
    proof_bytes: bytes,
    proof_hex_bytes: bytes * 2,
    generation: stats(generations),
    verification: stats(verifications),
    interpretation: 'Local measurements only; no production latency or security claim.',
  };
  await save(`${local}/reports/benchmark.json`, report);
  console.log(JSON.stringify(report, null, 2));
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : 'Benchmark failed');
  process.exitCode = 1;
});
