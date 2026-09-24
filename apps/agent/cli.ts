import { AgentClient } from '../../sdk/agent.js';
import { PassportError } from '../../sdk/wire.js';
import { enroll, local, revoke, save, updatePolicy } from '../../scripts/admin.js';
async function main() {
  const [command, name = 'codex-local', amountText = '1200', ...flags] = process.argv.slice(2);
  if (command === 'enroll' || command === 'renew') {
    const client = await enroll(name, command === 'renew');
    console.log(
      JSON.stringify(
        {
          enrolled: true,
          agent_id: client.profile.agent_id,
          runtime_key_id: client.profile.key_id,
          expires_at: client.profile.delegation.payload.expires_at,
        },
        null,
        2,
      ),
    );
    return;
  }
  if (command === 'revoke') {
    await revoke(name, amountText);
    console.log(JSON.stringify({ revoked: true, kind: name, id: amountText }));
    return;
  }
  if (command === 'policy') {
    const policy = await updatePolicy(Number(name));
    console.log(
      JSON.stringify({ active_policy: policy.payload.id, version: policy.payload.version }),
    );
    return;
  }
  const client = await AgentClient.fromFile(`${local}/agents/${name}/profile.json`);
  const proof = flags.includes('--proof') || amountText === '--proof',
    amount = amountText === '--proof' ? 1200 : Number(amountText);
  if (command === 'identity') console.log(JSON.stringify(await client.identity(), null, 2));
  else if (command === 'verify') {
    const result = await client.verify(amount, proof);
    await save(`${local}/reports/last-evidence.json`, result.evidence);
    console.log(
      JSON.stringify(
        {
          verified: true,
          executed: false,
          ...result.verification,
          evidence_file: '.local/reports/last-evidence.json',
        },
        null,
        2,
      ),
    );
  } else if (command === 'purchase')
    console.log(JSON.stringify(await client.purchase(amount, proof), null, 2));
  else throw new Error('Unknown command');
}
main().catch((error) => {
  console.error(
    JSON.stringify({
      code: error instanceof PassportError ? error.code : 'error',
      message: error instanceof Error ? error.message : 'failed',
    }),
  );
  process.exitCode = 1;
});
