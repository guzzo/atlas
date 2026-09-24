import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { strict as assert } from 'node:assert';
import { resolve } from 'node:path';
const transport = new StdioClientTransport({
  command: resolve('bin/passport'),
  args: ['mcp', 'codex-local'],
  stderr: 'inherit',
});
const client = new Client({ name: 'passport-smoke', version: '0.1.0' });
try {
  await client.connect(transport);
  const list = await client.listTools();
  assert.equal(list.tools.length, 4);
  for (const name of ['passport_identity', 'passport_verify']) {
    const result = await client.callTool({
      name,
      arguments: name === 'passport_verify' ? { amount_minor_units: 1200, proof: true } : {},
    });
    assert.ok(!result.isError, JSON.stringify(result));
    console.log(`${name}: verified via real MCP stdio transport`);
  }
} finally {
  await client.close();
}
