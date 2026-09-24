import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { AgentClient } from '../../sdk/agent.js';
import { http, PassportError } from '../../sdk/wire.js';

const client = await AgentClient.fromFile(
  process.env.PROFILE_FILE ?? '.local/agents/codex-local/profile.json',
);
const server = new McpServer(
  { name: 'passport', version: '0.1.0' },
  {
    instructions:
      'Passport is a local agent-identity and authorization demo. First call passport_identity to verify this runtime. Use passport_verify for a dry run, or passport_purchase only when the user requests the simulated purchase. Amounts are integer USD cents. No real funds move. Runtime credentials cannot administer organizations or change policies. Never expose private keys.',
  },
);
const inputSchema = {
  amount_minor_units: z
    .number()
    .int()
    .positive()
    .max(4294967295)
    .default(1200)
    .describe('Amount in integer USD cents; no decimals.'),
  proof: z.boolean().default(false).describe('Request the experimental hidden-limit proof.'),
};
function tool(
  fn: () => Promise<unknown>,
): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
  return fn()
    .then((data) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] }))
    .catch((error) => ({
      isError: true,
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify({
            code: error instanceof PassportError ? error.code : 'unavailable',
          }),
        },
      ],
    }));
}
server.registerTool(
  'passport_identity',
  {
    description:
      'Verify the runtime key, organization binding and live delegation of this local agent.',
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  () => tool(() => client.identity()),
);
server.registerTool(
  'passport_verify',
  {
    description:
      'Obtain an Acme capability and independently verify it at Globex without executing a purchase. Produces an authorization audit receipt.',
    inputSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  },
  ({ amount_minor_units, proof }) =>
    tool(async () => ({
      executed: false,
      ...(await client.verify(amount_minor_units, proof)).verification,
    })),
);
server.registerTool(
  'passport_purchase',
  {
    description:
      'Execute a simulated Globex research-report purchase after live authorization checks. No real funds move. Produces a signed execution receipt.',
    inputSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  },
  ({ amount_minor_units, proof }) => tool(() => client.purchase(amount_minor_units, proof)),
);
server.registerTool(
  'passport_receipts',
  {
    description:
      'Read recent public demonstration receipts from Globex; includes all local demo agents.',
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  () => tool(() => http(`${client.profile.globex_url}/v0/receipts`)),
);
await server.connect(new StdioServerTransport());
