#!/usr/bin/env node
// kunji MCP bridge — lets an AI runtime (Claude Code / Claude Desktop) act for a user at
// an app via a user-authorized, scoped, expiring CAPABILITY — never the user's keys.
//
// Flow: kunji_authorize → (user approves in the wallet) → kunji_set_capability → kunji_login.
// See ../../docs/agentic-delegation.md.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { agentRequest, setCapability, currentCapability, login } from './capability-client.js';

const server = new McpServer({ name: 'kunji', version: '0.1.0' });

const text = (t) => ({ content: [{ type: 'text', text: t }] });
const fail = (e) => ({ content: [{ type: 'text', text: `Error: ${e.message || e}` }], isError: true });

server.registerTool(
  'kunji_authorize',
  {
    title: 'Request kunji authorization',
    description:
      'Begin authorization to act for the user at an app. Returns a request the USER must approve ' +
      'in their kunji wallet (Security → Authorize an agent). After they approve, they paste the ' +
      'capability back via kunji_set_capability. The agent never receives the user\'s keys.',
    inputSchema: {
      audience: z.string().describe("The app's domain to act at, e.g. 'example.com'."),
      scope: z.array(z.string()).optional().describe("Requested scopes, e.g. ['login']. Defaults to ['login']."),
    },
  },
  async ({ audience, scope }) => {
    try {
      const req = agentRequest(audience, scope);
      return text(
        `Ask the user to authorize this in their kunji wallet → Security → "Authorize an agent" ` +
          `(scan or paste), then approve and paste the capability back to you for kunji_set_capability:\n\n` +
          JSON.stringify(req),
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'kunji_set_capability',
  {
    title: 'Store an authorized capability',
    description:
      'Store the capability the user got from their kunji wallet after approving kunji_authorize. ' +
      'Validated against this agent\'s key (holder-of-key) and expiry before it is accepted.',
    inputSchema: { capability: z.string().describe('The capability token (JWT) from the wallet.') },
  },
  async ({ capability }) => {
    try {
      const cap = setCapability(capability);
      return text(
        `Capability stored. audience=${cap.audience}, scope=${JSON.stringify(cap.scope)}, ` +
          `expires=${new Date(cap.exp * 1000).toISOString()}. You can now kunji_login.`,
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'kunji_login',
  {
    title: 'Sign in with kunji (as the authorized agent)',
    description:
      'Use the stored capability to sign in at the relying party: creates a session, signs its ' +
      'challenge with the agent key (holder-of-key), and submits it. Returns the verified sub + scope.',
    inputSchema: {
      baseUrl: z.string().describe("The RP base URL, e.g. 'https://kunji-demo.web.app'."),
    },
  },
  async ({ baseUrl }) => {
    try {
      const r = await login(baseUrl);
      return text(JSON.stringify(r));
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'kunji_status',
  {
    title: 'Show kunji agent status',
    description: "Show this agent's public key and whether a capability is loaded (audience, scope, expiry).",
    inputSchema: {},
  },
  async () => {
    try {
      return text(JSON.stringify(currentCapability(), null, 2));
    } catch (e) {
      return fail(e);
    }
  },
);

const transport = new StdioServerTransport();
server.connect(transport).catch((err) => {
  console.error('kunji MCP server failed to start:', err);
  process.exit(1);
});
