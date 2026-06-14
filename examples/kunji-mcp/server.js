#!/usr/bin/env node
// kunji MCP bridge — lets an AI runtime (Claude Code / Claude Desktop) act for a user at
// an app via a user-authorized, scoped, expiring CAPABILITY — never the user's keys.
//
// Flow: kunji_authorize → (user approves in the wallet) → kunji_await_capability → kunji_login.
// Mid-task, an app may return 403 insufficient_scope → kunji_stepup asks the user for more access
// (incl. having them present a verified credential via a vc: scope). A channel-less agent the user
// enabled notifications for can nudge the wallet with kunji_request_via_push. See ../../docs/agentic-delegation.md.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  agentRequest,
  postAgentRequest,
  requestQr,
  setCapability,
  currentCapability,
  login,
  awaitCapability,
  stepUp,
  requestViaPush,
} from './capability-client.js';

const server = new McpServer({ name: 'kunji', version: '0.1.0' });

const text = (t) => ({ content: [{ type: 'text', text: t }] });
const fail = (e) => ({ content: [{ type: 'text', text: `Error: ${e.message || e}` }], isError: true });

server.registerTool(
  'kunji_authorize',
  {
    title: 'Request kunji authorization',
    description:
      'Begin authorization to act for the user at an app. Returns a request the USER must approve ' +
      'in their kunji wallet (Security → Authorize an agent). On approval the wallet delivers the ' +
      'capability back automatically over an encrypted relay — then call kunji_await_capability to ' +
      'receive it (no copy/paste). kunji_set_capability remains as a manual fallback. The agent ' +
      "never receives the user's keys.",
    inputSchema: {
      audience: z.string().describe("The app's domain to act at, e.g. 'example.com'."),
      scope: z.array(z.string()).optional().describe("Requested scopes, e.g. ['login']. Defaults to ['login']."),
    },
  },
  async ({ audience, scope }) => {
    try {
      const req = await agentRequest(audience, scope);
      const [code, qr] = await Promise.all([postAgentRequest(req), requestQr(req)]);
      const lines = [
        `Ask the user to open their kunji wallet → Security → "Authorize an agent", then Approve.`,
        `On approval the wallet relays the capability back to you securely — call kunji_await_capability next.`,
        ``,
      ];
      if (code) {
        lines.push(`Easiest — have them type this 6-digit code (expires in ~3 min):`, ``, `        ${code}`, ``);
      }
      if (qr) {
        lines.push(`…or scan this QR with the wallet:`, ``, qr);
      }
      lines.push(`…or paste this request:`, ``, JSON.stringify(req));
      return text(lines.join('\n'));
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'kunji_await_capability',
  {
    title: 'Receive the authorized capability',
    description:
      'After the user approves kunji_authorize in their wallet, the wallet relays the capability back ' +
      'encrypted to this agent. This polls for it, decrypts it with the agent transport key, validates ' +
      'it (holder-of-key + expiry), and stores it — no copy/paste. Blocks briefly while waiting for approval.',
    inputSchema: {
      sessionId: z
        .string()
        .optional()
        .describe('The session id from kunji_authorize. Defaults to the most recent authorization.'),
    },
  },
  async ({ sessionId }) => {
    try {
      const cap = await awaitCapability(sessionId);
      return text(
        `Capability received and stored. audience=${cap.audience}, scope=${JSON.stringify(cap.scope)}, ` +
          `expires=${new Date(cap.exp * 1000).toISOString()}. You can now kunji_login.`,
      );
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'kunji_stepup',
  {
    title: 'Request additional scope (step-up)',
    description:
      'When an app returns 403 insufficient_scope mid-task, request a BROADER scope on the app you are ' +
      'already connected to — including a `vc:` scope to have the USER present a verified credential ' +
      "(e.g. 'vc:age#age_over_18'; the agent can't present the user's credentials itself). The user " +
      'approves a delta-aware re-consent in their wallet; then call kunji_await_capability, kunji_login ' +
      'again, and retry the request. Defaults the audience to your current capability.',
    inputSchema: {
      scope: z.array(z.string()).describe("The full desired scope, e.g. ['login','read:profile'] or ['login','vc:age#age_over_18']."),
      audience: z.string().optional().describe("The app domain. Defaults to your current capability's audience."),
    },
  },
  async ({ scope, audience }) => {
    try {
      const aud = audience || currentCapability().cap?.audience;
      if (!aud) throw new Error('No audience — pass one, or authorize first so I can default to it.');
      const { sessionId, code, qr, deepLink } = await stepUp(aud, scope);
      const lines = [
        `Ask the user to approve broader access to ${aud} (scope ${JSON.stringify(scope)}) in their kunji wallet.`,
        `On approval, call kunji_await_capability — then kunji_login again and retry the request.`,
        ``,
        `Same device — open this link:`,
        ``,
        `        ${deepLink}`,
        ``,
      ];
      if (code) lines.push(`…or have them type this 6-digit code (expires ~3 min):`, ``, `        ${code}`, ``);
      if (qr) lines.push(`…or scan this QR with the wallet:`, ``, qr);
      lines.push(`(session ${sessionId})`);
      return text(lines.join('\n'));
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  'kunji_request_via_push',
  {
    title: 'Ping the wallet via push (Transport ②)',
    description:
      'For a channel-less agent: if the user enabled notifications for you and gave you a channel id, ' +
      'ping their wallet via the opt-in Web Push relay to prompt a (re-)authorization — no QR/code to ' +
      'relay out of band. The push carries only an opaque pointer; the request rides the encrypted ' +
      'relay. On approval, call kunji_await_capability. Defaults the audience to your current capability.',
    inputSchema: {
      channelId: z.string().describe('The channel id the wallet showed the user when they enabled notifications for this agent.'),
      scope: z.array(z.string()).optional().describe("Requested scope. Defaults to ['login']."),
      audience: z.string().optional().describe("The app domain. Defaults to your current capability's audience."),
    },
  },
  async ({ channelId, scope, audience }) => {
    try {
      const aud = audience || currentCapability().cap?.audience;
      if (!aud) throw new Error('No audience — pass one, or authorize first so I can default to it.');
      const { sessionId } = await requestViaPush(channelId, aud, scope);
      return text(
        `Push sent to the user's wallet (session ${sessionId}). When they approve the notification, ` +
          `call kunji_await_capability to receive the capability.`,
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
