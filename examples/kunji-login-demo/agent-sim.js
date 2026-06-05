// Headless agent demo — prove an authorized capability against the demo RP, no human in
// the loop after the one-time wallet authorization. Mirrors the protocol an MCP bridge
// (Phase 4) would automate. See docs/agentic-delegation.md.
//
// Step 1 — print the agent's request to authorize:
//     BASE="https://kunji-demo.web.app" node agent-sim.js
// Step 2 — in the kunji wallet: Security → Authorize an agent → paste/scan that request,
//     approve, copy the capability. Then:
//     CAP="<capability JWT>" BASE="https://kunji-demo.web.app" node agent-sim.js
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { buildAgentProof } from './functions/capability.js';

const BASE = process.env.BASE || 'http://localhost:5173';
const audience = new URL(BASE).hostname;
const scope = (process.env.SCOPE || 'login').split(',');
const KEYFILE = new URL('./.agent-key', import.meta.url);

// Persist the agent keypair across the two runs so the capability (minted for the key
// printed in step 1) matches the proof we sign in step 2.
let secretKey;
if (existsSync(KEYFILE)) {
  secretKey = new Uint8Array(Buffer.from(readFileSync(KEYFILE, 'utf8').trim(), 'base64'));
} else {
  ({ secretKey } = ed25519.keygen());
  writeFileSync(KEYFILE, Buffer.from(secretKey).toString('base64'));
}
const agentPub = Buffer.from(ed25519.getPublicKey(secretKey)).toString('base64');

const CAP = process.env.CAP;
if (!CAP) {
  console.log('Agent public key (base64):', agentPub);
  console.log('\nAuthorize this request in the kunji wallet (Security → Authorize an agent):\n');
  console.log(JSON.stringify({ kunjiCap: 'v1', audience, scope, agentPub }));
  console.log(`\nThen: CAP="<capability>" BASE="${BASE}" node agent-sim.js`);
  process.exit(0);
}

const post = (path, body) =>
  fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then((r) => r.json());

const capJti = JSON.parse(Buffer.from(CAP.split('.')[1], 'base64url').toString('utf8')).jti;

const session = await post('/api/session', { audience, callbackUrl: `${BASE}/kunji/callback` });
if (!session.sessionId) throw new Error('createSession failed: ' + JSON.stringify(session));

const agentProof = buildAgentProof(secretKey, { audience, challenge: session.challenge, capJti });
const result = await post('/kunji/agent', { sessionId: session.sessionId, capability: CAP, agentProof });
console.log('agent login →', result);

const status = await fetch(`${BASE}/kunji/status?sessionId=${session.sessionId}`).then((r) => r.json());
console.log('session    →', status); // { status:'approved', sub, claims, ... } on success
