// Headless agent demo — authorize once via the live QR + OTP relay, then sign in to THIS demo RP
// with the resulting capability, no human in the loop after that. Mirrors what the kunji-mcp bridge
// (Phase 4) automates. See ../../docs/agentic-delegation.md.
//
// Run it (defaults to the local server):
//     node agent-sim.js
// It prints a 6-digit CODE + a QR + the raw request. In the kunji wallet: Security → Authorize an
// agent → type the code (or scan the QR, or paste), pick a TTL, Approve. The agent then receives the
// capability over the encrypted relay and logs in automatically — no copy/paste.
//
// Point at another host with BASE (e.g. BASE="http://192.168.1.5:3000" node agent-sim.js); the
// capability's audience is that host's hostname. Offline/relay-down fallback (paste a capability):
//     CAP="<capability JWT>" BASE="http://localhost:3000" node agent-sim.js
import { buildRequest, postForCode, terminalQr, awaitCapability, login, agentPubB64 } from './agent-client.js';

const BASE = process.env.BASE || 'http://localhost:3000';
const audience = new URL(BASE).hostname;
const scope = (process.env.SCOPE || 'login').split(',');

// Fallback path: a capability pasted in via CAP= (skips the relay entirely).
const CAP = process.env.CAP;
if (CAP) {
  const r = await login(BASE, CAP);
  console.log('agent login →', r.agentResp);
  console.log('session    →', r.status); // { status:'approved', sub, scope, agent:true } on success
  process.exit(r.status?.status === 'approved' ? 0 : 1);
}

console.log('Agent public key (base64):', agentPubB64(), '\n');
const req = await buildRequest(audience, scope);
const [code, qr] = await Promise.all([postForCode(req), terminalQr(req)]);

console.log('Authorize this agent in the kunji wallet (Security → Authorize an agent):\n');
if (code) console.log(`  • Type this 6-digit code:  ${code}   (expires ~3 min)\n`);
if (qr) {
  console.log('  • …or scan this QR:\n');
  console.log(qr);
}
console.log('  • …or paste this request:\n');
console.log('    ' + JSON.stringify(req) + '\n');
console.log('Waiting for approval…  (Ctrl-C to cancel)\n');

try {
  const capability = await awaitCapability(req.sessionId);
  console.log('✓ capability received over the relay\n');
  const r = await login(BASE, capability);
  console.log('agent login →', r.agentResp);
  console.log('session    →', r.status); // { status:'approved', sub, scope, agent:true } on success
  process.exit(r.status?.status === 'approved' ? 0 : 1);
} catch (e) {
  console.error('\n✗ ' + e.message);
  console.error(`Relay unavailable or approval timed out. Paste fallback:`);
  console.error(`  CAP="<capability>" BASE="${BASE}" node agent-sim.js`);
  process.exit(1);
}
