// Headless agent demo — authorize once via the live QR + OTP relay, then sign in to THIS demo RP
// with the resulting capability, no human in the loop after that. Mirrors what the kunji-mcp bridge
// (Phase 4) automates. See ../../docs/agentic-delegation.md.
//
// It also demonstrates STEP-UP authorization (push-relay.md Transport ①): start with only `login`,
// hit a scope-gated action (`/api/profile` needs `read:profile`) → `403 insufficient_scope` → ask the
// user for the missing scope → receive a broader capability → retry → 200. No new kunji infra: the
// re-request rides the SAME relay, and the user approves the delta in the wallet (code/QR/deep link).
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
import {
  buildRequest,
  postForCode,
  terminalQr,
  awaitCapability,
  login,
  agentPubB64,
  stepUp,
  requestViaPush,
} from './agent-client.js';

const BASE = process.env.BASE || 'http://localhost:3000';
const audience = new URL(BASE).hostname;
const scope = (process.env.SCOPE || 'login').split(',');

// Call the RP's scope-gated /api/profile (needs `read:profile`). Returns { status, body } so the
// caller can react: 200 if the granted scope covers it, 403 insufficient_scope otherwise.
const callScoped = async (sessionId) => {
  const resp = await fetch(`${BASE}/api/profile?sessionId=${sessionId}`);
  const body = await resp.json();
  console.log(`\nread:profile → ${resp.status}`, body);
  return { status: resp.status, body };
};

// Step-up: an `insufficient_scope` 403 names what's missing (`need`); ask the user for it on the
// SAME relay, await the broader capability, re-login, and retry the gated call (Transport ①).
const runStepUp = async (need) => {
  console.log(`\n↑ Step-up: requesting the missing scope "${need}" — approve it in the kunji wallet:\n`);
  const su = await stepUp(audience, ['login', need]);
  if (su.code) console.log(`  • Type this 6-digit code:  ${su.code}   (expires ~3 min)`);
  console.log(`  • …or tap this deep link:  ${su.deepLink}`);
  if (su.qr) console.log('\n  • …or scan this QR:\n' + su.qr);
  console.log('\nWaiting for approval…  (Ctrl-C to cancel)\n');
  const capability = await awaitCapability(su.sessionId);
  console.log('✓ broader capability received over the relay\n');
  const r = await login(BASE, capability);
  console.log('session    →', r.status); // now includes read:profile
  return callScoped(r.sessionId);
};

// Push-relay path (Transport ②): the agent is channel-less and the user enabled notifications for it,
// giving it a CHANNEL id at authorization. `CHANNEL=<id> node agent-sim.js --push` pings the wallet via
// the push relay; the user's notification fires, they approve, and the capability returns over the relay.
if (process.argv.includes('--push')) {
  const channelId = process.env.CHANNEL;
  if (!channelId) {
    console.error('Set CHANNEL=<channelId the wallet showed when you enabled notifications>.');
    process.exit(1);
  }
  console.log('Pinging the wallet via the push relay (it should show a notification)…\n');
  const { sessionId } = await requestViaPush(channelId, audience, scope);
  console.log('✓ dispatched — waiting for the user to approve the notification…  (Ctrl-C to cancel)\n');
  const capability = await awaitCapability(sessionId);
  console.log('✓ capability received over the relay\n');
  const r = await login(BASE, capability);
  console.log('session    →', r.status);
  process.exit(r.status?.status === 'approved' ? 0 : 1);
}

// Fallback path: a capability pasted in via CAP= (skips the relay entirely, so no step-up).
const CAP = process.env.CAP;
if (CAP) {
  const r = await login(BASE, CAP);
  console.log('agent login →', r.agentResp);
  console.log('session    →', r.status); // { status:'approved', sub, scope, agent:true } on success
  const scoped = await callScoped(r.sessionId);
  if (scoped.status === 403)
    console.log('\n(Pasted capability lacks read:profile — re-run with SCOPE=login,read:profile to grant it.)');
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
  let scoped = await callScoped(r.sessionId);
  // If the granted scope doesn't cover the gated action, demonstrate step-up rather than giving up.
  if (scoped.status === 403 && scoped.body?.error === 'insufficient_scope') {
    scoped = await runStepUp(scoped.body.need || 'read:profile');
  }
  process.exit(r.status?.status === 'approved' && scoped.status === 200 ? 0 : 1);
} catch (e) {
  console.error('\n✗ ' + e.message);
  console.error(`Relay unavailable or approval timed out. Paste fallback:`);
  console.error(`  CAP="<capability>" BASE="${BASE}" node agent-sim.js`);
  process.exit(1);
}
