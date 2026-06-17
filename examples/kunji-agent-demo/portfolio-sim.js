// Headless PORTFOLIO demo (roadmap 4.2) — ONE agent asks to be authorized at SEVERAL apps in a single
// approval, then receives an independent per-app capability for each over the encrypted relay. Mirrors
// agent-sim.js but exercises the `portfolio-v1` request + the wallet's AuthorizePortfolioSheet. The
// per-app capabilities are independent (each signed by its own per-app key, its own aud/sub) — this is a
// batched UX, NOT a single cross-app grant, so per-app unlinkability is preserved. See ../../docs/agentic-delegation.md.
//
// Run it:
//     node portfolio-sim.js
// It prints ONE deep link / QR / request for N apps. In the kunji wallet the link opens straight to the
// multi-app review; approve once. The agent then receives N capabilities over the relay and prints each
// one's audience + scope + sub (distinct sub per audience = unlinkability preserved).
//
// Override the app list (comma-separated audiences) and label:
//     APPS="shop.example,travel.example,tickets.example" LABEL="Concierge" node portfolio-sim.js
import { buildPortfolioRequest, postForCode, terminalQr, authorizeDeepLink, awaitCapability, decodeCapability } from './agent-client.js';

const APPS = (process.env.APPS || 'shop.example,travel.example,tickets.example').split(',').map((s) => s.trim()).filter(Boolean);
const LABEL = process.env.LABEL || 'Concierge agent';
const apps = APPS.map((audience) => ({ audience, scope: ['login'] }));

const req = await buildPortfolioRequest(apps, LABEL);
// A portfolio request has no single OTP slot in the relay (the relay validator is single-app), so the
// primary hand-off is the deep link / QR; the OTP attempt is best-effort and usually null here.
const [, qr] = await Promise.all([postForCode(req).catch(() => null), terminalQr(req)]);

console.log(`\nAuthorize "${LABEL}" across ${apps.length} apps in ONE approval:\n`);
console.log('  • Tap this deep link (opens the multi-app review):\n    ' + authorizeDeepLink(req) + '\n');
if (qr) console.log('  • …or scan this QR:\n' + qr);
console.log('  • …or paste this request:\n    ' + JSON.stringify(req) + '\n');
console.log('Waiting for approval…  (Ctrl-C to cancel)\n');

const results = await Promise.allSettled(
  req.items.map(async (it) => {
    const capability = await awaitCapability(it.sessionId);
    return { audience: it.audience, claims: decodeCapability(capability) };
  }),
);

let ok = 0;
for (const r of results) {
  if (r.status === 'fulfilled') {
    ok++;
    const { audience, claims } = r.value;
    console.log(`✓ ${audience}  →  aud=${claims?.aud}  scope=${JSON.stringify(claims?.scope)}  sub=${claims?.sub?.slice(0, 12)}…`);
  } else {
    console.log(`✗ ${r.reason?.message || r.reason}`);
  }
}
console.log(`\n${ok}/${req.items.length} apps authorized — each an independent per-app capability.`);
process.exit(ok === req.items.length ? 0 : 1);
