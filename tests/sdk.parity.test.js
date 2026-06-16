import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// @kunji/verify is the canonical source of the RP verifier. The demo RPs + the live issuer ship
// byte-identical mirrors (different deploy contexts — Firebase Functions bundles + plain-Node demos
// — preclude a shared import/workspace dep), kept in lockstep by scripts/sync-verify.js. This guards
// against any mirror drifting from the package. Edit the verifier in packages/verify/src, then run
// `node scripts/sync-verify.js`.
const read = (rel) => readFileSync(fileURLToPath(new URL('../' + rel, import.meta.url)), 'utf8');

const MIRRORS = {
  'packages/verify/src/verify.js': [
    'examples/kunji-node-demo/verify.js',
    'examples/kunji-agent-demo/verify.js',
    'examples/kunji-login-demo/functions/verify.js',
    'examples/kunji-selfhosted-demo/functions/verify.js',
    'examples/kunji-relay-demo/functions/verify.js',
    'issuer-functions/loginVerify.js',
  ],
  'packages/verify/src/capability.js': [
    'examples/kunji-agent-demo/capability.js',
    'examples/kunji-login-demo/functions/capability.js',
  ],
};

describe('@kunji/verify — mirrors are byte-identical to the canonical package source', () => {
  for (const [source, mirrors] of Object.entries(MIRRORS)) {
    const canonical = read(source);
    for (const mirror of mirrors) {
      it(`${mirror} === ${source}`, () => {
        expect(read(mirror)).toBe(canonical);
      });
    }
  }
});

describe('@kunji/verify — public API surface', () => {
  it('exports the documented entry points', async () => {
    const pkg = await import('../packages/verify/src/index.js');
    for (const name of [
      'verifyAssertion',
      'verifyCapabilityAssertion',
      'scopeSatisfies',
      'canonicalJson',
      'subFromPublicKey',
      'buildAgentProof',
      'revokeMessage',
      'signJWS',
      'recommendedTtl',
      'recommendedTtlForScopes',
      'TTL_GUIDANCE',
    ]) {
      expect(pkg[name], name).toBeDefined();
    }
  });

  it('recommendedTtlForScopes returns the strictest member TTL', async () => {
    const { recommendedTtl, recommendedTtlForScopes, TTL_GUIDANCE } = await import(
      '../packages/verify/src/ttl.js'
    );
    expect(recommendedTtl('payments:send')).toBe(TTL_GUIDANCE.payments);
    expect(recommendedTtl('read:orders')).toBe(TTL_GUIDANCE.read);
    expect(recommendedTtl('something:weird')).toBe(TTL_GUIDANCE.default);
    // strictest wins: payments (300) over read (86400)
    expect(recommendedTtlForScopes(['read:orders', { id: 'payments:send', max: '50USD' }])).toBe(
      TTL_GUIDANCE.payments,
    );
    expect(recommendedTtlForScopes([])).toBe(TTL_GUIDANCE.default);
  });
});
