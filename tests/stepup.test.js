import { describe, it, expect, vi } from 'vitest';

// The services pull in Firebase at import; stub it so these pure validators run in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('../src/services/activityLog', () => ({ logActivity: vi.fn(), listenToActivityLog: vi.fn() }));

import { scopeId, scopeSatisfies, mintCapability } from '../src/lib/capability.js';
import { generateMasterKey, generateEd25519KeyPair, exportEd25519PublicKey } from '../src/lib/crypto/index.js';
import { parseAgentRequest } from '../src/services/capability.js';
import { parseQRPayload, requestsCredentials, requestsProfile } from '../src/services/identity.js';

// Step-up authorization (push-relay.md Transport ①). The wallet marks each requested scope item as
// "already granted" vs "new" by asking whether the agent's EXISTING scope already satisfies it, and a
// broadened re-request must still be a valid capability. The deep links that carry these requests
// (?authorize= for agents, ?approve= for human login) must never cross-route.

// Mirrors AuthorizeAgentSheet's `alreadyGranted(item)` = scopeSatisfies(priorScope, [item]).
const isNew = (priorScope, item) => scopeId(item) !== 'login' && !scopeSatisfies(priorScope, [item]);

describe('step-up scope delta', () => {
  it('classifies requested items as already-granted vs new against the prior scope', () => {
    const prior = ['login', 'read:orders', { id: 'payments:charge', max: '30USD' }];
    const requested = ['login', 'read:orders', 'read:profile', { id: 'payments:charge', max: '50USD' }];
    const fresh = requested.filter((s) => isNew(prior, s));
    // read:orders is already held; login is implied; read:profile is new; a HIGHER max is not covered.
    expect(fresh.map(scopeId)).toEqual(['read:profile', 'payments:charge']);
  });

  it('a wildcard prior covers a specific new request (no step-up needed)', () => {
    expect(isNew(['read:*'], 'read:orders')).toBe(false);
    expect(isNew(['read:*'], 'write:orders')).toBe(true);
  });

  it('login is never counted as new (implied by any assertion)', () => {
    expect(isNew([], 'login')).toBe(false);
  });

  it('a broadened (superset) re-request still mints a valid capability covering old + delta', async () => {
    const master = await generateMasterKey();
    const agent = generateEd25519KeyPair();
    const agentPubB64 = exportEd25519PublicKey(agent.publicKey);
    const oldScope = ['login', 'read:orders'];
    const newScope = ['login', 'read:orders', 'read:profile'];
    const { capability, scope } = await mintCapabilityScope(master, newScope, agentPubB64);
    expect(capability.split('.')).toHaveLength(3); // a well-formed JWS
    // The broadened capability covers everything the old one did, plus the requested delta.
    expect(scopeSatisfies(scope, oldScope)).toBe(true);
    expect(scopeSatisfies(scope, ['read:profile'])).toBe(true);
  });
});

// Helper: mint + surface the scope baked into the capability (mintCapability returns no scope field).
const mintCapabilityScope = async (master, scope, agentPubB64) => {
  const r = await mintCapability(master, { audience: 'app.example', scope, ttlSeconds: 3600, agentPubB64 });
  const claims = JSON.parse(Buffer.from(r.capability.split('.')[1], 'base64url').toString('utf8'));
  return { capability: r.capability, scope: claims.scope };
};

describe('deep-link discrimination (?authorize= agent request vs ?approve= login QR)', () => {
  const agentPubB64 = exportEd25519PublicKey(generateEd25519KeyPair().publicKey);
  const agentRequest = JSON.stringify({
    kunjiCap: 'v1',
    audience: 'app.example',
    agentPub: agentPubB64,
    scope: ['login', 'read:profile'],
  });
  const loginQR = JSON.stringify({
    kunjiAuth: 'v2',
    mode: 'discoverable',
    sessionId: 's',
    challenge: 'c',
    audience: 'app.example',
    callbackUrl: 'https://app.example/kunji/callback',
    expiresAt: Date.now() + 60_000,
  });

  // The links carry base64url(JSON); the wallet decodes then routes by which parser accepts it.
  const roundtrip = (json) => Buffer.from(Buffer.from(json).toString('base64url'), 'base64url').toString('utf8');

  it('an agent request parses as an agent request and is rejected by the login parser', () => {
    const raw = roundtrip(agentRequest);
    expect(parseAgentRequest(raw)).toMatchObject({ audience: 'app.example', scope: ['login', 'read:profile'] });
    expect(() => parseQRPayload(raw)).toThrow();
  });

  it('a login QR parses as a login QR and is rejected by the agent parser', () => {
    const raw = roundtrip(loginQR);
    expect(parseQRPayload(raw)).toMatchObject({ audience: 'app.example' });
    expect(() => parseAgentRequest(raw)).toThrow('invalid_request');
  });
});

describe('back-compat (no step-up context)', () => {
  it('a plain login QR is unchanged and requests nothing extra', () => {
    const qr = parseQRPayload(
      JSON.stringify({
        kunjiAuth: 'v2',
        mode: 'discoverable',
        sessionId: 's',
        challenge: 'c',
        audience: 'app.example',
        callbackUrl: 'https://app.example/kunji/callback',
        expiresAt: Date.now() + 60_000,
      }),
    );
    expect(requestsProfile(qr)).toBe(false);
    expect(requestsCredentials(qr)).toBe(false);
  });

  it('a plain string scope still parses on the agent request (back-compat)', () => {
    const pub = exportEd25519PublicKey(generateEd25519KeyPair().publicKey);
    const req = parseAgentRequest(JSON.stringify({ kunjiCap: 'v1', audience: 'app.example', agentPub: pub, scope: ['login'] }));
    expect(req.scope).toEqual(['login']);
  });
});
