import { describe, it, expect, vi } from 'vitest';

// capability.js pulls in Firebase at import; stub it so the pure parser runs in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('firebase/firestore', () => ({ collection: vi.fn(), doc: vi.fn(), getDocs: vi.fn(), setDoc: vi.fn() }));

import { parsePortfolioRequest, isPortfolioRequest } from '../src/services/capability.js';

const HEX64 = 'a'.repeat(64);
const HEX64B = 'b'.repeat(64);
const AGENT_PUB = 'A'.repeat(43) + '='; // shape-valid base64 Ed25519 pub
const TRANSPORT = 'B'.repeat(120); // loose base64 SPKI

const item = (over = {}) => ({ audience: 'shop.example', scope: ['login'], sessionId: HEX64, ...over });
const req = (over = {}) => ({ kunjiCap: 'portfolio-v1', agentPub: AGENT_PUB, transportPub: TRANSPORT, items: [item()], ...over });
const parse = (o) => parsePortfolioRequest(JSON.stringify(o));

describe('parsePortfolioRequest — happy path (4.2)', () => {
  it('parses a multi-app request: one agent, N per-app items', () => {
    const out = parse(
      req({
        label: 'Concierge',
        items: [
          item({ audience: 'shop.example', sessionId: HEX64 }),
          item({ audience: 'travel.example', scope: ['login', 'read:profile'], sessionId: HEX64B }),
        ],
      }),
    );
    expect(out.agentPub).toBe(AGENT_PUB);
    expect(out.transportPub).toBe(TRANSPORT);
    expect(out.label).toBe('Concierge');
    expect(out.items).toHaveLength(2);
    expect(out.items[0]).toEqual({ audience: 'shop.example', scope: ['login'], sessionId: HEX64 });
    expect(out.items[1].audience).toBe('travel.example');
    expect(out.items[1].scope).toEqual(['login', 'read:profile']);
  });

  it('carries optional per-item scopeLabels (bounded), drops a blank/oversized label', () => {
    const out = parse(req({ label: '   ', items: [item({ scopeLabels: { 'read:profile': 'Your profile' } })] }));
    expect(out.label).toBeUndefined(); // blank label trimmed away
    expect(out.items[0].scopeLabels).toEqual({ 'read:profile': 'Your profile' });
  });

  it('isPortfolioRequest only matches the portfolio-v1 marker', () => {
    expect(isPortfolioRequest(JSON.stringify(req()))).toBe(true);
    expect(isPortfolioRequest(JSON.stringify({ kunjiCap: 'v2', audience: 'a', scope: ['login'], agentPub: AGENT_PUB }))).toBe(false);
    expect(isPortfolioRequest('not json')).toBe(false);
  });
});

describe('parsePortfolioRequest — rejections', () => {
  const bad = (o) => expect(() => parse(o)).toThrow('invalid_request');

  it('rejects a non-portfolio marker', () => bad(req({ kunjiCap: 'v2' })));
  it('rejects a malformed agentPub / transportPub', () => {
    bad(req({ agentPub: 'short' }));
    bad(req({ transportPub: '!!!' }));
  });
  it('rejects empty items, or more than 10', () => {
    bad(req({ items: [] }));
    bad(req({ items: Array.from({ length: 11 }, (_, i) => item({ audience: `app${i}.example`, sessionId: HEX64 })) }));
  });
  it('rejects an item with a bad audience / sessionId / scope', () => {
    bad(req({ items: [item({ audience: '' })] }));
    bad(req({ items: [item({ sessionId: 'nothex' })] }));
    bad(req({ items: [item({ scope: [] })] }));
    bad(req({ items: [item({ scope: ['bad scope id!'] })] }));
  });
  it('rejects duplicate audiences (one capability per audience per agent)', () => {
    bad(req({ items: [item({ audience: 'dup.example', sessionId: HEX64 }), item({ audience: 'dup.example', sessionId: HEX64B })] }));
  });
  it('rejects non-JSON', () => expect(() => parsePortfolioRequest('{')).toThrow('invalid_request'));
});
