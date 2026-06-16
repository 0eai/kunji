import { describe, it, expect } from 'vitest';
import { formatConstraint, formatConstraints } from '../src/lib/scopeFormat.js';
import { parseAgentRequest } from '../src/services/capability.js';
import { generateEd25519KeyPair, exportEd25519PublicKey } from '../src/lib/crypto/index.js';

describe('scopeFormat — prose constraint rendering', () => {
  it('formats known constraint dimensions', () => {
    expect(formatConstraint('max', '50USD')).toBe('up to $50');
    expect(formatConstraint('max', '100 EUR')).toBe('up to €100');
    expect(formatConstraint('max', '500')).toBe('up to 500'); // no currency
    expect(formatConstraint('max', '40 ZZD')).toBe('up to 40 ZZD'); // unknown currency → code
    expect(formatConstraint('resource', 'acct_123')).toBe('resource acct_123');
    expect(formatConstraint('maxUses', 1)).toBe('1 use');
    expect(formatConstraint('maxUses', 3)).toBe('3 uses');
    expect(formatConstraint('rateBudget', '10/min')).toBe('rate 10/min');
  });

  it('falls back to "key value" for unknown dimensions', () => {
    expect(formatConstraint('region', 'eu')).toBe('region eu');
  });

  it('joins all constraints on a scope item (and ignores id)', () => {
    expect(formatConstraints({ id: 'payments:send', max: '50USD', resource: 'acct_1' })).toBe(
      'up to $50 · resource acct_1',
    );
    expect(formatConstraints('read:orders')).toBe(''); // string scope → no constraints
    expect(formatConstraints({ id: 'read:orders' })).toBe(''); // object, id only
  });
});

describe('parseAgentRequest — scopeLabels pass-through (untrusted, sanitized)', () => {
  const validReq = (extra = {}) => {
    const agentPub = exportEd25519PublicKey(generateEd25519KeyPair().publicKey);
    return JSON.stringify({
      kunjiCap: 'v1',
      audience: 'app.example.com',
      agentPub,
      scope: ['login', { id: 'payments:send', max: '50USD' }],
      ...extra,
    });
  };

  it('passes a well-formed scopeLabels object through', () => {
    const out = parseAgentRequest(validReq({ scopeLabels: { 'payments:send': 'Send a payment' } }));
    expect(out.scopeLabels).toEqual({ 'payments:send': 'Send a payment' });
  });

  it('drops non-string and oversized entries; omits the field when empty', () => {
    const out = parseAgentRequest(
      validReq({
        scopeLabels: {
          'payments:send': 'ok',
          bad: 123, // non-string value → dropped
          huge: 'x'.repeat(200), // > 120 chars → dropped
        },
      }),
    );
    expect(out.scopeLabels).toEqual({ 'payments:send': 'ok' });

    const none = parseAgentRequest(validReq({ scopeLabels: { bad: 5 } }));
    expect(none.scopeLabels).toBeUndefined();

    const arr = parseAgentRequest(validReq({ scopeLabels: ['not', 'an', 'object'] }));
    expect(arr.scopeLabels).toBeUndefined();
  });
});
