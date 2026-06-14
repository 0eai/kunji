import { describe, it, expect, vi } from 'vitest';

// credentials.js pulls in Firebase at import; stub it so this pure validator runs in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));

import { responseTargetTrusted } from '../src/services/credentials.js';

// [S20] OpenID4VP response-redirection guard: the wallet must only POST a vp_token to a response
// endpoint that is HTTPS (except loopback dev) AND whose host matches the verifier's shown client_id —
// otherwise an attacker shows a trusted client_id but redirects (and relays) the bound presentation.
describe('responseTargetTrusted (OID4VP response-redirection guard)', () => {
  it('accepts an https response_uri whose host matches the client_id', () => {
    expect(responseTargetTrusted('verifier.example', 'https://verifier.example/oid4vp/response')).toBe(true);
    expect(responseTargetTrusted('https://verifier.example', 'https://verifier.example/r')).toBe(true); // origin form
  });

  it('accepts http only for a loopback host (local dev)', () => {
    expect(responseTargetTrusted('localhost', 'http://localhost:3000/oid4vp/response')).toBe(true);
    expect(responseTargetTrusted('127.0.0.1', 'http://127.0.0.1:3000/r')).toBe(true);
  });

  it('rejects a response_uri whose host differs from the client_id (relay / redirection)', () => {
    expect(responseTargetTrusted('my-bank.example', 'https://attacker.example/collect')).toBe(false);
  });

  it('rejects http to a non-loopback host (anti-MITM)', () => {
    expect(responseTargetTrusted('verifier.example', 'http://verifier.example/r')).toBe(false);
  });

  it('rejects a malformed or missing endpoint / client_id', () => {
    expect(responseTargetTrusted('verifier.example', 'not a url')).toBe(false);
    expect(responseTargetTrusted('', 'https://verifier.example/r')).toBe(false);
    expect(responseTargetTrusted('verifier.example', '')).toBe(false);
  });
});
