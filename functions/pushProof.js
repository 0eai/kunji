// Holder-of-key verification for the opt-in Web Push relay (pushDispatch, push-relay.md Transport ②).
// Pure (no Firebase) so it's unit-testable against the wallet's `buildAgentProof`. The requester proves
// possession of the channel's registered `postKeyJwk` (an Ed25519 OKP key) with a `kunji-agentproof+jwt`
// JWS over (aud=channelId, challenge=requestId); only that holder can ping the channel.
import { ed25519 } from '@noble/curves/ed25519.js';

const b64u = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

/** True only for a fresh, channel+request-bound proof signed by `postKeyJwk`. */
export const verifyPostProof = (proof, postKeyJwk, channelId, requestId, now = Date.now()) => {
  try {
    const [h, c, sig] = String(proof).split('.');
    if (!h || !c || !sig) return false;
    const header = JSON.parse(b64u(h).toString('utf8'));
    const claims = JSON.parse(b64u(c).toString('utf8'));
    if (header.typ !== 'kunji-agentproof+jwt' || header.alg !== 'EdDSA') return false;
    if (!postKeyJwk || postKeyJwk.kty !== 'OKP' || postKeyJwk.crv !== 'Ed25519' || typeof postKeyJwk.x !== 'string')
      return false;
    const pub = new Uint8Array(b64u(postKeyJwk.x));
    if (!ed25519.verify(new Uint8Array(b64u(sig)), new TextEncoder().encode(`${h}.${c}`), pub)) return false;
    if (claims.aud !== channelId || claims.challenge !== requestId) return false;
    if (typeof claims.iat !== 'number' || Math.abs(now - claims.iat * 1000) > 120 * 1000) return false;
    return true;
  } catch {
    return false;
  }
};
