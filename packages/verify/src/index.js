// @kunji/verify — framework-agnostic RP-side verification for kunji discoverable login + agentic
// delegation. Pure (Node `crypto` + @noble/curves Ed25519); no Firebase, no network, no I/O. The
// RP verifies a signed assertion locally — kunji runs no backend in the login path.
//
// The canonical source lives here. The in-repo demo RPs mirror src/verify.js + src/capability.js
// (byte-identical, drift-guarded by tests/sdk.parity.test.js + scripts/sync-verify.js). External
// adopters: `npm i @kunji/verify` and import from here.

export { canonicalJson, subFromPublicKey, verifyAssertion } from './verify.js';
export {
  signJWS,
  scopeSatisfies,
  buildAgentProof,
  revokeMessage,
  verifyCapabilityAssertion,
} from './capability.js';
export { TTL_GUIDANCE, recommendedTtl, recommendedTtlForScopes } from './ttl.js';
