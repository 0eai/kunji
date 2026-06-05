// Agentic delegation (wallet side) — parse an agent's authorization request and mint a
// capability for it after explicit user approval. See docs/agentic-delegation.md.
import { mintCapability } from '../lib/capability';
import { logActivity } from './activityLog';

// A base64 (std) Ed25519 public key is exactly 32 bytes → 43 chars + one '=' pad.
const ED25519_PUB_B64 = /^[A-Za-z0-9+/]{43}=$/;

/**
 * Parse + validate an agent's authorization request (scanned QR / pasted JSON):
 *   { kunjiCap:'v1', audience, scope:[…], agentPub:<base64 Ed25519 pubkey> }
 * The agent generates its own keypair and presents the public key here (holder-of-key).
 */
export const parseAgentRequest = (raw) => {
  let req;
  try {
    req = JSON.parse(raw);
  } catch {
    throw new Error('invalid_request');
  }
  if (
    req?.kunjiCap !== 'v1' ||
    typeof req.audience !== 'string' ||
    !req.audience ||
    typeof req.agentPub !== 'string' ||
    !ED25519_PUB_B64.test(req.agentPub) ||
    !Array.isArray(req.scope) ||
    req.scope.length === 0 ||
    !req.scope.every((s) => typeof s === 'string' && s.length <= 64)
  ) {
    throw new Error('invalid_request');
  }
  return { audience: String(req.audience), scope: req.scope.slice(0, 16), agentPub: req.agentPub };
};

/**
 * Mint a capability for an agent. Requires the unlocked master key (`cryptoKey`) — this is
 * the human-approval trust root; nothing is minted without it. Returns the capability JWT
 * + metadata; the agent's private key never touches the wallet.
 */
export const issueCapability = async (userId, cryptoKey, { audience, scope, ttlSeconds, agentPub }) => {
  const result = await mintCapability(cryptoKey, { audience, scope, ttlSeconds, agentPubB64: agentPub });
  await logActivity(userId, `Authorized an agent for ${audience}`, 'success', 'ShieldCheck', cryptoKey);
  return result; // { capability, appPub, sub, jti, exp }
};
