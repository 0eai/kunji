// Agentic delegation (wallet side) — parse an agent's authorization request and mint a
// capability for it after explicit user approval. See docs/agentic-delegation.md.
import { collection, doc, getDocs, setDoc } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveECDHSharedSecret,
  encryptData,
  decryptData,
  deriveVaultId,
  deriveVaultWriteKeyPair,
  deriveAppKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
  signMessageEd25519,
} from '../lib/crypto';
import { mintCapability, isValidScopeItem } from '../lib/capability';
import { logActivity } from './activityLog';

const VAULT_WRITE_URL = import.meta.env.VITE_VAULT_WRITE_URL || '/vault/write';
const AGENT_REQUEST_URL = import.meta.env.VITE_AGENT_REQUEST_URL || '/agent/request';
// The signed revocation message — MUST match the RP verifier byte-for-byte.
export const revokeMessage = (jti) => `kunji-revoke-v1:${jti}`;

// A base64 (std) Ed25519 public key is exactly 32 bytes → 43 chars + one '=' pad.
const ED25519_PUB_B64 = /^[A-Za-z0-9+/]{43}=$/;
// A 256-bit relay session id (the agent's unguessable random) — 64 hex chars.
const HEX64 = /^[0-9a-f]{64}$/i;
// Loose base64 sanity check for the agent's ECDH transport pub (SPKI); cryptographically
// validated at deposit time via importECDHPublicKey.
const B64 = /^[A-Za-z0-9+/]{80,400}={0,2}$/;
const RELAY_TTL_MS = 5 * 60 * 1000; // the agent should poll promptly; short-lived relay

/**
 * Parse + validate an agent's authorization request (scanned QR / pasted JSON).
 *   v1: { kunjiCap:'v1', audience, scope:[…], agentPub:<base64 Ed25519 pubkey> }   (paste-only)
 *   v2: …plus { transportPub:<base64 ECDH-P256 SPKI>, sessionId:<64-hex> }          (relay hand-off)
 * The agent generates its own keypair(s) and presents the public key(s) here (holder-of-key).
 */
// Sanitize an optional RP-supplied scopeLabels map — human labels for custom scope ids, shown in
// consent marked "unverified" (the RP can type anything; these are NOT trusted). Keep only string→string
// entries, bounded in count + length, so a malformed/oversized map can't bloat or break the consent sheet.
const sanitizeScopeLabels = (raw) => {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const labels = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof k === 'string' && typeof v === 'string' && k.length <= 64 && v.length <= 120) labels[k] = v;
    if (Object.keys(labels).length >= 16) break;
  }
  return Object.keys(labels).length ? labels : null;
};

export const parseAgentRequest = (raw) => {
  let req;
  try {
    req = JSON.parse(raw);
  } catch {
    throw new Error('invalid_request');
  }
  if (
    (req?.kunjiCap !== 'v1' && req?.kunjiCap !== 'v2') ||
    typeof req.audience !== 'string' ||
    !req.audience ||
    typeof req.agentPub !== 'string' ||
    !ED25519_PUB_B64.test(req.agentPub) ||
    !Array.isArray(req.scope) ||
    req.scope.length === 0 ||
    req.scope.length > 16 ||
    !req.scope.every(isValidScopeItem)
  ) {
    throw new Error('invalid_request');
  }
  const out = {
    audience: String(req.audience),
    scope: req.scope,
    agentPub: req.agentPub,
  };
  const labels = sanitizeScopeLabels(req.scopeLabels);
  if (labels) out.scopeLabels = labels;
  // v2 adds the relay transport key + session id. Both must be well-formed or we reject —
  // a malformed v2 must not silently downgrade to the paste-only path.
  if (req.kunjiCap === 'v2') {
    if (typeof req.transportPub !== 'string' || !B64.test(req.transportPub) || !HEX64.test(req.sessionId || '')) {
      throw new Error('invalid_request');
    }
    out.transportPub = req.transportPub;
    out.sessionId = String(req.sessionId);
  }
  return out;
};

const MAX_PORTFOLIO_ITEMS = 10; // bound the consolidated review so one request can't fan out unbounded

/**
 * Parse + validate a PORTFOLIO authorization request (4.2) — ONE agent asking to be authorized at
 * SEVERAL apps in a single approval. Shape:
 *   { kunjiCap:'portfolio-v1', agentPub:<base64 Ed25519>, transportPub:<base64 ECDH-P256 SPKI>,
 *     label?:<string>, items:[ { audience, scope:[…], sessionId:<64-hex>, scopeLabels? }, … ] }
 * One shared agent key + relay transport key; each item is an independent per-app ask (its own audience,
 * scope, and relay session). Minting stays per-item (one capability per audience, each signed by its own
 * per-app key + deposited to its own session) — so per-app unlinkability is preserved; this is purely a
 * batched UX over the existing single-agent path. Duplicate audiences are rejected (one cap per audience).
 */
export const parsePortfolioRequest = (raw) => {
  let req;
  try {
    req = JSON.parse(raw);
  } catch {
    throw new Error('invalid_request');
  }
  if (
    req?.kunjiCap !== 'portfolio-v1' ||
    typeof req.agentPub !== 'string' ||
    !ED25519_PUB_B64.test(req.agentPub) ||
    typeof req.transportPub !== 'string' ||
    !B64.test(req.transportPub) ||
    !Array.isArray(req.items) ||
    req.items.length === 0 ||
    req.items.length > MAX_PORTFOLIO_ITEMS
  ) {
    throw new Error('invalid_request');
  }
  const items = req.items.map((it) => {
    if (
      !it ||
      typeof it !== 'object' ||
      Array.isArray(it) ||
      typeof it.audience !== 'string' ||
      !it.audience ||
      !HEX64.test(it.sessionId || '') ||
      !Array.isArray(it.scope) ||
      it.scope.length === 0 ||
      it.scope.length > 16 ||
      !it.scope.every(isValidScopeItem)
    ) {
      throw new Error('invalid_request');
    }
    const item = { audience: String(it.audience), scope: it.scope, sessionId: String(it.sessionId) };
    const labels = sanitizeScopeLabels(it.scopeLabels);
    if (labels) item.scopeLabels = labels;
    return item;
  });
  // One capability per audience per agent — duplicate audiences would mint colliding records (same
  // per-app key), so reject them up front rather than silently overwriting.
  if (new Set(items.map((i) => i.audience)).size !== items.length) throw new Error('invalid_request');
  const out = { agentPub: req.agentPub, transportPub: req.transportPub, items };
  if (typeof req.label === 'string' && req.label.trim() && req.label.length <= 80) out.label = req.label.trim();
  return out;
};

/** True if `raw` is a portfolio-v1 request (so the caller can route to the portfolio sheet). Cheap peek;
 *  the full validator (`parsePortfolioRequest`) still runs inside the sheet. */
export const isPortfolioRequest = (raw) => {
  try {
    return JSON.parse(raw)?.kunjiCap === 'portfolio-v1';
  } catch {
    return false;
  }
};

/**
 * Resolve a 6-digit agent-authorization code to the agent's request (OTP path). The agent POSTed
 * its request to the relay and showed the user this short code; we fetch it back through the same
 * function and return the raw JSON string for `parseAgentRequest` (so the code-typed and the
 * QR-scanned paths converge on one validator). Throws a friendly message on a bad/expired code.
 */
export const lookupAgentRequest = async (code) => {
  const c = String(code || '').trim();
  if (!/^\d{6}$/.test(c)) throw new Error('Enter the 6-digit code.');
  let resp;
  try {
    resp = await fetch(`${AGENT_REQUEST_URL}?code=${c}`);
  } catch {
    throw new Error('Network error — check your connection.');
  }
  if (resp.status === 404) throw new Error('Code not found — check it and try again.');
  if (resp.status === 410) throw new Error('Code expired — ask the agent for a new one.');
  if (resp.status === 429) throw new Error('Too many tries — wait a moment.');
  if (!resp.ok) throw new Error('Could not load the request.');
  return resp.text(); // raw JSON → parseAgentRequest
};

/**
 * Deposit a minted capability into the relay so the agent receives it with no manual copy.
 * The capability is ECDH-encrypted to the agent's transport key (the relay doc holds only
 * ciphertext + our ephemeral pub + audience). Mirrors linking.js depositMasterKey.
 */
export const depositAgentCapability = async (sessionId, agentTransportPubB64, capability, audience) => {
  const { publicKey, privateKey } = await generateECDHKeyPair();
  const walletPubE = await exportECDHPublicKey(publicKey);
  const agentPubE = await importECDHPublicKey(agentTransportPubB64);
  const shared = await deriveECDHSharedSecret(privateKey, agentPubE);
  const encryptedCapability = await encryptData(capability, shared);
  const expiresAt = Date.now() + RELAY_TTL_MS;
  await setDoc(doc(db, 'agentSessions', sessionId), {
    walletPubE,
    encryptedCapability,
    audience: String(audience || ''),
    expiresAt,
    ttl: new Date(expiresAt + 5 * 60 * 1000), // add a Firestore TTL policy on `ttl` to auto-clean
  });
};

/**
 * Mint a capability for an agent. Requires the unlocked master key (`cryptoKey`) — this is
 * the human-approval trust root; nothing is minted without it. Returns the capability JWT
 * + metadata; the agent's private key never touches the wallet.
 */
export const issueCapability = async (userId, cryptoKey, { audience, scope, ttlSeconds, agentPub }) => {
  const result = await mintCapability(cryptoKey, { audience, scope, ttlSeconds, agentPubB64: agentPub });
  // Tag with the agent's jti/audience (NOT `domain`, so it doesn't mix into per-app activity) so the
  // agent detail sheet can show this agent's lifecycle.
  await logActivity(userId, `Authorized an agent for ${audience}`, 'success', 'ShieldCheck', cryptoKey, {
    agentJti: result.jti,
    agentAudience: audience,
  });
  return result; // { capability, appPub, sub, jti, exp }
};

// Signed write of the encrypted agent record to the shared vault log (vaultWrite kind:'agent').
// Mirrors services/profile.js writeProfile — the function never sees the master key or plaintext.
const agentVaultWrite = async (cryptoKey, op, jti, docPayload) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const timestamp = Date.now();
  const signed = {
    appId: jti,
    doc: docPayload ?? null,
    kind: 'agent',
    op,
    publicKey: publicKeyB64,
    timestamp,
    vaultId,
  };
  const signedToken = signWithEd25519(signed, secretKey);
  const resp = await fetch(VAULT_WRITE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      vaultId,
      op,
      appId: jti,
      kind: 'agent',
      doc: docPayload ?? undefined,
      publicKey: publicKeyB64,
      signedToken,
      timestamp,
    }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('agent_write_failed:' + (e.error || resp.status));
  }
};

/** Persist a just-minted capability's metadata (NOT the capability) so the user can see + revoke it.
 *  `pushEnabled` records whether the user turned on notifications for this agent — so the connected-apps
 *  list can show + toggle the per-app push channel (it's re-derivable from `audience`). */
export const recordAgent = async (cryptoKey, { jti, audience, scope, exp, agentPub, pushEnabled, agentLabel }) => {
  const record = { audience, scope, exp, agentPub, issuedAt: Math.floor(Date.now() / 1000) };
  if (pushEnabled) record.pushEnabled = true;
  // Optional friendly name (from a portfolio request's `label`) so the agents list can group the
  // same agent's per-app capabilities under one heading. Absent on legacy/single-app records.
  if (agentLabel) record.agentLabel = agentLabel;
  const payload = await encryptData(record, cryptoKey);
  await agentVaultWrite(cryptoKey, 'set', jti, payload);
};

/** Flip an agent's notification (push) status, re-recording its metadata. Used by the connected-apps UI. */
export const setAgentPushEnabled = async (cryptoKey, agent, enabled) => {
  await recordAgent(cryptoKey, { ...agent, pushEnabled: enabled });
};

/** The active (non-expired) authorized agents, decrypted, newest first. Shared across devices. */
export const listAgents = async (cryptoKey) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const snap = await getDocs(collection(db, 'vaults', vaultId, 'agents'));
  const now = Math.floor(Date.now() / 1000);
  const agents = [];
  for (const d of snap.docs) {
    const dec = await decryptData(d.data(), cryptoKey);
    if (dec) agents.push({ jti: d.id, ...dec });
  }
  return agents
    .filter((a) => !a.exp || a.exp > now)
    .sort((a, b) => (b.issuedAt || 0) - (a.issuedAt || 0));
};

/**
 * Revoke an agent: sign the revocation with the SAME per-app key that minted the capability and
 * publish it to the public revocations/{jti} denylist (cooperating RPs verify the signature
 * against the capability's own key, so only the issuer can revoke). Then drop the list record.
 */
export const revokeAgent = async (userId, cryptoKey, { jti, audience }) => {
  const { secretKey } = await deriveAppKeyPair(cryptoKey, audience);
  const sig = signMessageEd25519(revokeMessage(jti), secretKey);
  await setDoc(doc(db, 'revocations', jti), { jti, sig, revokedAt: Date.now() });
  await agentVaultWrite(cryptoKey, 'delete', jti, null);
  await logActivity(userId, `Revoked an agent for ${audience}`, 'info', 'ShieldX', cryptoKey, {
    agentJti: jti,
    agentAudience: audience,
  });
};
