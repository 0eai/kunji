import { collection, doc, getDoc, getDocs, onSnapshot, orderBy, query } from 'firebase/firestore';
import { db } from '../lib/firebase';
import { encryptData, decryptData } from '../lib/crypto';
import {
  deriveAppKeyPair,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../lib/crypto';
import { normalizeDomain } from '../lib/crypto/helpers';

// Vault writes go through a signed-writes Cloud Function (rules deny direct client
// writes). Same-origin via Hosting rewrite in production; override for local dev.
const VAULT_WRITE_URL = import.meta.env.VITE_VAULT_WRITE_URL || '/vault/write';

// Sign and POST a single vault write (set/delete an app doc). Proves master-key
// possession via the vault write key — the server verifies the signature + TOFU pubkey.
const callVaultWrite = async (vaultId, cryptoKey, op, appId, docPayload) => {
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const timestamp = Date.now();
  // Signed payload — keys/values must match what the function reconstructs.
  const signed = {
    appId,
    doc: docPayload ?? null,
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
      appId,
      doc: docPayload ?? undefined,
      publicKey: publicKeyB64,
      signedToken,
      timestamp,
    }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('vault_write_failed:' + (e.error || resp.status));
  }
};
import { logActivity } from './activityLog';

// Apps are keyed by the master-key-derived vaultId so the list syncs across every
// linked device. Activity logging stays per-device (userId).
const appsCol = (vaultId) => collection(db, 'vaults', vaultId, 'apps');
const appDoc = (vaultId, appId) => doc(db, 'vaults', vaultId, 'apps', appId);

// Deterministic doc id per domain, so a domain maps to exactly one app entry
// (same id across devices and logins — registration is idempotent). Normalized so
// casing variants of the same domain collapse to one entry.
const appIdForDomain = async (domain) => {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(normalizeDomain(domain)),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

export const listenToApps = (vaultId, cryptoKey, callback) => {
  const q = query(appsCol(vaultId), orderBy('createdAt', 'asc'));
  return onSnapshot(q, async (snap) => {
    const apps = [];
    const seenDomains = new Set();
    for (const d of snap.docs) {
      const raw = d.data();
      try {
        const decrypted = await decryptData(raw, cryptoKey);
        if (decrypted) {
          if (seenDomains.has(decrypted.domain)) continue; // collapse legacy duplicates
          seenDomains.add(decrypted.domain);
          apps.push({ id: d.id, ...decrypted, publicKey: raw.publicKey, createdAt: raw.createdAt });
        }
      } catch {
        // Skip corrupted docs silently
      }
    }
    callback(apps);
  });
};

export const registerApp = async (vaultId, cryptoKey, { name, domain, iconUrl = '' }, userId) => {
  // Per-app keypair is derived from the master key + domain (not stored).
  const { publicKey } = await deriveAppKeyPair(cryptoKey, domain);
  const pubKeyBase64 = exportEd25519PublicKey(publicKey);

  // Idempotent: one doc per domain. Only write (and log) the first time it's seen.
  const id = await appIdForDomain(domain);
  const ref = appDoc(vaultId, id);
  const existed = (await getDoc(ref)).exists();

  if (!existed) {
    const payload = await encryptData(
      { name, domain: normalizeDomain(domain), iconUrl },
      cryptoKey,
    );
    await callVaultWrite(vaultId, cryptoKey, 'set', id, { ...payload, publicKey: pubKeyBase64 });
    if (userId)
      await logActivity(userId, `Registered app: ${name}`, 'success', 'Link', cryptoKey, {
        domain,
      });
  }

  return { registeredAppId: id, publicKey: pubKeyBase64, isNew: !existed };
};

export const deleteApp = async (vaultId, registeredAppId, appName, cryptoKey, userId) => {
  await callVaultWrite(vaultId, cryptoKey, 'delete', registeredAppId, null);
  if (userId) await logActivity(userId, `Removed app: ${appName}`, 'info', 'Unlink', cryptoKey);
};

/**
 * One-time migration: copy apps from the legacy per-device path (users/{uid}/apps)
 * to the shared vault path (vaults/{vaultId}/apps) so previously-registered apps
 * reappear after the move to vaultId-keyed storage. Idempotent (same doc ids).
 */
export const migrateLegacyApps = async (userId, vaultId, cryptoKey) => {
  const legacy = await getDocs(collection(db, 'users', userId, 'apps'));
  if (legacy.empty) return 0;
  let n = 0;
  for (const d of legacy.docs) {
    const data = d.data();
    delete data.createdAt; // let the function set a fresh server timestamp
    await callVaultWrite(vaultId, cryptoKey, 'set', d.id, data);
    n++;
  }
  return n;
};

/**
 * Derive the stable per-app subject ID from the app's Ed25519 public key.
 * `sub = hex( SHA-256( utf8(publicKeyBase64) ) )`. Self-contained: the relying
 * party recomputes the same value from the public key it receives (no kunji UID
 * involved). Stable per (user, app) — the keypair is per app domain — and
 * different across apps, so apps cannot correlate the same kunji user.
 */
export const deriveSubFromPublicKey = async (publicKeyBase64) => {
  const data = new TextEncoder().encode(publicKeyBase64);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Parse a v2 discoverable-login QR payload.
 * Shape: { kunjiAuth:'v2', mode:'discoverable', sessionId, challenge, audience,
 *          callbackUrl, appName?, iconUrl?, expiresAt }
 * The callbackUrl must be same-site as the audience and HTTPS (localhost may use HTTP).
 */
export const parseQRPayload = (rawValue) => {
  let parsed;
  try {
    parsed = JSON.parse(rawValue);
  } catch {
    throw new Error('invalid_qr');
  }

  if (
    parsed?.kunjiAuth !== 'v2' ||
    parsed.mode !== 'discoverable' ||
    !parsed.sessionId ||
    !parsed.challenge ||
    !parsed.audience ||
    !parsed.callbackUrl ||
    !parsed.expiresAt
  ) {
    throw new Error('invalid_qr');
  }

  assertSameSiteCallback(parsed.audience, parsed.callbackUrl);

  if (Date.now() > parsed.expiresAt) {
    throw new Error('expired_qr');
  }

  return parsed;
};

// Bare public suffixes / TLDs that must never be accepted as an `audience` — otherwise
// `host.endsWith('.'+audience)` would match unrelated sites (e.g. audience:"com" →
// "evil.com"). Not exhaustive (a full PSL is the proper long-term fix); covers the
// common cases that break the same-site guarantee.
const PUBLIC_SUFFIXES = new Set([
  'com',
  'org',
  'net',
  'io',
  'co',
  'dev',
  'app',
  'xyz',
  'cc',
  'info',
  'biz',
  'me',
  'ai',
  'gg',
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.in',
  'co.jp',
  'com.br',
  'co.nz',
  'co.za',
  'com.mx',
  'com.sg',
  'com.hk',
]);

const normalizeHost = (h) =>
  String(h || '')
    .toLowerCase()
    .replace(/\.$/, '');

const isRegistrableDomain = (aud) => aud.includes('.') && !PUBLIC_SUFFIXES.has(aud);

// The callback must be same-site as the audience and HTTPS (HTTP only for localhost).
// The audience must be a plausible registrable domain — a bare TLD/public suffix is
// rejected so it can't be abused to relay assertions to an unrelated host.
const assertSameSiteCallback = (audience, callbackUrl) => {
  let cbUrl;
  try {
    cbUrl = new URL(callbackUrl);
  } catch {
    throw new Error('untrusted_callback');
  }
  const host = normalizeHost(cbUrl.hostname);
  const aud = normalizeHost(audience);
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  const secure = cbUrl.protocol === 'https:' || (isLocal && cbUrl.protocol === 'http:');
  if (isLocal) {
    if (!secure) throw new Error('untrusted_callback');
    return;
  }
  if (!isRegistrableDomain(aud)) throw new Error('untrusted_callback');
  const sameSite = host === aud || host.endsWith('.' + aud);
  if (!sameSite || !secure) throw new Error('untrusted_callback');
};

/**
 * Is `returnUrl` safe to render as a clickable link after sign-in? Must be HTTPS and
 * same-site as the audience (localhost allowed in dev). `returnUrl` is attacker-
 * controllable via the QR / deep link and is NOT part of the signed payload, so an
 * unvalidated link is an open-redirect / phishing amplifier inside the trusted wallet.
 */
export const isSafeReturnUrl = (returnUrl, audience) => {
  if (!returnUrl) return false;
  let u;
  try {
    u = new URL(returnUrl);
  } catch {
    return false;
  }
  const host = normalizeHost(u.hostname);
  const aud = normalizeHost(audience);
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  if (isLocal) return u.protocol === 'http:' || u.protocol === 'https:';
  if (u.protocol !== 'https:') return false;
  if (!isRegistrableDomain(aud)) return false;
  return host === aud || host.endsWith('.' + aud);
};

/**
 * Derive the per-app identity (public key + sub + whether it's new) WITHOUT writing
 * anything to the vault. Used to populate the approval screen before the user consents;
 * the actual `registerApp` write happens only on approval.
 */
export const deriveAppIdentity = async (vaultId, cryptoKey, domain) => {
  const { publicKey } = await deriveAppKeyPair(cryptoKey, domain);
  const pubKeyBase64 = exportEd25519PublicKey(publicKey);
  const id = await appIdForDomain(domain);
  const existed = (await getDoc(appDoc(vaultId, id))).exists();
  return { registeredAppId: id, publicKey: pubKeyBase64, isNew: !existed };
};

/**
 * Device-authorization: resolve a 6-digit code shown by a relying party (already
 * registered, so we know its domain) to its pending session. Returns the same
 * shape parseQRPayload yields, so submitDiscoverableAssertion can consume it.
 */
export const lookupSessionByCode = async (domain, code) => {
  const resp = await fetch(`https://${domain}/kunji/session?code=${encodeURIComponent(code)}`);
  if (resp.status === 404) throw new Error('invalid_code');
  if (resp.status === 410) throw new Error('expired_code');
  if (resp.status === 429) throw new Error('rate_limited');
  if (!resp.ok) throw new Error('lookup_failed');
  const s = await resp.json();
  if (!s.sessionId || !s.challenge || !s.audience || !s.callbackUrl)
    throw new Error('lookup_failed');
  if (s.audience !== domain) throw new Error('untrusted_callback');
  assertSameSiteCallback(s.audience, s.callbackUrl);
  return s; // { sessionId, challenge, audience, callbackUrl }
};

/**
 * Sign the discoverable-login assertion with the app's per-app key and POST it
 * to the relying party's callback URL. Kunji writes nothing to any shared store —
 * the only outbound effect is this single HTTPS POST to the app's own endpoint.
 */
export const submitDiscoverableAssertion = async (userId, cryptoKey, qr) => {
  // Reproduce the per-app keypair from the master key + audience domain.
  const { secretKey, publicKey } = await deriveAppKeyPair(cryptoKey, qr.audience);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const sub = await deriveSubFromPublicKey(publicKeyB64);

  const signedPayload = {
    sessionId: qr.sessionId,
    challenge: qr.challenge,
    audience: qr.audience,
    sub,
    timestamp: Date.now(),
  };
  const signedToken = signWithEd25519(signedPayload, secretKey);

  const resp = await fetch(qr.callbackUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: publicKeyB64, signedPayload, signedToken }),
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(`callback_rejected:${resp.status}${detail ? ` ${detail}` : ''}`);
  }

  await logActivity(userId, `Signed in to ${qr.audience}`, 'success', 'ShieldCheck', cryptoKey, {
    domain: qr.audience,
  });
  return { sub };
};

export const exportAllApps = async (vaultId, cryptoKey) => {
  const snap = await getDocs(appsCol(vaultId));
  const apps = [];
  for (const d of snap.docs) {
    const raw = d.data();
    try {
      const dec = await decryptData(raw, cryptoKey);
      if (dec)
        apps.push({
          id: d.id,
          name: dec.name,
          domain: dec.domain,
          iconUrl: dec.iconUrl,
          publicKey: raw.publicKey,
        });
    } catch {
      /* skip */
    }
  }
  return apps;
};
