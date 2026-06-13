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
import { setSessionIp } from '../lib/sessionMeta';
import { isValidScopeItem, scopeId } from '../lib/capability';

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
  // The function echoes our public IP; cache it so the shared activity log can record it.
  const data = await resp.json().catch(() => ({}));
  if (data?.ip) setSessionIp(data.ip);
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

export const registerApp = async (
  vaultId,
  cryptoKey,
  { name, domain, iconUrl = '', sharedProfile = false },
  userId,
) => {
  // Per-app keypair is derived from the master key + domain (not stored).
  const { publicKey } = await deriveAppKeyPair(cryptoKey, domain);
  const pubKeyBase64 = exportEd25519PublicKey(publicKey);

  // One doc per domain. Write the first time it's seen, OR when `sharedProfile` changes (so the
  // app-details "what this app sees" stays accurate). `sharedProfile` is wallet-only metadata — it
  // is NOT sent to the RP; the assertion's `claims` are the actual share. `createdAt` is preserved
  // by vaultWrite on re-writes.
  const id = await appIdForDomain(domain);
  const ref = appDoc(vaultId, id);
  const snap = await getDoc(ref);
  const existed = snap.exists();
  const prior = existed ? await decryptData(snap.data(), cryptoKey).catch(() => null) : null;

  if (!existed || !!prior?.sharedProfile !== !!sharedProfile) {
    const payload = await encryptData(
      { name, domain: normalizeDomain(domain), iconUrl, sharedProfile: !!sharedProfile },
      cryptoKey,
    );
    await callVaultWrite(vaultId, cryptoKey, 'set', id, { ...payload, publicKey: pubKeyBase64 });
    if (!existed && userId)
      await logActivity(userId, `Registered app: ${name}`, 'success', 'Link', cryptoKey, {
        domain: normalizeDomain(domain),
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
 * Shape: { kunjiAuth:'v2', sessionId, challenge, audience, expiresAt,
 *          mode?, callbackUrl?, appName?, iconUrl?, returnUrl?, scope?: string[] }
 * `mode` and `callbackUrl` are OPTIONAL (lean QR): `mode` defaults to 'discoverable', and an
 * omitted `callbackUrl` derives the same-site default `https://{audience}/kunji/callback`.
 * RPs with a non-default callback (custom path, or a decoupled host like the relay) include it.
 * The (provided or derived) callbackUrl must be same-site as the audience and HTTPS (localhost
 * may use HTTP). `scope` is an optional list of requested scopes (e.g. ['profile']) the wallet
 * only uses to OFFER a consent toggle. Older full QRs still parse (backward compatible).
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
    (parsed.mode !== undefined && parsed.mode !== 'discoverable') ||
    !parsed.sessionId ||
    !parsed.challenge ||
    !parsed.audience ||
    !parsed.expiresAt
  ) {
    throw new Error('invalid_qr');
  }

  if (
    parsed.scope !== undefined &&
    (!Array.isArray(parsed.scope) || !parsed.scope.every(isValidScopeItem))
  ) {
    throw new Error('invalid_qr');
  }

  // callbackUrl is optional: when omitted, derive the same-site default. The derived value is
  // always same-site as the (signed, user-shown) audience, so it can't be relayed cross-site.
  const callbackUrl =
    parsed.callbackUrl || `https://${normalizeHost(parsed.audience)}/kunji/callback`;
  assertSameSiteCallback(parsed.audience, callbackUrl);

  if (Date.now() > parsed.expiresAt) {
    throw new Error('expired_qr');
  }

  return { ...parsed, callbackUrl };
};

/** Does this parsed QR / session request the user's profile (Layer 2 consent)? */
export const requestsProfile = (qr) =>
  Array.isArray(qr?.scope) && qr.scope.some((s) => scopeId(s) === 'profile');

/** Does this parsed QR / session request a verified credential (a `vc:` scope item)? */
export const requestsCredentials = (qr) =>
  Array.isArray(qr?.scope) && qr.scope.some((s) => String(scopeId(s)).startsWith('vc:'));

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
    // A real-domain audience with a localhost callback is a §5.2 mismatch (relay attempt):
    // only allow the localhost shortcut when the audience is itself local (or unset).
    const audLocal = !aud || aud === host || aud === 'localhost' || aud === '127.0.0.1';
    if (!audLocal) throw new Error('untrusted_callback');
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
  if (isLocal) {
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    // Same §5.2 audience-binding as assertSameSiteCallback: a real-domain audience
    // with a localhost return URL is not same-site.
    return !aud || aud === host || aud === 'localhost' || aud === '127.0.0.1';
  }
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
 *
 * `claims` (optional) is the user's self-asserted profile to share with THIS app —
 * only passed when the user explicitly consented. It's signed (so it can't be
 * tampered in transit) but is NOT verified by anyone: the RP must treat it as
 * untrusted input. Absent claims ⇒ the RP falls back to the default identity.
 */
export const submitDiscoverableAssertion = async (userId, cryptoKey, qr, claims, vcPresentations) => {
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
  // Attach consented profile claims (fixed key order; the signer canonicalizes only
  // top-level keys, so the RP must round-trip this object verbatim — which it does).
  if (claims && (claims.name || claims.picture)) {
    signedPayload.claims = {};
    if (claims.name) signedPayload.claims.name = String(claims.name).slice(0, 60);
    if (claims.picture) signedPayload.claims.picture = String(claims.picture);
  }
  // Attach any presented verified credentials (signed over, so tamper-evident; the RP verifies each
  // issuer signature + holder binding locally). Optional + back-compatible.
  if (Array.isArray(vcPresentations) && vcPresentations.length) {
    signedPayload.vc_presentations = vcPresentations;
  }
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
    domain: normalizeDomain(qr.audience),
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
