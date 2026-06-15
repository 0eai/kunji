// Verified credentials (wallet side) — receive a credential from an issuer, store it encrypted in
// the vault, list/delete held credentials. Mirrors services/capability.js (agent storage): the
// vaultWrite function never sees the master key or plaintext. The credential binds to a per-issuer
// holder key (deriveCredentialHolderKey); the wallet presents it at login (see Dashboard/identity.js).
// See docs/verified-credentials.md.
import { collection, getDocs } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  deriveVaultId,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
  encryptData,
  decryptData,
  deriveCredentialHolderKey,
  deriveBbsHolderSecret,
  generateEd25519KeyPair,
  exportEd25519SecretKey,
  importEd25519SecretKey,
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveECDHSharedSecret,
} from '../lib/crypto';
import { holderJwkFor, parseSdJwt, matchCredentialsByScope } from '../lib/vc';
import { b64uToBytes, bytesToB64u } from '../lib/bbs';
import {
  parseCredentialOffer,
  buildProofJwt,
  buildDpopProof,
  buildVpToken,
  buildBbsVpToken,
  buildVpResponse,
  parseClientIdScheme,
} from '../lib/oid4vc';
import { encryptJwe } from '../lib/jwe';
import { resolveDidKey, didWebToUrl } from '../lib/did';
import { verifyX5cChain, verifyEs256Jws } from '../lib/x509';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

// Unlinkability v2 (verified-credentials.md §7): ask the issuer for a small batch of one-time-use
// copies, each bound to a DISTINCT random holder key, so the wallet can spend a fresh copy per
// presentation — no two presentations share an issuer signature or a holder key (`cnf.jwk`). Tunable:
// trades issuer-side issuance volume for presentations-before-refill. Issuers that don't support batch
// degrade gracefully to a single reusable (v1) credential.
const BATCH_SIZE = 5;

const VAULT_WRITE_URL = import.meta.env.VITE_VAULT_WRITE_URL || '/vault/write';
const CREDENTIAL_POLL_URL = import.meta.env.VITE_CREDENTIAL_POLL_URL || '/credential/poll';

const randomHex = (n) => {
  const b = new Uint8Array(n);
  window.crypto.getRandomValues(b);
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
};

const randomCredId = () => {
  const b = new Uint8Array(16);
  window.crypto.getRandomValues(b);
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
};

// Signed write of an encrypted credential record to the shared vault (vaultWrite kind:'credential').
// Mirrors services/capability.js agentVaultWrite — the function only sees ciphertext + the vault
// write public key + a signature.
const credentialVaultWrite = async (cryptoKey, op, credId, docPayload) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const timestamp = Date.now();
  const signed = {
    appId: credId,
    doc: docPayload ?? null,
    kind: 'credential',
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
      appId: credId,
      kind: 'credential',
      doc: docPayload ?? undefined,
      publicKey: publicKeyB64,
      signedToken,
      timestamp,
    }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('credential_write_failed:' + (e.error || resp.status));
  }
};

/**
 * Store a received SD-JWT credential (+ metadata) encrypted in the vault. A v2 one-time-use copy also
 * carries `holderSk` (the per-copy random holder secret key, base64), a `poolId` grouping its batch,
 * and `oneTime:true` (spent on presentation). A v1 credential omits these (its holder key is re-derived
 * from the issuer; reusable). Back-compat: legacy records simply have none of the three fields.
 */
export const storeCredential = async (cryptoKey, { vct, iss, sdjwt, bbs, format, holderSk, poolId, oneTime, brand, verifiedVia }) => {
  const credId = randomCredId();
  const record = { vct, iss, receivedAt: Math.floor(Date.now() / 1000) };
  if (format) record.format = format; // absent ⇒ SD-JWT (v1/v2); 'bbs' ⇒ unlinkable (v3)
  if (sdjwt) record.sdjwt = sdjwt;
  if (bbs) record.bbs = bbs; // the BBS credential blob (mintBbsCredential output)
  if (holderSk) record.holderSk = holderSk;
  if (poolId) record.poolId = poolId;
  if (oneTime) record.oneTime = true;
  // Issuer display, captured ONCE at receipt + shown locally (so viewing a held credential needs no network
  // call — a per-view fetch would let the issuer see when you hold/view it). See fetchIssuerDisplay.
  if (brand) record.brand = brand;
  if (verifiedVia) record.verifiedVia = verifiedVia;
  const payload = await encryptData(record, cryptoKey);
  await credentialVaultWrite(cryptoKey, 'set', credId, payload);
  return { credId, vct, iss, poolId, format };
};

// Generate N random holder keypairs for a batch — each becomes one one-time copy's `cnf.jwk`.
const makeHolderKeys = (n) =>
  Array.from({ length: n }, () => {
    const { secretKey, publicKey } = generateEd25519KeyPair();
    return { secretKey, publicKey, jwk: holderJwkFor(publicKey), skB64: exportEd25519SecretKey(secretKey) };
  });

// Normalize an issuer's response into the SD-JWT strings it returned (string array, object array
// `[{credential}]`, or a single `{credential}` from a non-batch issuer). Robust to draft shape diffs.
const credentialsFrom = (data) => {
  const toStr = (c) => (typeof c === 'string' ? c : c?.credential);
  if (Array.isArray(data?.credentials)) return data.credentials.map(toStr).filter(Boolean);
  return data?.credential ? [toStr(data.credential)].filter(Boolean) : [];
};

/**
 * Validate + store a batch of issued SD-JWTs under one `poolId`. Each copy must (a) have `iss` == the
 * origin we asked, and (b) be bound (`cnf.jwk`) to one of the holder keys we offered — matched by key,
 * not order, and each key used once (so the issuer can't bind two copies to the same key, which would
 * relink them). A batch of >1 is `oneTime` (spent per presentation); a single (non-batch issuer) is a
 * reusable v1 credential. Returns `{ poolId, count, vct, iss }`.
 */
const storeBatch = async (cryptoKey, origin, sdjwts, holderKeys) => {
  if (!sdjwts.length) throw new Error('The issuer returned no credential.');
  const byX = new Map(holderKeys.map((h) => [h.jwk.x, h]));
  const oneTime = sdjwts.length > 1;
  const poolId = randomCredId();
  let count = 0;
  let vct;
  let display = null;
  for (const sdjwt of sdjwts) {
    const { issuerClaims } = parseSdJwt(sdjwt);
    if (issuerClaims.iss !== origin) throw new Error('Issuer identity mismatch — cannot bind credential.');
    const h = byX.get(issuerClaims.cnf?.jwk?.x);
    if (!h) throw new Error('Issuer bound a credential to a key we did not offer.');
    byX.delete(issuerClaims.cnf.jwk.x); // each holder key is used at most once
    if (!display) display = await fetchIssuerDisplay(origin, issuerClaims.vct); // once per batch, best-effort
    await storeCredential(cryptoKey, { vct: issuerClaims.vct, iss: origin, sdjwt, holderSk: h.skB64, poolId, oneTime, brand: display?.brand, verifiedVia: display?.verifiedVia });
    vct = issuerClaims.vct;
    count++;
  }
  return { poolId, count, vct, iss: origin };
};

/**
 * Collapse a flat held list into one logical credential per pool (a v1 credential is its own pool of
 * one), each with a `remaining` count and whether its copies are one-time. For the credentials list UI.
 */
export const groupByPool = (held) => {
  const groups = new Map();
  for (const c of held || []) {
    const key = c.poolId || c.credId;
    let g = groups.get(key);
    if (!g) {
      g = { key, vct: c.vct, iss: c.iss, brand: c.brand || null, verifiedVia: c.verifiedVia || null, oneTime: false, unlinkable: false, copies: [] };
      groups.set(key, g);
    }
    if (c.oneTime) g.oneTime = true;
    if (c.format === 'bbs') g.unlinkable = true; // v3 — one credential, unlinkable proofs
    g.copies.push(c);
  }
  return Array.from(groups.values())
    .map((g) => ({
      ...g,
      remaining: g.copies.length,
      sample: g.copies.slice().sort((a, b) => (b.receivedAt || 0) - (a.receivedAt || 0))[0],
    }))
    .sort((a, b) => (b.sample?.receivedAt || 0) - (a.sample?.receivedAt || 0));
};

/**
 * One unused copy per logical credential that satisfies `scope` → `[{ cred, disclose }]`. Wraps
 * `matchCredentialsByScope` (which returns every matching copy, flat) and collapses by pool, so a
 * 5-copy pool presents ONE copy (the one then spent) — never five identical rows / five presentations.
 */
export const selectForPresentation = (held, scope) => {
  const seen = new Set();
  const out = [];
  for (const m of matchCredentialsByScope(held, scope)) {
    const key = m.cred.poolId || m.cred.credId;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(m);
  }
  return out;
};

/** The held credentials, decrypted, newest first. Shared across devices. */
export const listCredentials = async (cryptoKey) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const snap = await getDocs(collection(db, 'vaults', vaultId, 'credentials'));
  const out = [];
  for (const d of snap.docs) {
    const dec = await decryptData(d.data(), cryptoKey);
    if (dec) out.push({ credId: d.id, ...dec });
  }
  return out.sort((a, b) => (b.receivedAt || 0) - (a.receivedAt || 0));
};

/** Delete a held credential. The issuer's StatusList owns real revocation; this drops our copy. */
export const deleteCredential = async (cryptoKey, credId) => {
  await credentialVaultWrite(cryptoKey, 'delete', credId, null);
};

/**
 * Receive a credential from an issuer (synchronous): ask for a batch of one-time-use copies, each bound
 * to a DISTINCT random holder key (`POST {origin}/issue { holderJwks:[…] }`), and store them under one
 * pool (unlinkability v2 §7). An issuer that only understands the single `holderJwk` returns one
 * `credential` → a reusable v1 credential (graceful fallback). The issuer's `iss` MUST equal the origin
 * (so it can't bind a credential to a foreign issuer). Returns `{ poolId, count, vct, iss }`.
 */
export const receiveFromIssuer = async (cryptoKey, issuerOrigin) => {
  const origin = String(issuerOrigin || '')
    .trim()
    .replace(/\/$/, '');
  if (!/^https?:\/\//.test(origin)) throw new Error('Enter the issuer URL (https://…).');
  const holderKeys = makeHolderKeys(BATCH_SIZE);
  let resp;
  try {
    resp = await fetch(`${origin}/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // `holderJwks` is the batch ask; `holderJwk` keeps a pre-batch issuer working (one copy back).
      body: JSON.stringify({ holderJwks: holderKeys.map((h) => h.jwk), holderJwk: holderKeys[0].jwk }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!resp.ok) throw new Error('The issuer declined to issue a credential.');
  const sdjwts = credentialsFrom(await resp.json().catch(() => ({})));
  return storeBatch(cryptoKey, origin, sdjwts, holderKeys);
};

// ── Async issuance via the kunji relay ───────────────────────────────────────
// Poll the relay once: returns the decrypted SD-JWT string, or null if not deposited yet.
const pollCredentialOnce = async (transportPriv, sessionId) => {
  const resp = await fetch(`${CREDENTIAL_POLL_URL}?sessionId=${sessionId}`);
  if (resp.status === 410) throw new Error('Issuance expired before the issuer delivered it.');
  if (!resp.ok) return null; // 404 = not yet, 429 = backing off
  const { issuerPubE, encryptedCredential } = await resp.json();
  const shared = await deriveECDHSharedSecret(transportPriv, await importECDHPublicKey(issuerPubE));
  return decryptData(encryptedCredential, shared); // the SD-JWT string
};

/**
 * Receive a credential from an issuer via the kunji relay (out-of-band issuance): derive the
 * per-issuer holder key + an ephemeral transport key, hand the issuer
 * { holderJwk, transportPub, sessionId } so it can ECDH-encrypt the credential and deposit it to
 * /credential/offer, then poll /credential/poll and decrypt. Use when the issuer issues asynchronously
 * (the synchronous `receiveFromIssuer` is the simple case).
 */
export const receiveViaRelay = async (cryptoKey, issuerOrigin, { tries = 60, intervalMs = 2000 } = {}) => {
  const origin = String(issuerOrigin || '')
    .trim()
    .replace(/\/$/, '');
  if (!/^https?:\/\//.test(origin)) throw new Error('Enter the issuer URL (https://…).');
  const { publicKey } = await deriveCredentialHolderKey(cryptoKey, origin);
  const transport = await generateECDHKeyPair();
  const transportPub = await exportECDHPublicKey(transport.publicKey);
  const sessionId = randomHex(32);
  let resp;
  try {
    resp = await fetch(`${origin}/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ holderJwk: holderJwkFor(publicKey), transportPub, sessionId, deposit: true }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!resp.ok) throw new Error('The issuer declined to issue a credential.');
  for (let i = 0; i < tries; i++) {
    const sdjwt = await pollCredentialOnce(transport.privateKey, sessionId);
    if (sdjwt) {
      const { issuerClaims } = parseSdJwt(sdjwt);
      if (issuerClaims.iss !== origin) throw new Error('Issuer identity mismatch — cannot bind credential.');
      const display = await fetchIssuerDisplay(origin, issuerClaims.vct);
      return storeCredential(cryptoKey, { vct: issuerClaims.vct, iss: issuerClaims.iss, sdjwt, brand: display?.brand, verifiedVia: display?.verifiedVia });
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('Timed out waiting for the issuer to deliver the credential.');
};

// ── Unlinkable credentials (v3, BBS) ─────────────────────────────────────────
// One credential derives a fresh, randomized zero-knowledge proof per presentation, so presentations
// share no correlation handle — no signature, no holder key — without issuing N copies (v2). See
// docs/verified-credentials.md §7. NOTE (this slice): replay-protected (the proof binds aud+nonce) but
// not yet holder-bound — a leaked credential blob is transferable; holder binding is the next slice.

/** Resolve an issuer's BBS public key (the `alg:'BBS'` entry) from its `.well-known` → Uint8Array. */
export const getIssuerBbsKey = async (iss) => {
  const u = httpsOrLoopback(iss);
  if (!u) throw new Error('issuer_origin_invalid');
  const resp = await fetch(`${u.origin}/.well-known/kunji-issuer.json`);
  if (!resp.ok) throw new Error('issuer_unreachable');
  const k = ((await resp.json()).keys || []).find((x) => x.alg === 'BBS' && x.pub);
  if (!k) throw new Error('issuer_has_no_bbs_key');
  return b64uToBytes(k.pub);
};

/**
 * Receive an UNLINKABLE (BBS) credential from an issuer: `POST {origin}/issue { format:'bbs' }` → store
 * the BBS credential blob (format:'bbs'). One credential suffices (no batch — v3 needs no copies). The
 * issuer's `iss` MUST equal the origin. Returns `{ credId, vct, iss, format:'bbs' }`.
 */
export const receiveBbsFromIssuer = async (cryptoKey, issuerOrigin) => {
  const origin = String(issuerOrigin || '')
    .trim()
    .replace(/\/$/, '');
  if (!/^https?:\/\//.test(origin)) throw new Error('Enter the issuer URL (https://…).');
  // Holder binding (non-transferability): a master-key-derived secret the issuer signs as an undisclosed
  // message. Sent at issuance, NEVER stored in the blob — re-derived to present. [§7 v3]
  const holderBinding = bytesToB64u(await deriveBbsHolderSecret(cryptoKey, origin));
  let resp;
  try {
    resp = await fetch(`${origin}/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: 'bbs', holderBinding }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!resp.ok) throw new Error('The issuer declined to issue a credential.');
  const { credential } = await resp.json().catch(() => ({}));
  if (credential?.format !== 'bbs') throw new Error('The issuer did not return an unlinkable credential.');
  if (credential.iss !== origin) throw new Error('Issuer identity mismatch — cannot trust credential.');
  const display = await fetchIssuerDisplay(origin, credential.vct);
  return storeCredential(cryptoKey, { vct: credential.vct, iss: credential.iss, format: 'bbs', bbs: credential, brand: display?.brand, verifiedVia: display?.verifiedVia });
};

/**
 * Build a BBS presentation for the discoverable-login assertion: a fresh unlinkable proof bound to
 * (audience, challenge), revealing only `disclose`, serialized as a tagged string (so `vc_presentations`
 * stays a string[] and the assertion's canonical-JSON signing is undisturbed). The RP dispatches on the
 * `bbs~` tag → verifyBbsPresentation. Mirrors `buildBbsVpToken` (which the OID4VP present path uses).
 */
export const presentBbsForLogin = async (cryptoKey, { cred, disclose, audience, nonce }) => {
  const issuerPublicKey = await getIssuerBbsKey(cred.iss);
  const holderSecret = cred.bbs?.holderBound ? await deriveBbsHolderSecret(cryptoKey, cred.iss) : undefined;
  return buildBbsVpToken({ credential: cred.bbs, disclose, clientId: audience, nonce, issuerPublicKey, holderSecret });
};

// ── OpenID4VC interop (wallet side) ──────────────────────────────────────────
// The standard rails over the SAME SD-JWT VC + per-issuer holder key. See docs/oid4vc.md.

// An OpenID4VC counterparty endpoint must be HTTPS (except a loopback host for local dev) — the same
// anti-MITM posture parseQRPayload/isSafeReturnUrl enforce for login callbacks. Returns the parsed URL
// or null.
const isLoopbackHost = (h) => h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
const httpsOrLoopback = (urlStr) => {
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && !isLoopbackHost(u.hostname)) return null;
  return u;
};

// Capture an issuer's display info ONCE at receipt: the brand name + the verification method for this vct,
// from the issuer's published OpenID4VCI metadata. Stored on the credential record so the wallet can show
// "Issued by {brand} · verified via {method}" with NO network call when the user later views it (a per-view
// fetch would leak hold/view timing to the issuer). Best-effort — null on any failure (UI falls back to host).
const fetchIssuerDisplay = async (origin, vct) => {
  const u = httpsOrLoopback(origin);
  if (!u) return null;
  try {
    const resp = await fetch(`${u.origin}/.well-known/openid-credential-issuer`);
    if (!resp.ok) return null;
    const meta = await resp.json();
    const brand = meta?.brand?.name || null;
    const methods = meta?.credential_configurations_supported?.[vct]?.verification_methods;
    const verifiedVia = Array.isArray(methods) && methods.length ? methods[0] : null;
    return brand || verifiedVia ? { brand, verifiedVia } : null;
  } catch {
    return null;
  }
};

/**
 * Is a verifier's response endpoint safe to send a vp_token to? It must be HTTPS (except loopback) AND
 * its host must match the verifier's displayed `client_id`. Without this, an attacker could craft an
 * OpenID4VP request showing a trusted `client_id` while pointing `response_uri` at its own server: the
 * vp_token is bound to that `client_id`, so the attacker can RELAY the captured presentation to the real
 * verifier (response-redirection / verifier impersonation). Binding the destination host to the shown
 * identity closes that. [S20]
 */
export const responseTargetTrusted = (clientId, responseUri) => {
  const u = httpsOrLoopback(responseUri);
  if (!u || !clientId) return false;
  const scheme = parseClientIdScheme(clientId);
  // x509_san_dns binds to the SAN DNS name; did:web to the DID's host; did:jwk has NO host, so it can't be
  // host-bound here — the caller must require an encrypted response (direct_post.jwt) instead. [S20]
  if (scheme.scheme === 'x509_san_dns') return u.hostname === scheme.value;
  if (scheme.scheme === 'did') {
    if (clientId.startsWith('did:web:')) {
      try {
        return u.hostname === new URL(didWebToUrl(clientId)).hostname;
      } catch {
        return false;
      }
    }
    return false; // did:jwk — no host binding
  }
  return u.hostname === clientId || u.origin === clientId;
};

// Empty by default ⇒ x509_san_dns fails closed in the shipped wallet build (it can't run a CA program).
// A deployment that trusts specific CAs would pin their DER certs here. did:web / did:jwk still work. [x509]
export const WALLET_TRUST_ANCHORS = [];

/** Resolve a verifier DID key (did:jwk embedded / did:web fetched) for verifyRequestObject. */
export const resolveVerifierDidKey = (did, opts = {}) => resolveDidKey(did, { ...opts, fetchImpl: fetch });

/**
 * Verify an x509_san_dns request: the x5c chain (SAN == client_id, validity, ECDSA-P256-SHA256 to a pinned
 * anchor — scoped, see docs/oid4vc.md) then the request's ES256 JWS with the leaf key. Injected into
 * verifyRequestObject so the EdDSA-pure envelope never imports the DER parser. [x509]
 */
export const verifyVerifierX509 = async ({ requestJwt, x5c, dnsName, trustAnchors, now }) => {
  const chain = verifyX5cChain({ x5c, dnsName, trustAnchors: trustAnchors || WALLET_TRUST_ANCHORS, now });
  if (!chain.ok) return chain;
  if (!verifyEs256Jws(requestJwt, chain.leafPublicKey)) return { ok: false, error: 'bad_request_signature' };
  return { ok: true };
};

/**
 * Resolve a verifier's request-signing keys from its own `.well-known/kunji-verifier.json` — the
 * HTTPS-anchored client_id scheme (mirrors `fetchIssuerKeys`). `clientId` is the verifier's origin
 * (https except loopback dev). Used to verify a signed OpenID4VP request. [verifier authentication]
 */
export const fetchVerifierKeys = async (clientId) => {
  const u = httpsOrLoopback(clientId);
  if (!u) throw new Error('verifier_origin_invalid');
  const resp = await fetch(`${u.origin}/.well-known/kunji-verifier.json`);
  if (!resp.ok) throw new Error('verifier_unreachable');
  return (await resp.json()).keys || [];
};

/**
 * Receive a credential via an OpenID4VCI credential offer (pre-authorized_code grant): parse the offer,
 * exchange the pre-auth code for an access token + c_nonce, then request a BATCH with N holder proof
 * JWTs (`proofs.jwt:[…]`), each over a distinct random holder key (its `jwk` becomes that copy's
 * `cnf.jwk`) — unlinkability v2 §7. An issuer that only reads the single `proof` returns one credential
 * → a reusable v1 credential (graceful fallback). Same issuer-origin guard as `receiveFromIssuer`.
 * Returns `{ poolId, count, vct, iss }`.
 */
// Map an issuer error response to a user-facing message. A consumed/expired single-use offer comes back as
// `invalid_grant` (at /token) or `invalid_token` (a reused access token at /credential) — say so clearly
// instead of a generic "declined", so the user knows to fetch a fresh offer.
const issuerDeclineMessage = async (resp, fallback) => {
  const code = await resp
    .json()
    .then((b) => b?.error)
    .catch(() => null);
  if (code === 'invalid_grant' || code === 'invalid_token')
    return 'This credential offer was already used or has expired — get a fresh one.';
  return fallback;
};

export const receiveViaOffer = async (cryptoKey, offerInput) => {
  let offer;
  try {
    offer = parseCredentialOffer(offerInput);
  } catch {
    throw new Error('Not a valid credential offer.');
  }
  const issuer = String(offer.credentialIssuer || '')
    .trim()
    .replace(/\/$/, '');
  if (!httpsOrLoopback(issuer)) throw new Error('Credential offer issuer must be an https:// URL.'); // [S21]
  if (!offer.preAuthorizedCode) {
    // The authorization_code grant needs an authorization-server redirect, which a QR/no-redirect wallet
    // doesn't drive — kunji supports pre-authorized offers. (lib + demos exercise authorization_code.)
    if (offer.authorizationCode) throw new Error('This issuer requires sign-in (authorization_code); kunji accepts pre-authorized offers.');
    throw new Error('Unsupported offer (needs a pre-authorized code).');
  }

  // A fresh ephemeral DPoP key per receive (issuer-facing only — no linkability concern). We always
  // present a DPoP proof at /token; if the issuer echoes token_type:'DPoP' we sender-constrain the
  // credential request too. A legacy issuer ignores the header and returns a bearer token → unchanged. [DPoP]
  const dpopKey = generateEd25519KeyPair();
  const dpopFor = (path, accessToken) =>
    buildDpopProof({
      htu: `${issuer}${path}`,
      htm: 'POST',
      accessToken,
      holderSecretKey: dpopKey.secretKey,
      holderPublicKey: dpopKey.publicKey,
    });

  let tokenResp;
  try {
    tokenResp = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', DPoP: await dpopFor('/token') },
      body: JSON.stringify({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.preAuthorizedCode }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!tokenResp.ok) throw new Error(await issuerDeclineMessage(tokenResp, 'The issuer declined the offer.'));
  const { access_token, c_nonce, token_type } = await tokenResp.json().catch(() => ({}));
  if (!access_token) throw new Error('The issuer returned no access token.');
  const useDpop = String(token_type || '').toLowerCase() === 'dpop';

  const holderKeys = makeHolderKeys(BATCH_SIZE);
  const proofs = holderKeys.map((h) =>
    buildProofJwt({ holderSecretKey: h.secretKey, holderPublicKey: h.publicKey, audience: issuer, cNonce: c_nonce }),
  );
  const credHeaders = useDpop
    ? { 'Content-Type': 'application/json', Authorization: `DPoP ${access_token}`, DPoP: await dpopFor('/credential', access_token) }
    : { 'Content-Type': 'application/json', Authorization: `Bearer ${access_token}` };
  let credResp;
  try {
    credResp = await fetch(`${issuer}/credential`, {
      method: 'POST',
      headers: credHeaders,
      // `proofs` is the batch ask; `proof` keeps a pre-batch issuer working (one copy back).
      body: JSON.stringify({
        format: 'vc+sd-jwt',
        proofs: { jwt: proofs },
        proof: { proof_type: 'jwt', jwt: proofs[0] },
      }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!credResp.ok) throw new Error(await issuerDeclineMessage(credResp, 'The issuer declined to issue a credential.'));
  const sdjwts = credentialsFrom(await credResp.json().catch(() => ({})));
  return storeBatch(cryptoKey, issuer, sdjwts, holderKeys);
};

/**
 * Present a held credential to an OpenID4VP verifier (direct_post): build a vp_token (KB-JWT bound to
 * the verifier's `client_id` + the request `nonce`, signed by the per-issuer holder key) + a
 * presentation_submission, and POST them to the request's `response_uri`. Returns the verifier's result.
 */
export const presentViaOid4vp = async (cryptoKey, request, { cred, disclose }) => {
  if (!request?.responseUri) throw new Error('Invalid request (no response endpoint).');
  // Bind the response destination to the shown verifier identity (anti response-redirection). [S20]
  if (!responseTargetTrusted(request.clientId, request.responseUri))
    throw new Error('Untrusted verifier: the response endpoint does not match its identity.');
  // Branch by credential format: BBS (v3) derives an unlinkable proof from the issuer's BBS key; SD-JWT
  // (v1/v2) signs a KB-JWT with the holder key. Both yield a string vp_token for buildVpResponse.
  let vpToken;
  if (cred.format === 'bbs') {
    const issuerPublicKey = await getIssuerBbsKey(cred.iss);
    const holderSecret = cred.bbs?.holderBound ? await deriveBbsHolderSecret(cryptoKey, cred.iss) : undefined;
    vpToken = await buildBbsVpToken({ credential: cred.bbs, disclose, clientId: request.clientId, nonce: request.nonce, issuerPublicKey, holderSecret });
  } else {
    const holderSecretKey = await holderKeyFor(cryptoKey, cred);
    vpToken = await buildVpToken({ sdjwt: cred.sdjwt, disclose, clientId: request.clientId, nonce: request.nonce, holderSecretKey });
  }
  // The direct_post body differs by query form (DCQL → vp_token keyed by id; PD → vp_token + submission).
  const responseBody = buildVpResponse({ request, presentation: vpToken });
  // Encrypted response (response_mode: direct_post.jwt): JWE-encrypt the vp_token to the verifier's
  // published encryption key (from the verified request's client_metadata) so the presentation isn't
  // readable on the wire. Else post it in cleartext (the default).
  let postBody = responseBody;
  if (request.responseMode === 'direct_post.jwt') {
    const encJwk = (request.clientMetadata?.jwks?.keys || []).find((k) => k.crv === 'P-256');
    if (!encJwk) throw new Error('Verifier asked for an encrypted response but published no encryption key.');
    postBody = { response: await encryptJwe(responseBody, encJwk), state: request.state };
  }
  let resp;
  try {
    resp = await fetch(request.responseUri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(postBody),
    });
  } catch {
    throw new Error('Could not reach the verifier.');
  }
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(body.error || 'The verifier rejected the presentation.');
  await spendIfOneTime(cryptoKey, cred); // a one-time copy is consumed on a successful presentation
  return body;
};

/**
 * The holder secret key to present `cred` with: a v2 one-time copy carries its own random `holderSk`
 * (use it); a v1 / legacy credential re-derives the per-issuer key. Lets old and new credentials coexist.
 */
export const holderKeyFor = async (cryptoKey, cred) =>
  cred.holderSk ? importEd25519SecretKey(cred.holderSk) : (await deriveCredentialHolderKey(cryptoKey, cred.iss)).secretKey;

/** Delete a one-time copy after it's been presented (best-effort; v1 credentials are left in place). */
export const spendIfOneTime = async (cryptoKey, cred) => {
  if (!cred?.oneTime || !cred.credId) return;
  try {
    await deleteCredential(cryptoKey, cred.credId);
  } catch {
    /* best-effort: a failed delete just means a copy may be reused — no security impact */
  }
};
