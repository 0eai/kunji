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
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveECDHSharedSecret,
} from '../lib/crypto';
import { holderJwkFor, parseSdJwt } from '../lib/vc';
import {
  parseCredentialOffer,
  buildProofJwt,
  buildVpToken,
  buildPresentationSubmission,
} from '../lib/oid4vc';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

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

/** Store a received SD-JWT credential (+ metadata) encrypted in the vault. */
export const storeCredential = async (cryptoKey, { vct, iss, sdjwt }) => {
  const credId = randomCredId();
  const payload = await encryptData(
    { vct, iss, sdjwt, receivedAt: Math.floor(Date.now() / 1000) },
    cryptoKey,
  );
  await credentialVaultWrite(cryptoKey, 'set', credId, payload);
  return { credId, vct, iss };
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
 * Receive a credential from an issuer (synchronous): derive the per-issuer holder key, ask the issuer
 * to mint a credential bound to it (`POST {origin}/issue { holderJwk }`), and store the SD-JWT.
 * The issuer's `iss` MUST equal the origin we derived against (so presentation re-derives the same
 * holder key) — well-behaved issuers set `iss` to their own origin.
 */
export const receiveFromIssuer = async (cryptoKey, issuerOrigin) => {
  const origin = String(issuerOrigin || '')
    .trim()
    .replace(/\/$/, '');
  if (!/^https?:\/\//.test(origin)) throw new Error('Enter the issuer URL (https://…).');
  const { publicKey } = await deriveCredentialHolderKey(cryptoKey, origin);
  let resp;
  try {
    resp = await fetch(`${origin}/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ holderJwk: holderJwkFor(publicKey) }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!resp.ok) throw new Error('The issuer declined to issue a credential.');
  const { credential } = await resp.json().catch(() => ({}));
  if (!credential) throw new Error('The issuer returned no credential.');
  const { issuerClaims } = parseSdJwt(credential);
  if (issuerClaims.iss !== origin) throw new Error('Issuer identity mismatch — cannot bind credential.');
  return storeCredential(cryptoKey, { vct: issuerClaims.vct, iss: issuerClaims.iss, sdjwt: credential });
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
      return storeCredential(cryptoKey, { vct: issuerClaims.vct, iss: issuerClaims.iss, sdjwt });
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('Timed out waiting for the issuer to deliver the credential.');
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
  return u.hostname === clientId || u.origin === clientId;
};

/**
 * Receive a credential via an OpenID4VCI credential offer (pre-authorized_code grant): parse the offer,
 * exchange the pre-auth code for an access token + c_nonce, then request the credential with a holder
 * proof JWT (its `jwk` becomes the credential's `cnf.jwk`). Same holder-binding + issuer-origin guard as
 * `receiveFromIssuer`, so presentation re-derives the same per-issuer holder key.
 */
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
  if (!offer.preAuthorizedCode) throw new Error('Unsupported offer (needs a pre-authorized code).');

  const { secretKey, publicKey } = await deriveCredentialHolderKey(cryptoKey, issuer);

  let tokenResp;
  try {
    tokenResp = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.preAuthorizedCode }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!tokenResp.ok) throw new Error('The issuer declined the offer.');
  const { access_token, c_nonce } = await tokenResp.json().catch(() => ({}));
  if (!access_token) throw new Error('The issuer returned no access token.');

  const proofJwt = buildProofJwt({ holderSecretKey: secretKey, holderPublicKey: publicKey, audience: issuer, cNonce: c_nonce });
  let credResp;
  try {
    credResp = await fetch(`${issuer}/credential`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'vc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
    });
  } catch {
    throw new Error('Could not reach the issuer.');
  }
  if (!credResp.ok) throw new Error('The issuer declined to issue a credential.');
  const { credential } = await credResp.json().catch(() => ({}));
  if (!credential) throw new Error('The issuer returned no credential.');
  const { issuerClaims } = parseSdJwt(credential);
  if (issuerClaims.iss !== issuer) throw new Error('Issuer identity mismatch — cannot bind credential.');
  return storeCredential(cryptoKey, { vct: issuerClaims.vct, iss: issuerClaims.iss, sdjwt: credential });
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
  const { secretKey } = await deriveCredentialHolderKey(cryptoKey, cred.iss);
  const vpToken = await buildVpToken({
    sdjwt: cred.sdjwt,
    disclose,
    clientId: request.clientId,
    nonce: request.nonce,
    holderSecretKey: secretKey,
  });
  const presentationSubmission = buildPresentationSubmission(request.presentationDefinition);
  let resp;
  try {
    resp = await fetch(request.responseUri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken, presentation_submission: presentationSubmission, state: request.state }),
    });
  } catch {
    throw new Error('Could not reach the verifier.');
  }
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(body.error || 'The verifier rejected the presentation.');
  return body;
};
