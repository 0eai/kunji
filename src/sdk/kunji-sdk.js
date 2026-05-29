/**
 * kunji-sdk.js
 * Embed this in your web app's login page to add Kunji QR passwordless auth.
 *
 * Usage:
 *   const auth = new KunjiAuth({
 *     functionsBaseUrl: 'https://<region>-<project>.cloudfunctions.net',
 *     ownerUid: '<kunji-user-firebase-uid>',
 *     registeredAppId: '<uuid-from-kunji-registered-apps>',
 *   });
 *
 *   const { sessionId, qrData } = await auth.createSession();
 *   // Render qrData as a QR code image
 *
 *   auth.pollSession(sessionId, {
 *     onApproved: async ({ signedToken, signedPayload }) => {
 *       const pubKey = await auth.getPublicKey();
 *       const valid = await auth.verifyToken(signedToken, signedPayload, pubKey);
 *       if (valid) grantAccess(signedPayload.userId);
 *     },
 *     onDenied:  () => showError('Login denied'),
 *     onExpired: () => showError('QR code expired'),
 *   });
 */

class KunjiAuth {
  /**
   * @param {object} opts
   * @param {string}  opts.ownerUid        - Firebase UID of the Kunji user
   * @param {string}  opts.registeredAppId - UUID from Kunji app registration
   *
   * Supply ONE of:
   * @param {string}  [opts.functionsBaseUrl] - https://REGION-PROJECT.cloudfunctions.net
   * @param {object}  [opts.functionUrls]     - Direct URLs per function:
   *   { createSession, pollSession, getPublicKey }
   */
  constructor({ functionsBaseUrl, functionUrls, ownerUid, registeredAppId }) {
    this.baseUrl = functionsBaseUrl ? functionsBaseUrl.replace(/\/$/, '') : null;
    this.functionUrls = functionUrls || null;
    this.ownerUid = ownerUid;
    this.registeredAppId = registeredAppId;
    this._pollTimer = null;
    this._pubKeyCache = null;
  }

  _randomChallenge() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  _url(fnName) {
    if (this.functionUrls?.[fnName]) return this.functionUrls[fnName];
    if (this.baseUrl) return `${this.baseUrl}/kunji${fnName.charAt(0).toUpperCase()}${fnName.slice(1)}`;
    throw new Error('KunjiAuth: provide either functionsBaseUrl or functionUrls');
  }

  async _call(fnName, data) {
    const resp = await fetch(this._url(fnName), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data }),
    });
    const json = await resp.json();
    if (json.error) throw new Error(json.error.message || fnName + ' failed');
    return json.result ?? json;
  }

  /**
   * Creates a new auth session.
   * Returns { sessionId, expiresAt, challenge, qrData }
   * where qrData is the JSON string to encode as a QR image.
   */
  async createSession(challenge = null) {
    const ch = challenge || this._randomChallenge();
    const { sessionId, expiresAt } = await this._call('createSession', {
      ownerUid: this.ownerUid,
      registeredAppId: this.registeredAppId,
      challenge: ch,
    });

    const qrData = JSON.stringify({
      kunjiAuth: 'v1',
      sessionId,
      registeredAppId: this.registeredAppId,
      challenge: ch,
      expiresAt,
    });

    return { sessionId, expiresAt, challenge: ch, qrData };
  }

  /**
   * Polls for session approval every intervalMs milliseconds.
   * @param {string} sessionId
   * @param {{ onApproved, onDenied, onExpired, intervalMs }} callbacks
   */
  pollSession(sessionId, { onApproved, onDenied, onExpired, intervalMs = 2000 } = {}) {
    this.stopPolling();
    this._pollTimer = setInterval(async () => {
      try {
        const result = await this._call('pollSession', { sessionId });
        if (result.status === 'approved') {
          this.stopPolling();
          onApproved?.({ signedToken: result.signedToken, signedPayload: result.signedPayload });
        } else if (result.status === 'denied') {
          this.stopPolling();
          onDenied?.();
        } else if (result.status === 'expired') {
          this.stopPolling();
          onExpired?.();
        }
      } catch {
        // Network errors are transient — keep polling
      }
    }, intervalMs);
  }

  stopPolling() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
  }

  /**
   * Fetches and caches the Ed25519 public key for this registered app.
   */
  async getPublicKey() {
    if (this._pubKeyCache) return this._pubKeyCache;
    const result = await this._call('getPublicKey', {
      ownerUid: this.ownerUid,
      registeredAppId: this.registeredAppId,
    });
    this._pubKeyCache = result.publicKey;
    return this._pubKeyCache;
  }

  /**
   * Verifies a signed token against the signed payload.
   * Uses Web Crypto Ed25519 (Chrome 130+) with @noble/curves fallback if loaded globally.
   *
   * @param {string} signedToken     - Base64-encoded Ed25519 signature
   * @param {object} signedPayload   - The payload that was signed
   * @param {string} publicKeyBase64 - Base64-encoded Ed25519 public key
   * @returns {Promise<boolean>}
   */
  async verifyToken(signedToken, signedPayload, publicKeyBase64) {
    try {
      const sigBytes = this._base64ToBytes(signedToken);
      const pubKeyBytes = this._base64ToBytes(publicKeyBase64);
      const msgBytes = new TextEncoder().encode(this._canonicalJson(signedPayload));

      // @noble/curves if loaded globally
      if (typeof ed25519 !== 'undefined' && ed25519.verify) {
        return ed25519.verify(sigBytes, msgBytes, pubKeyBytes);
      }

      // Web Crypto Ed25519 (Chrome 130+)
      const key = await crypto.subtle.importKey('raw', pubKeyBytes, { name: 'Ed25519' }, false, ['verify']);
      return crypto.subtle.verify('Ed25519', key, sigBytes, msgBytes);
    } catch {
      return false;
    }
  }

  _canonicalJson(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return JSON.stringify(obj);
    const sorted = {};
    Object.keys(obj).sort().forEach(k => { sorted[k] = obj[k]; });
    return JSON.stringify(sorted);
  }

  _base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
}

// UMD — works as ES module, CommonJS, or plain <script> tag
if (typeof module !== 'undefined' && module.exports) {
  module.exports = KunjiAuth;
} else if (typeof window !== 'undefined') {
  window.KunjiAuth = KunjiAuth;
}
