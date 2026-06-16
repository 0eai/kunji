// Opt-in Web Push (push-relay.md Transport ②, wallet side). On the user's explicit opt-in, subscribe to
// Web Push and register a per-app push channel so a channel-less requester (a headless agent / an app
// with no UI to the user) can later ping the wallet for a step-up. The channel is addressed by an opaque,
// per-audience `channelId` (master-key-derived → kunji can't correlate it) and authorizes exactly one
// poster key (`postKeyJwk` = the requester's Ed25519 pubkey, holder-of-key). Registration is a SIGNED
// write through the `pushChannelRegister` function (master-key-derived vault-write key, TOFU-bound per
// channelId — S22), so a leaked channelId alone can't overwrite/delete it; `pushDispatch` reads it.
import { deriveChannelId, deriveVaultWriteKeyPair, exportEd25519PublicKey, signWithEd25519 } from '../lib/crypto';
import { base64ToBuffer } from '../lib/crypto/helpers';
import { okpJwk } from '../lib/capability';

const VAPID_PUBLIC_KEY = import.meta.env.VITE_VAPID_PUBLIC_KEY || '';
const PUSH_REGISTER_URL = import.meta.env.VITE_PUSH_REGISTER_URL || '/push/register';

// True only where Web Push can actually work (SW + PushManager + Notification).
export const pushSupported = () =>
  typeof navigator !== 'undefined' &&
  'serviceWorker' in navigator &&
  typeof window !== 'undefined' &&
  'PushManager' in window &&
  'Notification' in window &&
  !!VAPID_PUBLIC_KEY;

// VAPID public key (base64url) → the Uint8Array `applicationServerKey` pushManager.subscribe wants.
const vapidKeyBytes = (b64url) => {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(base64ToBuffer(b64));
};

// Signed write to the push-channel registration function (mirrors credentialVaultWrite): the wallet signs
// {channelId, op, publicKey, timestamp, …} with its vault-write key; the function verifies + TOFU-binds it.
const pushChannelWrite = async (cryptoKey, channelId, op, extra) => {
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const payload = { channelId, op, publicKey: exportEd25519PublicKey(publicKey), timestamp: Date.now(), ...extra };
  const signedToken = signWithEd25519(payload, secretKey);
  const resp = await fetch(PUSH_REGISTER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, signedToken }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('push_register_failed:' + (e.error || resp.status));
  }
};

/**
 * Enable push for `audience` and register the channel authorizing `requesterPubB64` (the agent's Ed25519
 * pubkey) to post. Prompts the OS notification permission. Returns `{ channelId }` (give it to the
 * requester so it can address the channel; it's not a secret to that authorized agent).
 */
export const enablePushForAudience = async (cryptoKey, audience, requesterPubB64) => {
  if (!pushSupported()) throw new Error("This device can't receive push notifications.");
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') throw new Error('Notifications were not allowed.');
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: vapidKeyBytes(VAPID_PUBLIC_KEY),
  });
  const channelId = await deriveChannelId(cryptoKey, audience);
  const postKeyJwk = okpJwk(new Uint8Array(base64ToBuffer(requesterPubB64)));
  // pushSub = { endpoint, keys:{p256dh,auth} } — web-push E2E-encrypts the payload to it. expiresAt/ttl
  // are set server-side by the function. The signed payload binds the subscription + poster key.
  await pushChannelWrite(cryptoKey, channelId, 'set', { postKeyJwk, pushSub: sub.toJSON() });
  return { channelId };
};

/** Revoke push for `audience` — a signed delete so the channel can no longer be pinged. */
export const revokePushForAudience = async (cryptoKey, audience) => {
  const channelId = await deriveChannelId(cryptoKey, audience);
  await pushChannelWrite(cryptoKey, channelId, 'delete', {});
};

// Global "let agents notify me" master switch. Per-DEVICE (localStorage), since the underlying Web Push
// subscription is per-device anyway — and a single shared channel can't exist (each channel binds one
// authorized poster key). It gates the per-agent channels: off = kill-switch (the UI revokes all enabled
// channels) and blocks enabling. Default ON, so existing per-agent notifications keep working.
const AGENT_NOTIFY_KEY = 'kunji.agentNotify';
export const agentNotifyAllowed = () => {
  try {
    return localStorage.getItem(AGENT_NOTIFY_KEY) !== 'off';
  } catch {
    return true;
  }
};
export const setAgentNotifyAllowed = (on) => {
  try {
    localStorage.setItem(AGENT_NOTIFY_KEY, on ? 'on' : 'off');
  } catch {
    /* private mode / storage blocked — preference just won't persist */
  }
};
