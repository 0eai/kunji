// Opt-in Web Push (push-relay.md Transport ②, wallet side). On the user's explicit opt-in, subscribe to
// Web Push and register a per-app push channel so a channel-less requester (a headless agent / an app
// with no UI to the user) can later ping the wallet for a step-up. The channel is addressed by an opaque,
// per-audience `channelId` (master-key-derived → kunji can't correlate it) and authorizes one or more
// poster keys (`postKeyJwks` = a map of requesters' Ed25519 pubkeys, holder-of-key; multi-poster, 4.3 —
// several agents at the same audience can each receive). Registration is a SIGNED
// write through the `pushChannelRegister` function (master-key-derived vault-write key, TOFU-bound per
// channelId — S22), so a leaked channelId alone can't overwrite/delete it; `pushDispatch` reads it.
import { deriveChannelId, deriveVaultWriteKeyPair, exportEd25519PublicKey, signWithEd25519 } from '../lib/crypto';
import { base64ToBuffer } from '../lib/crypto/helpers';
import { okpJwk } from '../lib/capability';
import { thisDeviceId } from './devices';

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
  // are set server-side. The channel keeps a subscription PER DEVICE (keyed by deviceId), so every device
  // the user enables receives; the signed payload binds this device's subscription + the poster key.
  await pushChannelWrite(cryptoKey, channelId, 'set', {
    deviceId: thisDeviceId(),
    postKeyJwk,
    pushSub: sub.toJSON(),
  });
  addLocalPushAudience(audience);
  return { channelId };
};

/**
 * Multi-poster (4.3): remove ONE agent's authorization to post on the audience's channel — leaving other
 * agents (and the device subscriptions) intact. `dropDeviceSub` ALSO unsubscribes THIS device for the
 * audience; pass it only when no other push-enabled agent remains at the audience (else other agents lose
 * reception here). The poster fingerprint is the agent's base64url Ed25519 pubkey = the `postKeyJwks` map key.
 */
export const disablePushForAgent = async (cryptoKey, audience, requesterPubB64, { dropDeviceSub = false } = {}) => {
  const channelId = await deriveChannelId(cryptoKey, audience);
  const postKeyFp = okpJwk(new Uint8Array(base64ToBuffer(requesterPubB64))).x;
  const extra = { postKeyFp };
  if (dropDeviceSub) extra.deviceId = thisDeviceId();
  await pushChannelWrite(cryptoKey, channelId, 'delete', extra);
  if (dropDeviceSub) removeLocalPushAudience(audience);
};

/** Stop receiving for `audience` on THIS device — a signed delete of just this device's subscription.
 *  Other linked devices that enabled it keep receiving. */
export const revokePushForAudience = async (cryptoKey, audience) => {
  const channelId = await deriveChannelId(cryptoKey, audience);
  await pushChannelWrite(cryptoKey, channelId, 'delete', { deviceId: thisDeviceId() });
  removeLocalPushAudience(audience);
};

/** Tear down the whole channel for `audience` across ALL devices (used when the agent itself is revoked). */
export const revokePushAllDevices = async (cryptoKey, audience) => {
  const channelId = await deriveChannelId(cryptoKey, audience);
  await pushChannelWrite(cryptoKey, channelId, 'delete', { all: true });
  removeLocalPushAudience(audience);
};

// ── Per-device subscription state ─────────────────────────────────────────────────────────────────
// Whether THIS device receives for an audience is per-device truth: the channel doc is unreadable to
// clients, so we remember locally which audiences this device subscribed to. (The old synced agent flag
// caused the "shows on but not allowed here" bug across linked devices.)
const LOCAL_PUSH_KEY = 'kunji.pushAudiences';
const readLocalSet = () => {
  try {
    return new Set(JSON.parse(localStorage.getItem(LOCAL_PUSH_KEY) || '[]'));
  } catch {
    return new Set();
  }
};
const writeLocalSet = (set) => {
  try {
    localStorage.setItem(LOCAL_PUSH_KEY, JSON.stringify([...set]));
  } catch {
    /* storage blocked — preference just won't persist */
  }
};
const addLocalPushAudience = (audience) => {
  const s = readLocalSet();
  s.add(audience);
  writeLocalSet(s);
};
const removeLocalPushAudience = (audience) => {
  const s = readLocalSet();
  s.delete(audience);
  writeLocalSet(s);
};
/** The opaque per-app push mailbox for `audience` (master-key-derived). Handed to an authorized agent (over
 *  the encrypted relay, or shown in the wallet) so it can address the channel; not a secret to that agent. */
export const channelIdFor = (cryptoKey, audience) => deriveChannelId(cryptoKey, audience);

/** The audiences THIS device is subscribed to receive for. */
export const localPushAudiences = () => readLocalSet();
/** Is this device actually set up to receive for `audience` — subscribed here AND OS permission granted? */
export const isPushOnHere = (audience) =>
  readLocalSet().has(audience) &&
  typeof Notification !== 'undefined' &&
  Notification.permission === 'granted';

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
