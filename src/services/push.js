// Opt-in Web Push (push-relay.md Transport ②, wallet side). On the user's explicit opt-in, subscribe to
// Web Push and register a per-app push channel so a channel-less requester (a headless agent / an app
// with no UI to the user) can later ping the wallet for a step-up. The channel is addressed by an opaque,
// per-audience `channelId` (master-key-derived → kunji can't correlate it) and authorizes exactly one
// poster key (`postKeyJwk` = the requester's Ed25519 pubkey, holder-of-key). The wallet writes the channel
// doc directly (authed, gated by the unguessable channelId, like `agentSessions`); `pushDispatch` reads it.
import { doc, setDoc, deleteDoc } from 'firebase/firestore';
import { db } from '../lib/firebase';
import { deriveChannelId } from '../lib/crypto';
import { base64ToBuffer } from '../lib/crypto/helpers';
import { okpJwk } from '../lib/capability';

const VAPID_PUBLIC_KEY = import.meta.env.VITE_VAPID_PUBLIC_KEY || '';
const CHANNEL_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days; the requester re-subscribes after expiry

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
  const expiresAt = Date.now() + CHANNEL_TTL_MS;
  await setDoc(doc(db, 'pushChannels', channelId), {
    pushSub: sub.toJSON(), // { endpoint, keys:{ p256dh, auth } } — web-push E2E-encrypts the payload to it
    postKeyJwk,
    expiresAt,
    ttl: new Date(expiresAt + 5 * 60 * 1000),
  });
  return { channelId };
};

/** Revoke push for `audience` — deletes the channel so it can no longer be pinged. */
export const revokePushForAudience = async (cryptoKey, audience) => {
  const channelId = await deriveChannelId(cryptoKey, audience);
  await deleteDoc(doc(db, 'pushChannels', channelId));
};
