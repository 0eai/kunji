import { initializeApp } from 'firebase/app';
import {
  getAuth,
  signInAnonymously,
  setPersistence,
  browserLocalPersistence,
  onAuthStateChanged,
  signOut,
  GoogleAuthProvider,
  signInWithPopup,
  linkWithPopup,
  EmailAuthProvider,
  sendSignInLinkToEmail,
  isSignInWithEmailLink,
  signInWithEmailLink,
  linkWithCredential,
  unlink,
} from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
  databaseURL: import.meta.env.VITE_FIREBASE_DATABASE_URL,
};

if (!firebaseConfig.apiKey) {
  console.error(
    'Firebase config missing. Copy .env.example to .env and fill in your Firebase project values.',
  );
}

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

/**
 * Sign in anonymously with local persistence.
 * Returns the Firebase User. Safe to call multiple times — reuses existing session.
 */
export async function ensureAnonymousAuth() {
  await setPersistence(auth, browserLocalPersistence);
  if (auth.currentUser) return auth.currentUser;
  const { user } = await signInAnonymously(auth);
  return user;
}

export const signOutDevice = () => signOut(auth);

export { onAuthStateChanged };

/* ── Optional account-backed recovery ─────────────────────────────────────────
 * kunji is anonymous by default (one anonymous uid per device). A user may OPT IN
 * to linking a federated provider (Google or email-link) to their account. Linking
 * UPGRADES the anonymous account to permanent while PRESERVING the uid, so signing
 * in with that provider on a fresh device resolves to the SAME uid → the existing
 * `users/{uid}` vault doc is reachable and the user's normal passkey decrypts it.
 * No recovery passphrase, no separate doc, no new crypto — the uid is not a crypto
 * input (see docs/discoverable-login.md + src/services/vault.js). Trade-off: kunji's
 * AUTH layer can now associate an email/Google identity with the (still ciphertext-
 * only) vault; per-app `sub`s are unchanged, so anonymity TO APPS is unaffected. */

export const googleProvider = new GoogleAuthProvider();

const EMAIL_LINK_PENDING = 'kunji_emaillink_pending';

// The federated providers currently linked to this account (empty for a pure
// anonymous user). Drives the Security "Account recovery" status — no Firestore field.
export const linkedProviders = () =>
  (auth.currentUser?.providerData || [])
    .filter((p) => p.providerId !== 'firebase')
    .map((p) => ({ providerId: p.providerId, email: p.email || null }));

export const hasAccountRecovery = () => linkedProviders().length > 0;

// True when the current URL is a Firebase email-sign-in link (handled at boot in App.jsx).
export const isEmailSignInLink = (href = window.location.href) =>
  isSignInWithEmailLink(auth, href);

// Link Google to the current (anonymous → permanent) account, preserving the uid.
// MUST be called from a user-gesture handler (popup blockers). Returns the user.
export async function linkGoogle() {
  const { user } = await linkWithPopup(auth.currentUser, googleProvider);
  return user;
}

// Recover on a fresh device: Google sign-in resolves to the linked uid, replacing the
// throwaway anonymous session. MUST be called from a user-gesture handler.
export async function recoverWithGoogle() {
  const { user } = await signInWithPopup(auth, googleProvider);
  return user;
}

// Send a passwordless email sign-in link. `intent` is 'link' (setup: link to the
// existing account, preserving uid) or 'recover' (fresh device: sign in as the linked
// uid). The email + intent are stashed so the inbound link can be completed at boot.
export async function startEmailLink(email, intent) {
  const url = `${window.location.origin}/finishSignIn`;
  await sendSignInLinkToEmail(auth, email, { url, handleCodeInApp: true });
  localStorage.setItem(EMAIL_LINK_PENDING, JSON.stringify({ email, intent }));
}

// Complete an inbound email-sign-in link at boot. For intent 'link' (with a current
// user) it links the credential (uid preserved); otherwise it signs in. Throws
// 'EMAIL_REQUIRED' when the email can't be determined (cross-device open) so the
// caller can prompt. Idempotent re-clicks (already linked / expired code) are swallowed.
export async function completeEmailLink(href, currentUser, emailFromPrompt) {
  const pendingRaw = localStorage.getItem(EMAIL_LINK_PENDING);
  const pending = pendingRaw ? JSON.parse(pendingRaw) : null;
  const email = emailFromPrompt || pending?.email;
  if (!email) throw new Error('EMAIL_REQUIRED');
  const intent = pending?.intent || 'recover';
  try {
    if (intent === 'link' && currentUser) {
      try {
        await linkWithCredential(currentUser, EmailAuthProvider.credentialWithLink(email, href));
      } catch (e) {
        // A re-clicked / expired link is a no-op (already linked, or code consumed).
        if (e.code !== 'auth/provider-already-linked' && e.code !== 'auth/invalid-action-code') {
          throw e;
        }
      }
    } else {
      await signInWithEmailLink(auth, email, href);
    }
  } finally {
    localStorage.removeItem(EMAIL_LINK_PENDING);
  }
}

// Disable account recovery by unlinking a provider (the account stays permanent).
export const unlinkProvider = (providerId) => unlink(auth.currentUser, providerId);
