/**
 * The on-prem worker — this is your "local server with a dynamic IP".
 *
 * It runs on your own box (home/office), behind NAT, and connects to Firebase
 * OUTBOUND ONLY (a Firestore listener + Admin writes). Nothing ever dials in, so your
 * IP can change freely — no DDNS, no port-forward, no tunnel. It reacts to logins
 * (verified at the edge by kunjiCallback) and runs whatever private logic you keep
 * off the cloud — touch hardware, process private data, call internal services, etc.
 *
 * Run:
 *   GOOGLE_APPLICATION_CREDENTIALS=./serviceAccount.json npm run worker
 *
 * Robustness: the listener's initial snapshot replays ALL users, so on restart it
 * catches up on anything it missed while down; a per-user `workerSeenAt` makes the
 * reaction idempotent (act only when lastLoginAt is newer than what we've processed).
 */
import { initializeApp, applicationDefault } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

initializeApp({ credential: applicationDefault() });
const db = getFirestore();

// —— your private, on-prem business logic ——
// Idempotent: gets called once per *new* login (not on every unrelated doc change).
async function onLogin(user) {
  const who = user.lastClaims?.name ? ` (${user.lastClaims.name})` : '';
  console.log(`✔ login: sub=${user.sub}${who} @ ${new Date(user.lastLoginAt).toISOString()}`);
  // e.g. provision a workspace, kick a job, flip a relay, sync to an internal DB…
}

console.log('worker online — listening to users/ (outbound only). Ctrl-C to stop.');

db.collection('users').onSnapshot(
  (snap) => {
    snap.docChanges().forEach(async (chg) => {
      if (chg.type === 'removed') return;
      const user = chg.doc.data();
      const seen = user.workerSeenAt || 0;
      // Only react to a fresh login we haven't processed (covers restart catch-up).
      if (!user.lastLoginAt || user.lastLoginAt <= seen) return;
      try {
        await onLogin(user);
        await chg.doc.ref.set({ workerSeenAt: user.lastLoginAt }, { merge: true });
      } catch (e) {
        console.error(`reaction failed for ${user.sub}:`, e.message); // will retry next change
      }
    });
  },
  (err) => {
    console.error('listener error (will not auto-resubscribe):', err.message);
    process.exit(1); // let your process manager (systemd/pm2) restart → catch-up on boot
  },
);
