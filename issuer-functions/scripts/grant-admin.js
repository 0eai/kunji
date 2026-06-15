// One-time: grant the issuer-admin custom claim to a user by email. The gate for admin.kunji.cc is
// `admin:true`, NOT mere sign-in (this project also mints anonymous wallet tokens).
//
//   cd issuer-functions && GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json \
//     node scripts/grant-admin.js you@example.com
//
// The user must sign in to admin.kunji.cc once first (so the account exists), then sign out + in again
// AFTER running this so the refreshed ID token carries the claim. Pass `--revoke` to remove it.
import { initializeApp, applicationDefault } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const email = process.argv[2];
const revoke = process.argv.includes('--revoke');
if (!email) {
  console.error('usage: node scripts/grant-admin.js <email> [--revoke]');
  process.exit(1);
}

initializeApp({ credential: applicationDefault() });
const auth = getAuth();
const user = await auth.getUserByEmail(email);
await auth.setCustomUserClaims(user.uid, { ...(user.customClaims || {}), admin: revoke ? undefined : true });
console.log(`${revoke ? 'revoked' : 'granted'} admin for ${email} (${user.uid}). They must re-sign-in to refresh the token.`);
