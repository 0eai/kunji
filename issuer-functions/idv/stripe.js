// IDV vendor adapter — Stripe Identity (ID-document + liveness). ALL Stripe specifics live here so the
// vendor is swappable: the issuer only ever sees `{ status, age }`, never the document/DOB. The hosted
// (redirect) flow is used — no `js.stripe.com` on the issuer page, so its CSP stays tight.
//
// Privacy contract: `verifiedAgeFor` returns an INTEGER age (computed from the vendor-verified DOB in memory);
// the caller derives `age_over_N` booleans and stores ONLY those + the vendor session id. The DOB is never
// returned to Firestore, never logged. Stripe holds the document + the legal liability.
import Stripe from 'stripe';

// Age from a Stripe `verified_outputs.dob` ({ day, month, year }; month is 1-12). UTC, same convention as
// issuer.js `ageOf`. Returns null if the dob is incomplete.
const ageFromDob = (dob) => {
  if (!dob || !dob.year || !dob.month || !dob.day) return null;
  const now = new Date();
  let age = now.getUTCFullYear() - dob.year;
  const m = now.getUTCMonth() + 1 - dob.month; // getUTCMonth() is 0-11
  if (m < 0 || (m === 0 && now.getUTCDate() < dob.day)) age--;
  return age;
};

export const makeIdv = (secretKey) => {
  const stripe = new Stripe(String(secretKey).trim());
  return {
    // Create a hosted document-verification session. `metadata.sid` is OUR opaque session id, echoed back on
    // the webhook so we resolve it with no Firestore query. `return_url` brings the user back to the issuer.
    createSession: async ({ returnUrl, sid }) => {
      const vs = await stripe.identity.verificationSessions.create({
        type: 'document',
        metadata: { sid },
        return_url: returnUrl,
        options: { document: { require_live_capture: true } },
      });
      return { stripeSessionId: vs.id, url: vs.url };
    },
    // Verify + parse a webhook payload. MUST be the RAW body (Buffer/string) + the `stripe-signature` header;
    // throws on a bad/absent/stale signature (the critical control against a forged "verified" event).
    verifyEvent: ({ rawBody, signature, webhookSecret }) =>
      stripe.webhooks.constructEvent(rawBody, signature, webhookSecret),
    // Retrieve the verified outputs for a session id and return the integer age only. `verified_outputs` is
    // NOT in the webhook payload by default — it must be retrieved with `expand`.
    verifiedAgeFor: async (stripeSessionId) => {
      const vs = await stripe.identity.verificationSessions.retrieve(stripeSessionId, {
        expand: ['verified_outputs'],
      });
      const age = ageFromDob(vs?.verified_outputs?.dob);
      return age == null ? { ok: false } : { ok: true, age };
    },
  };
};
