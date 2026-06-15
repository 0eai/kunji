// IDV vendor adapter — Persona (withpersona.com). Document + selfie/liveness via Persona's hosted flow.
// Vendor-neutral interface (createSession / parseWebhook / verifiedAgeFor) so index.js never sees Persona
// specifics and the provider stays swappable. The issuer receives only a verified INTEGER age; the DOB is
// computed in memory and never returned to Firestore. Persona holds the document + the legal liability.
//
// Webhook signature (docs.withpersona.com/webhooks-best-practices): header `Persona-Signature: t=<unix>,v1=<hex>`,
// where hex = HMAC-SHA256(secret, `${t}.${rawBody}`), timing-safe compared. No SDK needed.
import { createHmac, timingSafeEqual } from 'node:crypto';

const API = 'https://api.withpersona.com/api/v1';

// Integer age from a "YYYY-MM-DD" birthdate (UTC), same convention as issuer.js. null if malformed.
const ageFromDob = (s) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(s || ''));
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const now = new Date();
  let age = now.getUTCFullYear() - y;
  const diff = now.getUTCMonth() + 1 - mo; // getUTCMonth() is 0-11
  if (diff < 0 || (diff === 0 && now.getUTCDate() < d)) age--;
  return age;
};

const headers = (apiKey, version) => ({
  Authorization: `Bearer ${apiKey}`,
  'Content-Type': 'application/json',
  Accept: 'application/json',
  ...(version ? { 'Persona-Version': version } : {}),
});

export const makeIdv = ({ apiKey, webhookSecret, templateId, version }) => ({
  // Create a hosted inquiry; return our handle (the inquiry id) + the one-time link to redirect the user to.
  // `reference-id` carries OUR opaque sid, echoed back on the webhook so we resolve it without a query.
  createSession: async ({ returnUrl, sid }) => {
    if (!templateId) throw new Error('persona_template_missing');
    const r = await fetch(`${API}/inquiries`, {
      method: 'POST',
      headers: headers(apiKey, version),
      body: JSON.stringify({
        data: { attributes: { 'inquiry-template-id': templateId, 'reference-id': sid, 'redirect-uri': returnUrl } },
        meta: { 'auto-create-one-time-link': true },
      }),
    });
    if (!r.ok) throw new Error('persona_create_failed');
    const j = await r.json();
    const url = j?.meta?.['one-time-link'];
    const vendorSessionId = j?.data?.id;
    if (!url || !vendorSessionId) throw new Error('persona_link_missing');
    return { vendorSessionId, url };
  },

  // Verify the webhook signature over the RAW body, then normalize to { ok, status, sid, vendorSessionId }.
  // ok:false ⇒ bad/absent signature (reject). status: 'verified' | 'failed' | 'ignore'.
  parseWebhook: ({ rawBody, headers: h }) => {
    try {
      const sig = String(h?.['persona-signature'] || '');
      const t = /t=([^,]+)/.exec(sig)?.[1];
      const v1 = /v1=([0-9a-f]+)/.exec(sig)?.[1];
      if (!t || !v1) return { ok: false };
      const body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody ?? '');
      const expected = createHmac('sha256', String(webhookSecret)).update(`${t}.${body}`).digest('hex');
      const a = Buffer.from(expected);
      const b = Buffer.from(v1);
      if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false };
      const evt = JSON.parse(body);
      const name = evt?.data?.attributes?.name || '';
      const inq = evt?.data?.attributes?.payload?.data || {};
      // `approved` fires when a decision/workflow auto-approves; `completed` when verifications pass with no
      // decision step. Treat both as a success trigger — verifiedAgeFor then re-checks status + birthdate.
      const status =
        ['inquiry.approved', 'inquiry.completed'].includes(name)
          ? 'verified'
          : ['inquiry.declined', 'inquiry.failed', 'inquiry.expired'].includes(name)
            ? 'failed'
            : 'ignore';
      return { ok: true, status, sid: inq?.attributes?.['reference-id'] || null, vendorSessionId: inq?.id || null };
    } catch {
      return { ok: false };
    }
  },

  // Retrieve the inquiry fresh and return the integer age (authoritative — don't trust the event payload).
  verifiedAgeFor: async (vendorSessionId) => {
    const r = await fetch(`${API}/inquiries/${encodeURIComponent(vendorSessionId)}`, { headers: headers(apiKey, version) });
    if (!r.ok) return { ok: false };
    const a = (await r.json())?.data?.attributes || {};
    if (!['approved', 'completed'].includes(a.status)) return { ok: false };
    const age = ageFromDob(a?.fields?.birthdate?.value);
    return age == null ? { ok: false } : { ok: true, age };
  },
});
