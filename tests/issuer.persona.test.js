import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
// The Persona webhook signature check is the issuer's trust root: a forged "verified" event would mint a
// false age credential. Guard it (raw-body HMAC, timing-safe) + the event normalization. Network-free.
import { makeIdv } from '../issuer-functions/idv/persona.js';

const SECRET = 'whsec_test_secret';
const sign = (body) => {
  const t = '1700000000';
  const v1 = createHmac('sha256', SECRET).update(`${t}.${body}`).digest('hex');
  return `t=${t},v1=${v1}`;
};
const evt = (name, refId, inqId, status = 'approved') =>
  JSON.stringify({ data: { attributes: { name, payload: { data: { id: inqId, attributes: { 'reference-id': refId, status } } } } } });

describe('persona adapter — webhook signature + normalization (the critical control)', () => {
  const idv = makeIdv({ webhookSecret: SECRET });

  it('valid signature → ok + normalized { verified, sid, vendorSessionId }', () => {
    const body = evt('inquiry.approved', 'sid_abc', 'inq_123');
    expect(idv.parseWebhook({ rawBody: body, headers: { 'persona-signature': sign(body) } })).toEqual({
      ok: true,
      status: 'verified',
      sid: 'sid_abc',
      vendorSessionId: 'inq_123',
    });
  });

  it('tampered body (signature over the original) → ok:false', () => {
    const original = evt('inquiry.approved', 'sid_abc', 'inq_123');
    const sig = sign(original);
    const tampered = evt('inquiry.approved', 'sid_EVIL', 'inq_123');
    expect(idv.parseWebhook({ rawBody: tampered, headers: { 'persona-signature': sig } }).ok).toBe(false);
  });

  it('absent / malformed signature → ok:false', () => {
    expect(idv.parseWebhook({ rawBody: '{}', headers: {} }).ok).toBe(false);
    expect(idv.parseWebhook({ rawBody: '{}', headers: { 'persona-signature': 't=1,v1=zz' } }).ok).toBe(false);
  });

  it('event name → status mapping (approved/completed → verified; declined/failed/expired → failed; other → ignore)', () => {
    for (const n of ['inquiry.approved', 'inquiry.completed']) {
      const body = evt(n, 's', 'i');
      expect(idv.parseWebhook({ rawBody: body, headers: { 'persona-signature': sign(body) } }).status).toBe('verified');
    }
    for (const n of ['inquiry.declined', 'inquiry.failed', 'inquiry.expired']) {
      const body = evt(n, 's', 'i');
      expect(idv.parseWebhook({ rawBody: body, headers: { 'persona-signature': sign(body) } }).status).toBe('failed');
    }
    const created = evt('inquiry.created', 's', 'i');
    expect(idv.parseWebhook({ rawBody: created, headers: { 'persona-signature': sign(created) } }).status).toBe('ignore');
  });
});
