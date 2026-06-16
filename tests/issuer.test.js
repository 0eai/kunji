import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// The issuer's pluggable framework: a credential TYPE registry (credentials.js) × a verification METHOD
// registry (verify/). Guard the age claim boundaries (an off-by-one would let a minor present age_over_18 or
// block an adult), the registry lookups, and the document-upload validation. All pure (no Firestore/Storage).
import { getType, CREDENTIAL_TYPES, credentialConfigs, ISSUER_BRAND } from '../issuer-functions/credentials.js';
import { getMethod, VERIFICATION_METHODS } from '../issuer-functions/verify/index.js';
import { documentReview, MAX_DOC_BYTES } from '../issuer-functions/verify/documentReview.js';
import { nullifierDigest } from '../issuer-functions/nullifier.js';

describe('issuer credential-type registry — age buildClaims', () => {
  const age = getType('age');
  const yearsAgo = (n) => {
    const d = new Date();
    return `${d.getUTCFullYear() - n}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
  };

  it('from an integer age — boundaries 12/17/18/21', () => {
    expect(age.buildClaims({ age: 12 })).toEqual({ age_over_13: false, age_over_16: false, age_over_18: false, age_over_21: false });
    expect(age.buildClaims({ age: 17 })).toEqual({ age_over_13: true, age_over_16: true, age_over_18: false, age_over_21: false });
    expect(age.buildClaims({ age: 18 })).toMatchObject({ age_over_16: true, age_over_18: true, age_over_21: false });
    expect(age.buildClaims({ age: 21 })).toEqual({ age_over_13: true, age_over_16: true, age_over_18: true, age_over_21: true });
  });

  it('from a DOB string (reviewer-confirmed)', () => {
    expect(age.buildClaims({ dob: yearsAgo(30) })).toMatchObject({ age_over_18: true, age_over_21: true });
    expect(age.buildClaims({ dob: yearsAgo(15) })).toMatchObject({ age_over_13: true, age_over_18: false });
  });

  it('rejects an unparseable / missing DOB → null (no credential)', () => {
    expect(age.buildClaims({ dob: 'nope' })).toBeNull();
    expect(age.buildClaims({})).toBeNull();
  });

  it('exposes brand + lists age with its verification methods', () => {
    expect(ISSUER_BRAND.name).toBe('kunji');
    expect(CREDENTIAL_TYPES.age.methods).toContain('document-review');
    expect(credentialConfigs().age).toMatchObject({ vct: 'age', format: 'vc+sd-jwt', verification_methods: ['document-review'] });
    expect(getType('nope')).toBeNull();
  });
});

describe('issuer credential-type registry — residency + gender (coarse attributes)', () => {
  it('residency: coarse country (+ optional region) from a valid ISO code', () => {
    const r = getType('residency');
    expect(r.buildClaims({ country: 'us' })).toEqual({ country: 'US' }); // normalized uppercase
    expect(r.buildClaims({ country: 'GB', region: 'Scotland' })).toEqual({ country: 'GB', region: 'Scotland' });
    expect(r.buildClaims({ country: 'USA' })).toBeNull(); // not alpha-2
    expect(r.buildClaims({})).toBeNull();
    expect(credentialConfigs().residency).toMatchObject({ vct: 'residency', format: 'vc+sd-jwt' });
  });

  it('gender: one coarse marker, only the allowed values', () => {
    const g = getType('gender');
    expect(g.buildClaims({ gender: 'Female' })).toEqual({ gender: 'female' }); // normalized lowercase
    expect(g.buildClaims({ gender: 'x' })).toEqual({ gender: 'x' });
    expect(g.buildClaims({ gender: 'other' })).toBeNull();
    expect(g.buildClaims({})).toBeNull();
  });

  it('every type declares reviewFields with required keys (drives the dynamic admin panel)', () => {
    for (const [id, t] of Object.entries(CREDENTIAL_TYPES)) {
      expect(Array.isArray(t.reviewFields), id).toBe(true);
      expect(t.reviewFields.length, id).toBeGreaterThan(0);
      for (const f of t.reviewFields) {
        expect(typeof f.key, id).toBe('string');
        expect(['text', 'date', 'select']).toContain(f.type);
        if (f.type === 'select') expect(Array.isArray(f.options), id).toBe(true);
      }
    }
    // gender proves the SELECT renderer the personhood type will also need.
    expect(getType('gender').reviewFields[0].type).toBe('select');
  });
});

describe('issuer credential-type registry — verified_human (uniqueness)', () => {
  const vh = getType('verified_human');
  const full = { idType: 'passport', country: 'US', idNumber: 'X1234567' };

  it('mints ONLY the coarse is_human predicate (no ID data leaks into claims)', () => {
    expect(vh.buildClaims(full)).toEqual({ is_human: true });
    // The claim object must carry nothing ID-derived — the nullifier/idNumber must never appear.
    const claims = vh.buildClaims(full);
    expect(Object.keys(claims)).toEqual(['is_human']);
    expect(JSON.stringify(claims)).not.toContain('1234567');
  });

  it('rejects incomplete / invalid ID fields → null (no credential)', () => {
    expect(vh.buildClaims({ idType: 'passport', country: 'US' })).toBeNull(); // no number
    expect(vh.buildClaims({ idType: 'passport', country: 'USA', idNumber: 'X1234567' })).toBeNull(); // bad country
    expect(vh.buildClaims({ idType: 'library_card', country: 'US', idNumber: 'X1234567' })).toBeNull(); // bad type
    expect(vh.buildClaims({ idType: 'passport', country: 'US', idNumber: 'X1' })).toBeNull(); // too short
    expect(vh.buildClaims({})).toBeNull();
  });

  it('nullifierFrom is a frozen, normalized pre-image (case/separators folded, leading zeros kept)', () => {
    const base = vh.nullifierFrom(full);
    expect(base).toBe('verified_human|US|passport|X1234567');
    // separators + case are normalized away → same human, same pre-image (idempotent dedup)
    expect(vh.nullifierFrom({ idType: 'Passport', country: 'us', idNumber: 'x1-23 45/67' })).toBe(base);
    // leading zeros are SIGNIFICANT (preserved)
    expect(vh.nullifierFrom({ idType: 'passport', country: 'US', idNumber: '00123' })).toBe('verified_human|US|passport|00123');
    // distinct id / type / country → distinct pre-image
    expect(vh.nullifierFrom({ ...full, idNumber: 'X1234568' })).not.toBe(base);
    expect(vh.nullifierFrom({ ...full, idType: 'national_id' })).not.toBe(base);
    expect(vh.nullifierFrom({ ...full, country: 'GB' })).not.toBe(base);
    expect(vh.nullifierFrom({ idType: 'passport', country: 'US' })).toBeNull();
  });
});

describe('issuer uniqueness nullifier — secret-keyed, deterministic, one-way (nullifier.js)', () => {
  const pre = 'verified_human|US|passport|X1234567';
  it('is deterministic per (pre-image, secret) and base64url-safe', () => {
    const a = nullifierDigest(pre, 'secret-A');
    expect(nullifierDigest(pre, 'secret-A')).toBe(a); // deterministic → idempotent dedup
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/); // Firestore-doc-id safe, no '/' or '+'
  });
  it('changes with the secret (key-bound) and with the pre-image', () => {
    expect(nullifierDigest(pre, 'secret-A')).not.toBe(nullifierDigest(pre, 'secret-B'));
    expect(nullifierDigest(pre, 'secret-A')).not.toBe(nullifierDigest(pre + '8', 'secret-A'));
  });
  it('refuses empty inputs', () => {
    expect(() => nullifierDigest('', 'secret')).toThrow();
    expect(() => nullifierDigest(pre, '')).toThrow();
  });
});

describe('issuer verification-method registry — document-review', () => {
  it('resolves the method + its manual kind', () => {
    expect(getMethod('document-review')).toBe(documentReview);
    expect(VERIFICATION_METHODS['document-review'].kind).toBe('manual');
    expect(getMethod('nope')).toBeNull();
  });

  it('validates uploads: allowed image mimes within the size cap', () => {
    expect(documentReview.validateUpload({ contentType: 'image/jpeg', bytes: 1000 })).toBe(true);
    expect(documentReview.validateUpload({ contentType: 'image/png', bytes: MAX_DOC_BYTES })).toBe(true);
    expect(documentReview.validateUpload({ contentType: 'application/pdf', bytes: 1000 })).toBe(false);
    expect(documentReview.validateUpload({ contentType: 'image/jpeg', bytes: MAX_DOC_BYTES + 1 })).toBe(false);
    expect(documentReview.validateUpload({ contentType: 'image/jpeg', bytes: 0 })).toBe(false);
  });
});

describe('issuer login verifier — byte-identical to the login-demo verify.js (security-critical)', () => {
  it('loginVerify.js matches the proven assertion verifier', () => {
    const read = (p) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8');
    expect(read('../issuer-functions/loginVerify.js')).toBe(read('../examples/kunji-login-demo/functions/verify.js'));
  });
});
