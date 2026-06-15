import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// The issuer's pluggable framework: a credential TYPE registry (credentials.js) × a verification METHOD
// registry (verify/). Guard the age claim boundaries (an off-by-one would let a minor present age_over_18 or
// block an adult), the registry lookups, and the document-upload validation. All pure (no Firestore/Storage).
import { getType, CREDENTIAL_TYPES, credentialConfigs, ISSUER_BRAND } from '../issuer-functions/credentials.js';
import { getMethod, VERIFICATION_METHODS } from '../issuer-functions/verify/index.js';
import { documentReview, MAX_DOC_BYTES } from '../issuer-functions/verify/documentReview.js';

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
