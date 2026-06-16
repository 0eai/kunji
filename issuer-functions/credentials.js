// Credential TYPE registry — the issuer's extensibility seam. Add a credential type = ONE entry here (its
// vct + claim builder + allowed verification methods); the endpoints, the offer gate, and minting are all
// type-driven. The age logic lives here: `buildClaims` turns a verified DOB into boolean thresholds — the
// DOB itself is never persisted or put in the credential. See ../docs/issuer.md.
const DAY = 24 * 3600;

// The issuer's brand — published in the trust anchor + metadata so a relying party can recognize WHO issued
// a credential and HOW it was verified. kunji's trust model: known issuer + known verification method +
// brand mark (not a certification scheme — yet).
export const ISSUER_BRAND = { name: 'kunji', logo: 'https://kunji.cc/icon.svg', homepage: 'https://kunji.cc' };

const AGE_THRESHOLDS = [13, 16, 18, 21];
// Whole-years age from a 'YYYY-MM-DD' DOB (UTC). null if unparseable.
const ageFromDob = (dob) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(dob || ''));
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const now = new Date();
  let age = now.getUTCFullYear() - y;
  const diff = now.getUTCMonth() + 1 - mo; // getUTCMonth() is 0-11
  if (diff < 0 || (diff === 0 && now.getUTCDate() < d)) age--;
  return age;
};

export const CREDENTIAL_TYPES = {
  age: {
    vct: 'age',
    label: 'Age',
    description: 'Prove you are over an age threshold (over 18, …) — boolean only, never your date of birth.',
    ttlSeconds: 365 * DAY,
    methods: ['document-review'], // AVAILABLE (registered in verify/); validated by /verify/start
    // Display-only roadmap (never startable until they ship as real verify/ modules) — drives the chooser.
    comingSoon: [
      { id: 'pass', label: 'PASS (Korea)', description: 'Korean mobile-carrier identity verification.', region: 'KR' },
      { id: 'aadhaar', label: 'Aadhaar (India)', description: 'Indian eID (Aadhaar) verification.', region: 'IN' },
    ],
    // What the operator confirms from the ID (drives the admin review panel; sent back as `verifiedData`).
    reviewFields: [{ key: 'dob', label: 'Date of birth (from ID)', type: 'date', required: true }],
    // Disclosable claims from the verified data a method produced. For age: the reviewer-confirmed DOB (or a
    // provider-verified integer age) → boolean thresholds. The DOB is NEVER stored or returned. null = invalid.
    buildClaims: ({ dob, age } = {}) => {
      const a = age != null ? Number(age) : ageFromDob(dob);
      if (a == null || Number.isNaN(a)) return null;
      return Object.fromEntries(AGE_THRESHOLDS.map((n) => [`age_over_${n}`, a >= n]));
    },
  },

  // Residency — a COARSE attribute (country, optional region) read off the ID. No uniqueness/nullifier; the
  // raw document is never stored — only the country/region claim the user chooses to disclose.
  residency: {
    vct: 'residency',
    label: 'Residency',
    description: 'Prove the country (and optionally region) your government ID is from — coarse, not your address.',
    ttlSeconds: 365 * DAY,
    methods: ['document-review'],
    reviewFields: [
      { key: 'country', label: 'Country (ISO code, from ID)', type: 'text', required: true },
      { key: 'region', label: 'Region / state (optional)', type: 'text', required: false },
    ],
    buildClaims: ({ country, region } = {}) => {
      const c = String(country || '').trim().toUpperCase();
      if (!/^[A-Z]{2}$/.test(c)) return null; // ISO-3166 alpha-2
      const r = String(region || '').trim();
      return { country: c, ...(r ? { region: r } : {}) };
    },
  },

  // Gender — a single COARSE attribute (the ID's sex/gender marker). Sensitive, so it is opt-in, disclosed
  // only when the user chooses, and stored only as this one claim (never the raw ID). No uniqueness.
  gender: {
    vct: 'gender',
    label: 'Gender',
    description: 'Prove the gender marker on your government ID. Optional, and shared only when an app asks.',
    ttlSeconds: 365 * DAY,
    methods: ['document-review'],
    reviewFields: [
      {
        key: 'gender',
        label: 'Gender marker (from ID)',
        type: 'select',
        required: true,
        options: [
          { value: 'female', label: 'Female (F)' },
          { value: 'male', label: 'Male (M)' },
          { value: 'x', label: 'X / other / unspecified' },
        ],
      },
    ],
    buildClaims: ({ gender } = {}) => {
      const g = String(gender || '').trim().toLowerCase();
      return ['female', 'male', 'x'].includes(g) ? { gender: g } : null;
    },
  },
};

export const getType = (id) => CREDENTIAL_TYPES[id] || null;

// Per-type OpenID4VCI config + the verification methods a relying party can see (for the trust decision).
export const credentialConfigs = () =>
  Object.fromEntries(
    Object.entries(CREDENTIAL_TYPES).map(([id, t]) => [
      id,
      {
        format: 'vc+sd-jwt',
        vct: t.vct,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['EdDSA'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA'] } },
        verification_methods: t.methods,
      },
    ]),
  );
