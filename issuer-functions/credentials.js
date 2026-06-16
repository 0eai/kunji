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

// FROZEN uniqueness pre-image for verified-human. DO NOT CHANGE — altering normalization (or the format)
// re-buckets every prior enrollee, silently breaking uniqueness for them. Returns the canonical string a
// nullifier is derived from, or null if the ID fields are incomplete/invalid. Leading zeros are PRESERVED
// (significant in many ID formats); only whitespace + separators (- / .) are stripped; NFC + case-folded.
const ID_TYPES = new Set(['passport', 'national_id', 'drivers_license']);
const personhoodPreimage = ({ idType, country, idNumber } = {}) => {
  const t = String(idType || '').trim().toLowerCase();
  const c = String(country || '').trim().toUpperCase();
  const n = String(idNumber || '').normalize('NFC').toUpperCase().replace(/[\s\-/.]/g, '');
  if (!ID_TYPES.has(t) || !/^[A-Z]{2}$/.test(c) || n.length < 4) return null;
  return `verified_human|${c}|${t}|${n}`;
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

  // Verified human — a coarse "is a real, unique person" predicate. The operator confirms a government ID;
  // the credential carries ONLY `is_human: true` (never the ID number/name). Uniqueness is enforced
  // issuer-side via `nullifierFrom` (a per-issuer one-way digest of the ID — see index.js): one human per
  // real ID document, NOT per-app dedup (that needs per-verifier pseudonyms — roadmap 4.1). The nullifier is
  // NEVER in the credential — putting it there would make a colluding-RP global identifier.
  verified_human: {
    vct: 'verified_human',
    label: 'Verified human',
    description: 'Prove you are a real, unique person — a coarse signal, never your ID number or name.',
    ttlSeconds: 180 * DAY,
    methods: ['document-review'],
    // Requires a live gesture-video (anti-spoof) in addition to the ID — the operator face-matches a live
    // human to the ID. The video is reviewed then DELETED; never issued (credential stays coarse). See liveness.js.
    requiresLiveness: true,
    reviewFields: [
      {
        key: 'idType',
        label: 'ID type',
        type: 'select',
        required: true,
        options: [
          { value: 'passport', label: 'Passport' },
          { value: 'national_id', label: 'National ID' },
          { value: 'drivers_license', label: "Driver's license" },
        ],
      },
      { key: 'country', label: 'Issuing country (ISO code)', type: 'text', required: true },
      { key: 'idNumber', label: 'Document number', type: 'text', required: true },
    ],
    // Mints only from a complete, valid ID entry; returns ONLY the coarse predicate (no ID data leaks).
    buildClaims: (data = {}) => (personhoodPreimage(data) ? { is_human: true } : null),
    // The pre-image the issuer turns into a one-way nullifier for uniqueness (raw ID never stored).
    nullifierFrom: (data = {}) => personhoodPreimage(data),
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
