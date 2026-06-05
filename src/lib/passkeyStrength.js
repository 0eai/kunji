// Shared passkey policy — the minimum length + a heuristic strength meter, used by the
// vault-creation lock screen AND the "change passkey" flow so both enforce one policy.
// The real brute-force defense is the Argon2id KDF cost; this is a UX guardrail that
// nudges users away from trivially weak passkeys.
export const MIN_PASSKEY_LENGTH = 10;

export const getStrength = (passkey) => {
  if (!passkey || passkey.length === 0) return { label: '', color: '', width: '0%' };
  let score = 0;
  if (passkey.length >= 8) score++;
  if (passkey.length >= 12) score++;
  if (passkey.length >= 16) score++;
  if (/[A-Z]/.test(passkey) && /[a-z]/.test(passkey)) score++;
  if (/[0-9]/.test(passkey)) score++;
  if (/[^A-Za-z0-9]/.test(passkey)) score++;
  if (score <= 2) return { label: 'Weak', color: 'bg-danger', width: '25%' };
  if (score <= 3) return { label: 'Fair', color: 'bg-accent-fill', width: '50%' };
  if (score <= 4) return { label: 'Strong', color: 'bg-accent', width: '75%' };
  return { label: 'Very strong', color: 'bg-success', width: '100%' };
};
