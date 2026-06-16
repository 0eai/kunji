// Liveness anti-fraud (issuer). A type with `requiresLiveness` makes the user perform a RANDOM gesture
// sequence on camera; the server stores the sequence on the session and shows it to the operator beside the
// recorded video — a pre-recorded / downloaded clip won't match a fresh random challenge. The video is a
// transient biometric artifact: reviewed, then DELETED (S33) — NEVER issued; the credential stays coarse.
// Pure helpers (no Firestore/Storage): the sequence generator + the upload validator.
import { randomInt } from 'node:crypto';

// The gesture vocabulary (id → operator/user-facing label). Keep ids stable.
export const LIVENESS_GESTURES = [
  { id: 'left', label: 'Turn your head left' },
  { id: 'right', label: 'Turn your head right' },
  { id: 'up', label: 'Look up' },
  { id: 'blink', label: 'Blink slowly, twice' },
  { id: 'nod', label: 'Nod your head' },
];
const BY_ID = new Map(LIVENESS_GESTURES.map((g) => [g.id, g]));

// A random, NON-repeating sequence of `n` gestures (default 3), as `{ id, label }` — returned to the
// frontend (to prompt) and stored on the session (so the operator can confirm the same sequence). Uses
// crypto RNG.
export const randomGestureSequence = (n = 3) => {
  const pool = LIVENESS_GESTURES.map((g) => g.id);
  const out = [];
  for (let i = 0; i < n && pool.length; i++) out.push(pool.splice(randomInt(pool.length), 1)[0]);
  return out.map((id) => ({ id, label: BY_ID.get(id).label }));
};

export const LIVENESS_MAX_BYTES = 25 * 1024 * 1024; // ~25 MB — a short, low-res webm clip
const LIVENESS_MIMES = new Set(['video/webm', 'video/mp4']);
// Validate the captured liveness clip (a video, unlike the ID image's image-only validateUpload).
export const validateLivenessUpload = ({ contentType, bytes }) =>
  LIVENESS_MIMES.has(String(contentType)) && Number(bytes) > 0 && Number(bytes) <= LIVENESS_MAX_BYTES;
