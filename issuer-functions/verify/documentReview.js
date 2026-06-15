// Verification METHOD: document review (manual, human-in-the-loop). The user uploads a government ID; an
// operator reviews it in the admin console and confirms the DOB; only then does the session reach 'verified'.
// kunji stores the image transiently (deleted on the review decision) and never the DOB. See ../../docs/issuer.md.
export const MAX_DOC_BYTES = 8 * 1024 * 1024; // 8 MB cap on an uploaded ID image
const ALLOWED = new Set(['image/jpeg', 'image/png', 'image/webp']);

export const documentReview = {
  id: 'document-review',
  label: 'Government ID (manual review)',
  kind: 'manual', // resolved by an admin via the review API — no automated provider callback
  validateUpload: ({ contentType, bytes }) =>
    ALLOWED.has(String(contentType)) && Number(bytes) > 0 && Number(bytes) <= MAX_DOC_BYTES,
};
