// Verification METHOD registry — the issuer's other extensibility seam. Add a method = ONE module + ONE
// entry. 'manual' methods (document-review) are resolved by an admin; future 'redirect'/'inline' methods
// (PASS, Aadhaar, …) add start()/callback hooks and the endpoints dispatch on `kind`. See ../../docs/issuer.md.
import { documentReview } from './documentReview.js';

export const VERIFICATION_METHODS = {
  [documentReview.id]: documentReview,
};

export const getMethod = (id) => VERIFICATION_METHODS[id] || null;
