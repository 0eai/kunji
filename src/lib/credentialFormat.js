// Shared display helpers for held verified credentials (used by CredentialsSheet / CredentialRow /
// CredentialDetailSheet). Pure + view-only; no network on render (issuer brand is captured at receipt).
import { parseSdJwt } from './vc';
import { bbsClaimNames } from './vcBbs';

// Claim names to show — SD-JWT reads the disclosures; a BBS (v3) credential carries its names.
export const claimNamesOf = (cred) => {
  if (!cred) return [];
  if (cred.format === 'bbs') return bbsClaimNames(cred.bbs);
  try {
    return parseSdJwt(cred.sdjwt).disclosures.map((d) => d.name);
  } catch {
    return [];
  }
};

export const issuerLabel = (iss) => {
  try {
    return new URL(iss).host;
  } catch {
    return iss;
  }
};

// A kunji-operated issuer → show the bundled (same-origin) kunji mark; no external logo fetch (privacy).
export const isKunjiIssuer = (iss) => {
  try {
    const h = new URL(iss).host;
    return h === 'kunji.cc' || h.endsWith('.kunji.cc') || h === 'issuer-kunji-cc.web.app';
  } catch {
    return false;
  }
};

export const methodLabel = (m) => (m ? String(m).replace(/[-_]/g, ' ') : null); // 'document-review' → 'document review'

// Issuer brand captured at receipt (record.brand), else the host. No network on view.
export const issuerName = (g) => g.brand || issuerLabel(g.iss);
