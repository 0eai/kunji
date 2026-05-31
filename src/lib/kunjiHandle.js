/**
 * kunji default identity — deterministic, anonymous, RP-renderable.
 *
 * Given the per-app `sub` (= hex(SHA-256(publicKeyBase64)), which the relying party
 * already receives), this derives a friendly display NAME and a kunji-themed
 * IDENTICON. Both are:
 *   • deterministic  — same `sub` ⇒ same name + avatar, every time (stable UX);
 *   • per-app distinct — different `sub` ⇒ different identity (apps can't correlate);
 *   • zero-knowledge  — pure function of a value the RP already has, so no PII, no
 *     assertion change, no kunji infrastructure, no tracking.
 *
 * It is the Layer-1 DEFAULT. If the user opts to share a custom profile (Layer 2),
 * the RP prefers the signed `claims` over this. This module is pure, dependency-free,
 * and framework-agnostic so the wallet, the rp.js widget, and any third-party RP can
 * all produce byte-identical output (the algorithm is specified in
 * docs/discoverable-login.md). Do not add imports beyond the wordlists.
 */
import { ADJECTIVES, NOUNS } from './kunjiHandle.wordlists.js';

// On-brand foreground palette for the identicon (warm/earthy, paper-friendly).
const PALETTE = [
  '#b45309', // amber-700
  '#a16207', // yellow-700
  '#15803d', // green-700
  '#0f766e', // teal-700
  '#1d4ed8', // blue-700
  '#6d28d9', // violet-700
  '#be123c', // rose-700
  '#9a3412', // orange-800
];
const PAPER = '#faf9f6';

// Parse a slice of the hex `sub` as an unsigned integer. Slices stay ≤ 8 hex chars
// (32 bits) so the result is always a safe integer.
const hexInt = (sub, start, len) => parseInt(sub.slice(start, start + len), 16) || 0;

const normalizeSub = (sub) => String(sub || '').toLowerCase();

/**
 * Deterministic display name, e.g. "Wandering Fox 42".
 * adjective ← sub[0:8], noun ← sub[8:16], 2-digit discriminator ← sub[16:20]
 * (the number cuts within-app collisions; `sub` remains the real account key).
 */
export const deriveName = (sub) => {
  const s = normalizeSub(sub);
  const adj = ADJECTIVES[hexInt(s, 0, 8) % ADJECTIVES.length];
  const noun = NOUNS[hexInt(s, 8, 8) % NOUNS.length];
  const num = hexInt(s, 16, 4) % 100;
  const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);
  return `${cap(adj)} ${cap(noun)} ${num}`;
};

/**
 * Deterministic identicon as an SVG string. A 5×5 left-right-mirrored grid (so it
 * reads as a face/symbol) in one palette color on warm paper, keyed off `sub`.
 * Grid cells ← sub[24:39], color ← sub[40:42]. Self-contained (no external refs),
 * safe to inline or use as an <img> data-URI.
 */
export const deriveAvatarSvg = (sub) => {
  const s = normalizeSub(sub);
  const fg = PALETTE[hexInt(s, 40, 2) % PALETTE.length];
  const CELL = 16;
  const PAD = 10;
  const SIZE = CELL * 5 + PAD * 2; // 100

  const rects = [];
  // Decide the left 3 columns (0,1,2); mirror 1→3, 0→4. 15 cells ← 15 hex digits.
  for (let col = 0; col <= 2; col++) {
    for (let row = 0; row < 5; row++) {
      const on = parseInt(s[24 + col * 5 + row] || '0', 16) >= 8;
      if (!on) continue;
      const cols = col === 2 ? [2] : [col, 4 - col];
      for (const c of cols) {
        const x = PAD + c * CELL;
        const y = PAD + row * CELL;
        rects.push(`<rect x="${x}" y="${y}" width="${CELL}" height="${CELL}" rx="2"/>`);
      }
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${SIZE} ${SIZE}" width="${SIZE}" height="${SIZE}" role="img">` +
    `<rect width="${SIZE}" height="${SIZE}" rx="20" fill="${PAPER}"/>` +
    `<g fill="${fg}">${rects.join('')}</g>` +
    `</svg>`
  );
};

/** The identicon as an <img>-ready data URI (URL-encoded SVG; no script context). */
export const deriveAvatarDataUri = (sub) =>
  'data:image/svg+xml,' + encodeURIComponent(deriveAvatarSvg(sub));

/** Convenience: the full default identity for a `sub`. */
export const deriveHandle = (sub) => ({
  name: deriveName(sub),
  avatarSvg: deriveAvatarSvg(sub),
  avatarDataUri: deriveAvatarDataUri(sub),
});
