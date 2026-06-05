/**
 * kunji default identity — deterministic, anonymous, RP-renderable.
 *
 * Given the per-app `sub` (= hex(SHA-256(publicKeyBase64)), which the relying party
 * already receives), this derives a friendly display NAME ("Adjective Surname") and a
 * kunji **key-sigil** avatar — an amber wax-seal disc with an embossed key whose bow,
 * motif, shaft and bit-teeth are all derived from `sub`, so the key shape *is* the
 * identity. Both are:
 *   • deterministic  — same `sub` ⇒ same name + sigil, every time (stable UX);
 *   • per-app distinct — different `sub` ⇒ different identity (apps can't correlate);
 *   • zero-knowledge  — pure function of a value the RP already has, so no PII, no
 *     assertion change, no kunji infrastructure, no tracking.
 * The sigil doubles as a visual key-fingerprint (eyeball a swapped identity, the way
 * Signal shows a safety number).
 *
 * It is the Layer-1 DEFAULT. If the user opts to share a custom profile (Layer 2),
 * the RP prefers the signed `claims` over this. This module is pure, dependency-free,
 * and framework-agnostic so the wallet, the rp.js widget, and any third-party RP can
 * all produce byte-identical output (the algorithm is specified in
 * docs/discoverable-login.md §8.1). Do not add imports beyond the wordlists.
 */
import { ADJECTIVES, NAMES } from './kunjiHandle.wordlists.js';

const INK = '#1a1a18';
const PAPER = '#faf9f6';
const MOTIFS = ['none', 'dot', 'diamond', 'cross', 'ring'];

const normalizeSub = (sub) =>
  String(sub || '')
    .trim()
    .replace(/^0x/i, '')
    .toLowerCase();

// Parse `sub` into 32 bytes. Lenient & total (never throws): a short/invalid `sub`
// zero-pads, so callers always get a deterministic result.
const bytesFromSub = (sub) => {
  const hex = normalizeSub(sub);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    out[i] = Number.isNaN(byte) ? 0 : byte;
  }
  return out;
};

// Deterministic cursor over the identity bytes. `start` lets the name read from a
// disjoint slice (offset 16) so it varies independently of the sigil (which reads
// from the front). Never consumes randomness.
const reader = (bytes, start = 0) => {
  let i = start;
  const b = () => bytes[i++ % bytes.length];
  return {
    b,
    int: (lo, hi) => lo + Math.round((b() / 255) * (hi - lo)), // inclusive int
    flt: (lo, hi) => lo + (b() / 256) * (hi - lo), // float in [lo, hi)
    pick: (arr) => arr[b() % arr.length],
    idx: (len) => ((b() << 8) | b()) % len, // 2-byte index into a list
  };
};

const f = (n) => Number(n.toFixed(2)); // trim SVG coordinate noise

/**
 * Deterministic display name, e.g. "Amber Marlowe".
 * Read from the second half of the digest (offset 16): adjective ← bytes[16:18],
 * surname ← bytes[18:20]. `sub` remains the real account key — names may collide.
 */
export const deriveName = (sub) => {
  const r = reader(bytesFromSub(sub), 16);
  const adj = ADJECTIVES[r.idx(ADJECTIVES.length)];
  const name = NAMES[r.idx(NAMES.length)];
  return `${adj} ${name}`;
};

/**
 * Deterministic key-sigil avatar as an SVG string: an amber wax-seal disc (gradient +
 * rim) with an embossed ink key. The key geometry — bow radius/hole, inner motif,
 * shaft width, and bit-teeth — is keyed off `sub`; the amber hue/sat/lightness drift a
 * little within the brand family. Self-contained (no external refs/script), 96×96
 * viewBox, safe to inline or use as an <img> data-URI. The amber treatment is fixed so
 * every RP renders the same sigil (the cross-RP rendering contract).
 */
export const deriveAvatarSvg = (sub) => {
  const bytes = bytesFromSub(sub);
  const r = reader(bytes);

  // amber family (kunji brand: Amber #f59e0b · Ink #1a1a18 · Paper #faf9f6)
  const hJ = r.int(0, 9);
  const sJ = r.int(0, 12);
  const lJ = r.int(0, 10);
  const h = 33 + hJ;
  const s = 82 + sJ;
  const l = 47 + lJ;
  const discHi = `hsl(${h} ${s}% ${Math.min(l + 8, 62)}%)`;
  const discLo = `hsl(${Math.max(h - 5, 28)} ${s}% ${Math.max(l - 9, 38)}%)`;
  const rim = `hsl(${Math.max(h - 7, 26)} ${Math.min(s + 4, 96)}% ${Math.max(l - 20, 30)}%)`;
  const inner = PAPER; // paper highlight ring
  const emboss = INK; // the dark key
  const shadow = `hsl(${Math.max(h - 6, 26)} ${s}% ${Math.max(l - 28, 22)}%)`;

  // unique id suffix so many sigils can share one DOM without colliding
  const uid = Array.from(bytes.slice(0, 4), (x) => x.toString(16).padStart(2, '0')).join('');

  // --- key geometry (96-unit canvas) ---
  const cx = 48;
  const bowCy = 33;
  const R = r.flt(11, 15);
  const rr = R * r.flt(0.42, 0.6);
  const ringW = R - rr;
  const ringR = (R + rr) / 2;
  const sw = r.flt(5.5, 8);
  const shaftTop = bowCy + R * 0.45;
  const shaftBot = 78;
  const right = cx + sw / 2;
  const motif = r.pick(MOTIFS);

  const nTeeth = r.int(4, 6);
  const span = r.flt(14, 20);
  const depth = r.flt(3, 5.2);
  const seg = span / nTeeth;

  const parts = [];
  parts.push(
    `<circle cx="${cx}" cy="${bowCy}" r="${f(ringR)}" fill="none" stroke="${emboss}" stroke-width="${f(ringW)}"/>`,
  );

  const m = rr * 0.52;
  if (motif === 'dot') {
    parts.push(`<circle cx="${cx}" cy="${bowCy}" r="${f(m * 0.55)}" fill="${emboss}"/>`);
  } else if (motif === 'diamond') {
    parts.push(
      `<path d="M${cx} ${f(bowCy - m)}L${f(cx + m)} ${bowCy}L${cx} ${f(bowCy + m)}L${f(cx - m)} ${bowCy}Z" fill="${emboss}"/>`,
    );
  } else if (motif === 'cross') {
    const t = m * 0.4;
    parts.push(
      `<rect x="${f(cx - t)}" y="${f(bowCy - m)}" width="${f(t * 2)}" height="${f(m * 2)}" rx="${f(t * 0.4)}" fill="${emboss}"/>`,
    );
    parts.push(
      `<rect x="${f(cx - m)}" y="${f(bowCy - t)}" width="${f(m * 2)}" height="${f(t * 2)}" rx="${f(t * 0.4)}" fill="${emboss}"/>`,
    );
  } else if (motif === 'ring') {
    parts.push(
      `<circle cx="${cx}" cy="${bowCy}" r="${f(m * 0.85)}" fill="none" stroke="${emboss}" stroke-width="${f(m * 0.5)}"/>`,
    );
  }

  // collar + shaft
  parts.push(
    `<rect x="${f(cx - sw)}" y="${f(shaftTop - 1.6)}" width="${f(sw * 2)}" height="3.2" rx="1.2" fill="${emboss}"/>`,
  );
  parts.push(
    `<rect x="${f(cx - sw / 2)}" y="${f(shaftTop)}" width="${f(sw)}" height="${f(shaftBot - shaftTop)}" rx="${f(sw * 0.28)}" fill="${emboss}"/>`,
  );

  // bit: teeth from a deterministic pattern; the tip tooth is always present
  for (let i = 0; i < nTeeth; i++) {
    const present = i === 0 || r.b() & 1;
    if (!present) continue;
    const y1 = shaftBot - i * seg;
    const y0 = y1 - seg + 0.6;
    parts.push(
      `<rect x="${f(right)}" y="${f(y0)}" width="${f(depth)}" height="${f(y1 - y0)}" rx="0.8" fill="${emboss}"/>`,
    );
  }

  const label = `kunji identity ${uid}`;

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="96" height="96" role="img" aria-label="${label}">`,
    `<title>${label}</title>`,
    `<defs>`,
    `<linearGradient id="kg-${uid}" x1="0" y1="0" x2="0" y2="1">`,
    `<stop offset="0" stop-color="${discHi}"/>`,
    `<stop offset="1" stop-color="${discLo}"/>`,
    `</linearGradient>`,
    `<filter id="kf-${uid}" x="-20%" y="-20%" width="140%" height="140%">`,
    `<feDropShadow dx="0.5" dy="0.85" stdDeviation="0.5" flood-color="${shadow}" flood-opacity="0.55"/>`,
    `</filter>`,
    `</defs>`,
    `<circle cx="48" cy="48" r="46" fill="url(#kg-${uid})"/>`,
    `<circle cx="48" cy="48" r="46" fill="none" stroke="${rim}" stroke-width="3"/>`,
    `<circle cx="48" cy="48" r="40" fill="none" stroke="${inner}" stroke-opacity="0.35" stroke-width="1.1"/>`,
    `<g filter="url(#kf-${uid})">${parts.join('')}</g>`,
    `</svg>`,
  ].join('');
};

/** The sigil as an <img>-ready data URI (URL-encoded SVG; no script context). */
export const deriveAvatarDataUri = (sub) =>
  'data:image/svg+xml,' + encodeURIComponent(deriveAvatarSvg(sub));

/** Convenience: the full default identity for a `sub`. */
export const deriveHandle = (sub) => ({
  name: deriveName(sub),
  avatarSvg: deriveAvatarSvg(sub),
  avatarDataUri: deriveAvatarDataUri(sub),
});
