import { describe, it, expect } from 'vitest';
import {
  deriveName,
  deriveAvatarSvg,
  deriveAvatarDataUri,
  deriveHandle,
} from '../src/lib/kunjiHandle.js';
import { ADJECTIVES, NAMES } from '../src/lib/kunjiHandle.wordlists.js';

// Two arbitrary but fixed 64-hex subs (shape of SHA-256 hex).
const SUB_A = 'a'.repeat(64);
const SUB_B = '0123456789abcdef'.repeat(4);
const SUB_C = 'f0e1d2c3b4a5968778695a4b3c2d1e0fa1b2c3d4e5f60718293a4b5c6d7e8f90';

const lower = (arr) => arr.map((w) => w.toLowerCase());

describe('deriveName', () => {
  it('is deterministic for the same sub', () => {
    expect(deriveName(SUB_B)).toBe(deriveName(SUB_B));
  });

  it('differs across subs', () => {
    expect(deriveName(SUB_A)).not.toBe(deriveName(SUB_C));
  });

  it('is case-insensitive in the sub', () => {
    expect(deriveName(SUB_C)).toBe(deriveName(SUB_C.toUpperCase()));
  });

  it('reads as "Adjective Surname" drawn from the wordlists', () => {
    const name = deriveName(SUB_B);
    // surnames may contain a space (e.g. "Dela Cruz"), so split off the adjective only.
    const [adj, ...rest] = name.split(' ');
    const surname = rest.join(' ');
    expect(lower(ADJECTIVES)).toContain(adj.toLowerCase());
    expect(lower(NAMES)).toContain(surname.toLowerCase());
  });
});

describe('deriveAvatarSvg', () => {
  it('is deterministic and a well-formed, self-contained SVG', () => {
    const svg = deriveAvatarSvg(SUB_B);
    expect(svg).toBe(deriveAvatarSvg(SUB_B));
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg.endsWith('</svg>')).toBe(true);
    expect(svg).toContain('viewBox="0 0 96 96"');
    // No external references or script context.
    expect(svg).not.toMatch(/<script|href=|xlink/i);
  });

  it('renders the key sigil (seal disc + embossed key shaft)', () => {
    const svg = deriveAvatarSvg(SUB_C);
    // the wax-seal disc (r=46) and at least the key shaft rect are always present.
    expect(svg).toContain('<circle cx="48" cy="48" r="46"');
    expect(svg).toContain('<rect');
  });

  it('differs across subs', () => {
    expect(deriveAvatarSvg(SUB_A)).not.toBe(deriveAvatarSvg(SUB_C));
  });
});

describe('deriveAvatarDataUri', () => {
  it('is an <img>-ready svg data URI', () => {
    expect(deriveAvatarDataUri(SUB_B)).toMatch(/^data:image\/svg\+xml,/);
  });
});

describe('deriveHandle', () => {
  it('bundles name + avatar consistently with the individual derivers', () => {
    const h = deriveHandle(SUB_C);
    expect(h.name).toBe(deriveName(SUB_C));
    expect(h.avatarSvg).toBe(deriveAvatarSvg(SUB_C));
    expect(h.avatarDataUri).toBe(deriveAvatarDataUri(SUB_C));
  });
});
