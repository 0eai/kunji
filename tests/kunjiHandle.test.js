import { describe, it, expect } from 'vitest';
import {
  deriveName,
  deriveAvatarSvg,
  deriveAvatarDataUri,
  deriveHandle,
} from '../src/lib/kunjiHandle.js';
import { ADJECTIVES, NOUNS } from '../src/lib/kunjiHandle.wordlists.js';

// Two arbitrary but fixed 64-hex subs (shape of SHA-256 hex).
const SUB_A = 'a'.repeat(64);
const SUB_B = '0123456789abcdef'.repeat(4);
const SUB_C = 'f0e1d2c3b4a5968778695a4b3c2d1e0fa1b2c3d4e5f60718293a4b5c6d7e8f90';

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

  it('reads as "Adjective Noun NN" drawn from the wordlists', () => {
    const name = deriveName(SUB_B);
    const [adj, noun, num] = name.split(' ');
    expect(ADJECTIVES.map((w) => w.toLowerCase())).toContain(adj.toLowerCase());
    expect(NOUNS.map((w) => w.toLowerCase())).toContain(noun.toLowerCase());
    expect(Number(num)).toBeGreaterThanOrEqual(0);
    expect(Number(num)).toBeLessThan(100);
  });
});

describe('deriveAvatarSvg', () => {
  it('is deterministic and a well-formed, self-contained SVG', () => {
    const svg = deriveAvatarSvg(SUB_B);
    expect(svg).toBe(deriveAvatarSvg(SUB_B));
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg.endsWith('</svg>')).toBe(true);
    expect(svg).toContain('viewBox="0 0 100 100"');
    // No external references or script context.
    expect(svg).not.toMatch(/<script|href=|xlink/i);
  });

  it('is left-right mirrored about the center column', () => {
    const svg = deriveAvatarSvg(SUB_C);
    // Body cells only (skip the leading background rect, which has no x=).
    const cells = [...svg.matchAll(/<rect x="(\d+)" y="(\d+)"/g)].map((m) => ({
      x: +m[1],
      y: +m[2],
    }));
    expect(cells.length).toBeGreaterThan(0);
    const key = (c) => `${c.x},${c.y}`;
    const present = new Set(cells.map(key));
    // Mirror of x about the grid is (84 - x) for SIZE=100, CELL=16, PAD=10.
    for (const c of cells) expect(present.has(`${84 - c.x},${c.y}`)).toBe(true);
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
