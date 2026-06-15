import { describe, it, expect } from 'vitest';
// The real issuer derives `age_over_N` booleans from the vendor-verified integer age (never a DOB).
// Guard the threshold boundaries — an off-by-one here would let a minor present age_over_18, or block an adult.
import { ageClaimsFromAge } from '../issuer-functions/issuer.js';

describe('issuer ageClaimsFromAge — boolean thresholds from a verified age', () => {
  it('12 → all false', () => {
    expect(ageClaimsFromAge(12)).toEqual({
      age_over_13: false,
      age_over_16: false,
      age_over_18: false,
      age_over_21: false,
    });
  });
  it('17 → over_13/16 true, over_18/21 false', () => {
    expect(ageClaimsFromAge(17)).toEqual({
      age_over_13: true,
      age_over_16: true,
      age_over_18: false,
      age_over_21: false,
    });
  });
  it('18 (boundary) → over_18 true, over_21 false', () => {
    expect(ageClaimsFromAge(18)).toMatchObject({ age_over_16: true, age_over_18: true, age_over_21: false });
  });
  it('21 → all true', () => {
    expect(ageClaimsFromAge(21)).toEqual({
      age_over_13: true,
      age_over_16: true,
      age_over_18: true,
      age_over_21: true,
    });
  });
});
