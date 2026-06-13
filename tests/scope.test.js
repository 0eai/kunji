import { describe, it, expect } from 'vitest';
import {
  scopeId,
  normalizeScopeItem,
  isValidScopeItem,
  isValidScopeList,
  scopeSatisfies,
} from '../src/lib/capability.js';

describe('scope grammar', () => {
  it('scopeId reads a string or an object item', () => {
    expect(scopeId('login')).toBe('login');
    expect(scopeId({ id: 'payments:charge', max: '50USD' })).toBe('payments:charge');
  });

  it('normalizeScopeItem yields { id, ...constraints }', () => {
    expect(normalizeScopeItem('read:orders')).toEqual({ id: 'read:orders' });
    expect(normalizeScopeItem({ id: 'payments:charge', max: '50USD' })).toEqual({
      id: 'payments:charge',
      max: '50USD',
    });
  });

  it('accepts reserved-bare, verb:resource, URL, vc:, and object forms', () => {
    for (const s of [
      'login',
      'profile',
      'offline_access',
      'read:orders',
      'vc:age_over_18',
      'https://app.example/scopes/orders.read',
      { id: 'payments:charge', max: '50USD' },
    ]) {
      expect(isValidScopeItem(s)).toBe(true);
    }
  });

  it('rejects bare custom words, empty, over-long, and non-items', () => {
    expect(isValidScopeItem('admin')).toBe(false); // bare custom must be namespaced (contain ':')
    expect(isValidScopeItem({ id: 'admin' })).toBe(false);
    expect(isValidScopeItem('')).toBe(false);
    expect(isValidScopeItem('a:' + 'x'.repeat(64))).toBe(false); // > 64 chars
    expect(isValidScopeItem(['read:x'])).toBe(false); // array, not an item
    expect(isValidScopeItem(null)).toBe(false);
    expect(isValidScopeItem(123)).toBe(false);
  });

  it('isValidScopeList enforces a non-empty array of ≤16 items', () => {
    expect(isValidScopeList(['login'])).toBe(true);
    expect(isValidScopeList(['login', { id: 'read:orders' }])).toBe(true);
    expect(isValidScopeList([])).toBe(false);
    expect(isValidScopeList('login')).toBe(false);
    expect(isValidScopeList(Array.from({ length: 17 }, (_, i) => `read:r${i}`))).toBe(false);
    expect(isValidScopeList(['login', 'admin'])).toBe(false); // one bad item fails the list
  });
});

describe('scopeSatisfies', () => {
  it('login is always implied by a valid assertion', () => {
    expect(scopeSatisfies([], ['login'])).toBe(true);
    expect(scopeSatisfies(['read:orders'], ['login'])).toBe(true);
  });

  it('matches an exact id', () => {
    expect(scopeSatisfies(['read:orders'], ['read:orders'])).toBe(true);
    expect(scopeSatisfies(['read:orders'], ['read:invoices'])).toBe(false);
  });

  it('a verb:* wildcard covers verb:anything (but never a bare *)', () => {
    expect(scopeSatisfies(['read:*'], ['read:orders'])).toBe(true);
    expect(scopeSatisfies(['read:*'], ['read:orders', 'read:invoices'])).toBe(true);
    expect(scopeSatisfies(['read:*'], ['write:orders'])).toBe(false);
    expect(scopeSatisfies(['read:*'], ['read:'])).toBe(false); // needs content after "verb:"
  });

  it('enforces constraint ceilings (max) with matching currency', () => {
    const granted = [{ id: 'payments:charge', max: '50USD' }];
    expect(scopeSatisfies(granted, [{ id: 'payments:charge', max: '30USD' }])).toBe(true);
    expect(scopeSatisfies(granted, [{ id: 'payments:charge', max: '80USD' }])).toBe(false);
    expect(scopeSatisfies(granted, [{ id: 'payments:charge', max: '30EUR' }])).toBe(false); // ccy mismatch
    expect(scopeSatisfies(granted, [{ id: 'payments:charge' }])).toBe(true); // asking for no ceiling
  });

  it('a granted item unbounded on a dimension covers any required value there', () => {
    expect(
      scopeSatisfies([{ id: 'payments:charge' }], [{ id: 'payments:charge', max: '999USD' }]),
    ).toBe(true);
  });

  it('non-max constraints match exactly', () => {
    const g = [{ id: 'read:orders', resource: 'acct_1' }];
    expect(scopeSatisfies(g, [{ id: 'read:orders', resource: 'acct_1' }])).toBe(true);
    expect(scopeSatisfies(g, [{ id: 'read:orders', resource: 'acct_2' }])).toBe(false);
  });

  it('a required scope absent from granted is not satisfied', () => {
    expect(scopeSatisfies(['read:orders'], ['read:orders', 'write:orders'])).toBe(false);
    expect(scopeSatisfies('nope', ['read:orders'])).toBe(false); // granted must be an array
  });
});
