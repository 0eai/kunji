import { describe, it, expect } from 'vitest';
import {
  toMillis,
  isDeadDoc,
  sweepPlan,
  SWEEP_SPECS,
  MAX_CAP_TTL_MS,
  REVOCATION_FLOOR_MS,
  RATELIMIT_WINDOW_MS,
} from '../issuer-functions/opsClean.js';
import { shapeMetrics, shapeTrends, shapeDataHealth, COLLECTION_INFO } from '../issuer-functions/opsShape.js';

const NOW = 1_700_000_000_000;

describe('opsClean.toMillis — normalizes every stored time shape', () => {
  it('handles number, Firestore Timestamp, {_seconds}, Date, and garbage', () => {
    expect(toMillis(123)).toBe(123);
    expect(toMillis({ toMillis: () => 456 })).toBe(456);
    expect(toMillis({ _seconds: 2, _nanoseconds: 500_000_000 })).toBe(2500);
    expect(toMillis(new Date(789))).toBe(789);
    expect(toMillis(null)).toBe(null);
    expect(toMillis('nope')).toBe(null);
  });
});

describe('opsClean.isDeadDoc — only provably-dead docs, fail closed', () => {
  const spec = (collection) => SWEEP_SPECS.find((s) => s.collection === collection);

  it('a relay doc is dead once past expiresAt, alive before', () => {
    const s = spec('agentSessions');
    expect(isDeadDoc({ expiresAt: NOW - 1 }, s, NOW)).toBe(true);
    expect(isDeadDoc({ expiresAt: NOW + 60_000 }, s, NOW)).toBe(false);
  });

  it('a missing/unparseable time field is NEVER deleted (fail closed)', () => {
    const s = spec('agentSessions');
    expect(isDeadDoc({}, s, NOW)).toBe(false);
    expect(isDeadDoc({ expiresAt: 'x' }, s, NOW)).toBe(false);
  });

  it('a rate-limit bucket is dead only after its window elapsed', () => {
    const s = spec('rateLimits');
    expect(isDeadDoc({ start: NOW - RATELIMIT_WINDOW_MS - 1 }, s, NOW)).toBe(true);
    expect(isDeadDoc({ start: NOW - 1000 }, s, NOW)).toBe(false); // still within the window
  });

  it('a revocation is dead only past the 30-day cap-expiry floor, NOT within the max cap TTL', () => {
    const s = spec('revocations');
    expect(isDeadDoc({ revokedAt: NOW - REVOCATION_FLOOR_MS - 1 }, s, NOW)).toBe(true);
    // A fresh revocation (within the 7-day max cap TTL) must survive — the cap may still be live.
    expect(isDeadDoc({ revokedAt: NOW - MAX_CAP_TTL_MS }, s, NOW)).toBe(false);
    expect(REVOCATION_FLOOR_MS).toBeGreaterThan(MAX_CAP_TTL_MS);
  });

  it('handles a Firestore Timestamp ttl field (issuer relay)', () => {
    const s = spec('issuerOffers');
    expect(s.tsType).toBe('timestamp');
    expect(isDeadDoc({ ttl: { _seconds: Math.floor((NOW - 1000) / 1000) } }, s, NOW)).toBe(true);
    expect(isDeadDoc({ ttl: { _seconds: Math.floor((NOW + 60_000) / 1000) } }, s, NOW)).toBe(false);
  });
});

describe('opsClean.SWEEP_SPECS — the safety allow-list', () => {
  const swept = SWEEP_SPECS.map((s) => s.collection);

  it('NEVER includes the permanent records (ledger / nullifiers / verified / users / vaults / statuslist / opsDaily)', () => {
    for (const forbidden of [
      'issuerCredentials',
      'issuerNullifiers',
      'issuerVerified',
      'issuerUsers',
      'vaults',
      'issuerStatusList',
      'opsDaily',
    ]) {
      expect(swept).not.toContain(forbidden);
    }
  });

  it('includes the relay/session + rate-limit + revocation collections', () => {
    for (const c of ['agentSessions', 'pushChannels', 'rateLimits', 'issuerRateLimits', 'revocations', 'verificationSessions']) {
      expect(swept).toContain(c);
    }
  });

  it('sweepPlan computes cutoff = now - deadAfterMs per spec', () => {
    const plan = sweepPlan(NOW);
    const rl = plan.find((p) => p.collection === 'rateLimits');
    expect(rl.cutoffMs).toBe(NOW - RATELIMIT_WINDOW_MS);
    const rev = plan.find((p) => p.collection === 'revocations');
    expect(rev.cutoffMs).toBe(NOW - REVOCATION_FLOOR_MS);
    const relay = plan.find((p) => p.collection === 'agentSessions');
    expect(relay.cutoffMs).toBe(NOW); // deadAfterMs 0
  });
});

describe('opsShape.shapeMetrics — per-function count / errRate / avgMs', () => {
  const series = (fn, status, points) => ({
    resource: { labels: { function_name: fn } },
    metric: { labels: { status } },
    points: points.map((int64Value) => ({ value: { int64Value } })),
  });
  const dist = (fn, mean, count) => ({
    resource: { labels: { function_name: fn } },
    points: [{ value: { distributionValue: { mean, count } } }],
  });

  it('sums calls, splits errors, computes rate + weighted avg latency, sorts by count', () => {
    const counts = [series('vaultWrite', 'ok', [90, 10]), series('vaultWrite', 'error', [5]), series('pushDispatch', 'ok', [3])];
    const times = [dist('vaultWrite', 60, 100), dist('vaultWrite', 80, 5)];
    const out = shapeMetrics(counts, times);
    expect(out[0].fn).toBe('vaultWrite'); // higher count first
    expect(out[0].count).toBe(105);
    expect(out[0].errors).toBe(5);
    expect(out[0].errRate).toBeCloseTo(5 / 105, 4);
    expect(out[0].avgMs).toBe(Math.round((60 * 100 + 80 * 5) / 105));
    expect(out[1].fn).toBe('pushDispatch');
    expect(out[1].errRate).toBe(0);
    expect(out[1].avgMs).toBe(null); // no distribution series
  });

  it('reads function name from service_name fallback + handles empty', () => {
    expect(shapeMetrics([], [])).toEqual([]);
    const out = shapeMetrics([{ resource: { labels: { service_name: 'fn2' } }, points: [{ value: { int64Value: 2 } }] }], []);
    expect(out[0].fn).toBe('fn2');
  });
});

describe('opsShape.shapeTrends — oldest→newest series', () => {
  it('sorts by date id and projects each series, missing → 0', () => {
    const docs = [
      { id: '2024-01-03', vaults: 30 },
      { id: '2024-01-01', vaults: 10, issued: 5 },
      { id: '2024-01-02', vaults: 20 },
    ];
    const out = shapeTrends(docs);
    expect(out.dates).toEqual(['2024-01-01', '2024-01-02', '2024-01-03']);
    expect(out.series.vaults).toEqual([10, 20, 30]);
    expect(out.series.issued).toEqual([5, 0, 0]);
  });
});

describe('opsShape.shapeDataHealth — lifecycle flags + needsAttention', () => {
  it('flags a swept relay collection with implausibly old data, never a permanent one', () => {
    const rows = [
      { collection: 'agentSessions', count: 4, oldestMs: NOW - 40 * 24 * 60 * 60 * 1000 }, // 40d > 35d relay threshold
      { collection: 'rateLimits', count: 9, oldestMs: NOW - 2 * 24 * 60 * 60 * 1000 }, // 2d > 1d ratelimit threshold
      { collection: 'issuerCredentials', count: 1000, oldestMs: NOW - 999 * 24 * 60 * 60 * 1000 }, // permanent
      { collection: 'agentRequests', count: 1, oldestMs: NOW - 60_000 }, // fresh
    ];
    const out = shapeDataHealth(rows, NOW);
    const by = Object.fromEntries(out.map((r) => [r.collection, r]));
    expect(by.agentSessions.needsAttention).toBe(true);
    expect(by.rateLimits.needsAttention).toBe(true);
    expect(by.issuerCredentials.permanent).toBe(true);
    expect(by.issuerCredentials.needsAttention).toBe(false); // permanent → never flagged
    expect(by.agentRequests.needsAttention).toBe(false);
  });

  it('COLLECTION_INFO marks the permanent records permanent + not swept', () => {
    for (const c of ['issuerCredentials', 'issuerNullifiers', 'issuerVerified', 'vaults']) {
      expect(COLLECTION_INFO[c].permanent).toBe(true);
      expect(COLLECTION_INFO[c].swept).toBeFalsy();
    }
  });
});
