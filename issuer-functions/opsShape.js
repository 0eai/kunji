// Operator-observability shaping (pure, no Firebase / no Monitoring client) — turns raw Cloud Monitoring
// time series, opsDaily snapshots, and per-collection counts into the small JSON the admin console renders.
// Kept pure so the parsing is unit-tested without a live project.

// ── Function metrics (from Cloud Monitoring `execution_count` + `execution_times`) ──────────────────────

// 2nd-gen functions report under different resource labels depending on the metric/exporter; read the
// function name defensively from whichever label is present.
const fnName = (ts) =>
  ts?.resource?.labels?.function_name ||
  ts?.resource?.labels?.service_name ||
  ts?.metric?.labels?.function_name ||
  'unknown';

const sumPoints = (ts) =>
  (ts?.points || []).reduce((n, p) => n + Number(p?.value?.int64Value ?? p?.value?.doubleValue ?? 0), 0);

/**
 * Shape per-function metrics for a window.
 * @param execCountSeries time series of `function/execution_count` grouped by (function_name, status).
 * @param execTimeSeries  time series of `function/execution_times` (a DISTRIBUTION) per function.
 * @returns [{ fn, count, errors, errRate, avgMs }] sorted by count desc.
 */
export const shapeMetrics = (execCountSeries = [], execTimeSeries = []) => {
  const byFn = new Map();
  const row = (fn) => {
    if (!byFn.has(fn)) byFn.set(fn, { fn, count: 0, errors: 0, _latMs: 0, _latN: 0 });
    return byFn.get(fn);
  };
  for (const ts of execCountSeries) {
    const r = row(fnName(ts));
    const n = sumPoints(ts);
    r.count += n;
    // The `status` label is "ok" on success; anything else (error/timeout/…) counts as an error.
    if ((ts?.metric?.labels?.status || 'ok') !== 'ok') r.errors += n;
  }
  for (const ts of execTimeSeries) {
    const r = row(fnName(ts));
    for (const p of ts?.points || []) {
      const d = p?.value?.distributionValue;
      if (d && typeof d.mean === 'number' && Number(d.count) > 0) {
        r._latMs += d.mean * Number(d.count);
        r._latN += Number(d.count);
      }
    }
  }
  return [...byFn.values()]
    .map((r) => ({
      fn: r.fn,
      count: r.count,
      errors: r.errors,
      errRate: r.count ? +(r.errors / r.count).toFixed(4) : 0,
      avgMs: r._latN ? Math.round(r._latMs / r._latN) : null,
    }))
    .sort((a, b) => b.count - a.count);
};

// ── Daily trends (from opsDaily/{YYYY-MM-DD}) ───────────────────────────────────────────────────────────

const TREND_SERIES = ['vaults', 'verifiedUsers', 'issuerLogins', 'issued', 'anonAccounts'];

/** Shape opsDaily docs into { dates:[…], series:{ vaults:[…], … } }, oldest→newest, with the requested
 *  series only. Each doc id is the YYYY-MM-DD date. */
export const shapeTrends = (docs = []) => {
  const sorted = [...docs].sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const dates = sorted.map((d) => d.id);
  const series = {};
  for (const k of TREND_SERIES) series[k] = sorted.map((d) => Number(d[k] ?? 0));
  return { dates, series };
};

// ── Data health (per-collection counts + lifecycle metadata) ────────────────────────────────────────────

// What each operator-visible collection IS and how it's cleaned. `kind` drives the UI grouping; `ttl` is the
// human label of its Firestore TTL policy (null = no policy); `swept` = covered by the scheduled sweep/purge;
// `permanent` = an intentional record the sweep NEVER touches.
export const COLLECTION_INFO = {
  agentSessions: { kind: 'relay', ttl: '~5m', swept: true },
  agentRequests: { kind: 'relay', ttl: '~3m', swept: true },
  credentialSessions: { kind: 'relay', ttl: '~15m', swept: true },
  linkSessions: { kind: 'relay', ttl: '~5m', swept: true },
  pushChannels: { kind: 'relay', ttl: '~30d', swept: true },
  issuerOffers: { kind: 'relay', ttl: '~5m', swept: true },
  issuerTokens: { kind: 'relay', ttl: '~5m', swept: true },
  issuerLoginSessions: { kind: 'relay', ttl: '~5m', swept: true },
  issuerSessions: { kind: 'relay', ttl: '~30d', swept: true },
  verificationSessions: { kind: 'relay', ttl: '~24h', swept: true },
  rateLimits: { kind: 'ratelimit', ttl: null, swept: true },
  issuerRateLimits: { kind: 'ratelimit', ttl: null, swept: true },
  revocations: { kind: 'revocation', ttl: null, swept: true, note: 'pruned only past the 30-day cap-expiry floor' },
  issuerCredentials: { kind: 'ledger', ttl: null, swept: false, permanent: true },
  issuerNullifiers: { kind: 'permanent', ttl: null, swept: false, permanent: true, note: 'Sybil floor — never deleted' },
  issuerVerified: { kind: 'permanent', ttl: null, swept: false, permanent: true },
  vaults: { kind: 'vault', ttl: null, swept: false, permanent: true },
  opsDaily: { kind: 'ops', ttl: '~400d', swept: false },
};

const DAY = 24 * 60 * 60 * 1000;
// A swept collection is "stale" (needs attention) if its oldest doc is far older than it should ever be —
// a sign the TTL policy isn't deployed and/or the sweep isn't running. Relay/session ≈ minutes-to-30-days,
// so 35d is generously past every relay TTL; rate buckets should be seconds, so >1d is clearly stale.
const STALE_THRESHOLD_MS = { relay: 35 * DAY, ratelimit: 1 * DAY, revocation: 60 * DAY };

/** Enrich raw per-collection rows ({collection,count,oldestMs}) with lifecycle metadata + a needsAttention
 *  flag for swept collections whose oldest doc is implausibly old. */
export const shapeDataHealth = (rows = [], now = Date.now()) =>
  rows.map((r) => {
    const info = COLLECTION_INFO[r.collection] || { kind: 'other', ttl: null, swept: false };
    const oldestAgeMs = r.oldestMs != null ? Math.max(0, now - r.oldestMs) : null;
    const threshold = STALE_THRESHOLD_MS[info.kind];
    const needsAttention = !!(info.swept && threshold && oldestAgeMs != null && oldestAgeMs > threshold);
    return {
      collection: r.collection,
      count: r.count ?? 0,
      kind: info.kind,
      ttl: info.ttl,
      swept: !!info.swept,
      permanent: !!info.permanent,
      note: info.note || null,
      oldestAgeMs,
      needsAttention,
    };
  });
