import { useState, useEffect, useCallback } from 'react';
import { fetchOpsMetrics } from '../api.js';
import { SectionLabel, Badge, SkeletonRows, EmptyState } from '../ui.jsx';
import { fmtNum, fmtMs, fmtPct } from '../lib.js';

// Per-function call counts / error rate / avg latency from Cloud Monitoring (read-only project metrics).
export default function Metrics() {
  const [data, setData] = useState(null);
  const [window, setWindow] = useState('24h');
  const [err, setErr] = useState('');

  const load = useCallback(async (w) => {
    setData(null);
    try {
      setData(await fetchOpsMetrics(w));
      setErr('');
    } catch (e) {
      setErr(e.message);
    }
  }, []);
  useEffect(() => {
    load(window);
  }, [load, window]);

  return (
    <section>
      <div className="flex items-center justify-between gap-3 mb-3">
        <SectionLabel count={data?.functions?.length}>Function calls</SectionLabel>
        <div className="flex gap-1 p-1 rounded-full border border-line">
          {['24h', '7d'].map((w) => (
            <button
              key={w}
              onClick={() => setWindow(w)}
              className={`px-3 py-1 rounded-full text-[12px] font-medium transition-colors ${window === w ? 'bg-accent-soft text-accent' : 'text-muted hover:text-ink'}`}
            >
              {w}
            </button>
          ))}
        </div>
      </div>

      {err ? (
        <p className="text-[13px] text-danger">{err}</p>
      ) : !data ? (
        <SkeletonRows rows={6} />
      ) : data.error === 'metrics_unavailable' || data.functions.length === 0 ? (
        <EmptyState title="No metrics available.">
          Cloud Monitoring returned nothing for this window. If this persists, confirm the functions&rsquo;
          service account has the <span className="font-mono">monitoring.viewer</span> role (see the ops runbook).
        </EmptyState>
      ) : (
        <div className="border-t border-line divide-y divide-line">
          <div className="flex items-center gap-3 py-2 text-[11px] uppercase tracking-[0.12em] text-faint">
            <span className="flex-1">Function</span>
            <span className="w-20 text-right">Calls</span>
            <span className="w-20 text-right">Errors</span>
            <span className="w-20 text-right">Avg</span>
          </div>
          {data.functions.map((f) => (
            <div key={f.fn} className="flex items-center gap-3 py-3">
              <span className="flex-1 min-w-0 text-sm font-mono text-ink truncate">{f.fn}</span>
              <span className="w-20 text-right text-sm tabular">{fmtNum(f.count)}</span>
              <span className="w-20 text-right text-sm tabular">
                <Badge tone={f.errRate > 0.05 ? 'danger' : f.errRate > 0 ? 'warning' : 'muted'}>{fmtPct(f.errRate)}</Badge>
              </span>
              <span className="w-20 text-right text-sm tabular text-muted">{fmtMs(f.avgMs)}</span>
            </div>
          ))}
        </div>
      )}
      <p className="text-[12px] text-muted mt-4">Live from Cloud Monitoring · all functions in the project.</p>
    </section>
  );
}
