import { useState, useEffect, useCallback } from 'react';
import { fetchDataHealth, purgeExpired } from '../api.js';
import { Btn, SectionLabel, Badge, SkeletonRows, ConfirmDialog, Card } from '../ui.jsx';
import { useToast } from '../contexts/ToastContext.jsx';
import { fmtNum, fmtAge } from '../lib.js';

const KIND_LABEL = {
  relay: 'Relay / session',
  ratelimit: 'Rate limit',
  revocation: 'Revocation',
  ledger: 'Ledger',
  permanent: 'Permanent',
  vault: 'Vault',
  ops: 'Ops',
  other: 'Other',
};

// Per-collection data health: size, lifecycle (TTL / swept / permanent), oldest doc, and a confirm-gated
// "purge expired now" that runs the same provably-dead sweep as the scheduled job.
export default function DataHealth() {
  const { showToast } = useToast();
  const [rows, setRows] = useState(null);
  const [err, setErr] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await fetchDataHealth();
      setRows(r.collections || []);
      setErr('');
    } catch (e) {
      setErr(e.message);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const doPurge = async () => {
    setBusy(true);
    try {
      const { deleted } = await purgeExpired();
      const total = Object.values(deleted || {}).reduce((n, v) => n + v, 0);
      showToast(total ? `Purged ${fmtNum(total)} expired docs.` : 'Nothing to purge — all clean.');
      setConfirm(false);
      load();
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  if (err) return <p className="text-[13px] text-danger">{err}</p>;
  if (rows === null) return <SkeletonRows rows={6} />;

  const warnings = rows.filter((r) => r.needsAttention).length;

  return (
    <section>
      <div className="flex items-center justify-between gap-3 mb-3">
        <SectionLabel count={rows.length}>Collections</SectionLabel>
        <Btn variant="outline" onClick={() => setConfirm(true)}>
          Purge expired now
        </Btn>
      </div>

      {warnings > 0 && (
        <Card className="px-4 py-3 mb-4 border-accent/40 bg-accent-soft">
          <span className="text-[13px] text-ink">
            {warnings === 1 ? '1 collection has' : `${warnings} collections have`} unusually old data — the TTL
            policy may not be deployed. Run the sweep, or check the TTL runbook.
          </span>
        </Card>
      )}

      <div className="border-t border-line divide-y divide-line">
        {rows.map((r) => (
          <div key={r.collection} className="flex items-center gap-3 py-3">
            <div className="flex-1 min-w-0">
              <div className="text-sm font-mono text-ink truncate">{r.collection}</div>
              <div className="text-[12px] text-faint">
                {KIND_LABEL[r.kind] || r.kind}
                {r.ttl ? ` · TTL ${r.ttl}` : r.permanent ? ' · permanent' : ' · no TTL'}
                {r.swept ? ' · swept' : ''}
                {r.note ? ` · ${r.note}` : ''}
              </div>
            </div>
            <div className="text-right shrink-0">
              <div className="text-sm tabular text-ink">{fmtNum(r.count)}</div>
              {r.oldestAgeMs != null && (
                <div className="text-[11px] text-faint">
                  oldest {fmtAge(r.oldestAgeMs)}
                  {r.needsAttention && (
                    <>
                      {' '}
                      <Badge tone="warning">⚠</Badge>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      <p className="text-[12px] text-muted mt-4 leading-relaxed max-w-xl">
        The sweep only deletes provably-dead data: expired relay/session docs, stale rate-limit buckets, and
        revocations past the 30-day cap-expiry floor. The ledger, nullifiers, verified records, and vaults are
        never touched. It also runs automatically once a day.
      </p>

      {confirm && (
        <ConfirmDialog
          title="Purge expired data now?"
          body="Deletes provably-dead docs (expired sessions, stale rate-limit buckets, revocations past the 30-day floor). Permanent records — the ledger, nullifiers, verified records, vaults — are never touched."
          confirmLabel="Purge"
          busy={busy}
          onConfirm={doPurge}
          onCancel={() => !busy && setConfirm(false)}
        />
      )}
    </section>
  );
}
