import { useState, useEffect, useCallback } from 'react';
import { fetchLedger, revoke, unrevoke } from '../api.js';
import { Btn, SectionLabel, Badge, EmptyState, SkeletonRows, ConfirmDialog } from '../ui.jsx';
import { useToast } from '../contexts/ToastContext.jsx';
import { claimSummary, fmtDay } from '../lib.js';

// Issuance ledger (newest first) with load-more pagination and confirm-gated revoke / un-revoke.
export default function Ledger() {
  const { showToast } = useToast();
  const [items, setItems] = useState(null);
  const [nextBefore, setNextBefore] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [err, setErr] = useState('');
  const [confirm, setConfirm] = useState(null); // the item pending a revoke/un-revoke
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const l = await fetchLedger();
      setItems(l.items || []);
      setNextBefore(l.nextBefore || null);
      setErr('');
    } catch (e) {
      setErr(e.message);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const loadMore = async () => {
    if (!nextBefore) return;
    setLoadingMore(true);
    try {
      const l = await fetchLedger(nextBefore);
      setItems((xs) => [...(xs || []), ...(l.items || [])]);
      setNextBefore(l.nextBefore || null);
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      setLoadingMore(false);
    }
  };

  const doToggle = async () => {
    const it = confirm;
    setBusy(true);
    try {
      await (it.revoked ? unrevoke(it.type, it.idx) : revoke(it.type, it.idx));
      setItems((xs) => xs.map((x) => (x.id === it.id ? { ...x, revoked: !it.revoked } : x)));
      showToast(it.revoked ? 'Credential un-revoked.' : 'Credential revoked.');
      setConfirm(null);
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  if (err) return <p className="text-[13px] text-danger">{err}</p>;
  if (items === null) return <SkeletonRows rows={6} />;

  return (
    <section>
      <SectionLabel count={items.length} className="mb-1">
        Issuance ledger
      </SectionLabel>
      {items.length === 0 ? (
        <EmptyState title="Nothing issued yet.">Issued credentials appear here, newest first.</EmptyState>
      ) : (
        <>
          <div className="border-t border-line divide-y divide-line">
            {items.map((it) => (
              <div key={it.id} className={`flex items-center gap-3 py-3 ${it.revoked ? 'opacity-50' : ''}`}>
                <div className="flex-1 min-w-0">
                  <div className="text-sm">
                    {it.type} #{it.idx} <span className="font-mono text-[12px] text-muted">{claimSummary(it.claims)}</span>
                  </div>
                  <div className="text-[12px] text-faint font-mono truncate">
                    {it.kid} · {fmtDay(it.issuedAt)}
                  </div>
                </div>
                <Badge tone={it.revoked ? 'danger' : 'success'}>{it.revoked ? 'revoked' : 'valid'}</Badge>
                <Btn variant="quiet" onClick={() => setConfirm(it)}>
                  {it.revoked ? 'Un-revoke' : 'Revoke'}
                </Btn>
              </div>
            ))}
          </div>
          {nextBefore && (
            <div className="flex justify-center mt-5">
              <Btn variant="outline" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load more'}
              </Btn>
            </div>
          )}
        </>
      )}

      {confirm && (
        <ConfirmDialog
          title={confirm.revoked ? 'Un-revoke this credential?' : 'Revoke this credential?'}
          body={
            confirm.revoked
              ? `${confirm.type} #${confirm.idx} will be marked valid again on the status list.`
              : `${confirm.type} #${confirm.idx} will be marked revoked. Verifiers that check the status list will reject it.`
          }
          confirmLabel={confirm.revoked ? 'Un-revoke' : 'Revoke'}
          danger={!confirm.revoked}
          busy={busy}
          onConfirm={doToggle}
          onCancel={() => !busy && setConfirm(null)}
        />
      )}
    </section>
  );
}
