import React, { useState } from 'react';
import { Trash2 } from 'lucide-react';
import Sheet from './ui/Sheet';
import { SectionLabel, Monogram, Btn } from './ui/primitives';
import { claimNamesOf, isKunjiIssuer, issuerName, methodLabel } from '../lib/credentialFormat';
import { deleteCredential, receiveFromIssuer } from '../services/credentials';
import { useToast } from '../contexts/ToastContext';

// Per-credential detail (mirrors AppDetailsModal/AgentDetailsSheet): issuer, what it proves, format, one-time
// copies (+ receive more), and remove. `group` is a groupByPool entry. Opened from the credentials list.
const CredentialDetailSheet = ({ group: g, masterKey, onClose, onChanged, onRemoved }) => {
  const { showToast } = useToast();
  const [confirm, setConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);

  const claims = claimNamesOf(g.sample);

  // Top up a depleted one-time pool from the same issuer (its origin is the credential's `iss`).
  const receiveMore = async () => {
    setBusy(true);
    try {
      const r = await receiveFromIssuer(masterKey, g.iss);
      showToast(r?.count > 1 ? `Received ${r.count} single-use copies.` : 'Credential received.');
      onChanged?.();
    } catch (e) {
      showToast(e.message || 'Could not receive more from this issuer.', 'error');
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setDeleting(true);
    try {
      for (const c of g.copies) await deleteCredential(masterKey, c.credId);
      showToast('Credential removed.');
      onRemoved?.(g);
      onClose?.();
    } catch (e) {
      showToast('Could not remove: ' + (e.message || e), 'error');
      setDeleting(false);
    }
  };

  return (
    <Sheet onClose={onClose} z={70} labelledBy="creddetail-title">
      <div className="flex items-center gap-3.5 mb-7">
        <Monogram name={issuerName(g)} seed={g.iss} size="lg" src={isKunjiIssuer(g.iss) ? '/icons/icon.svg' : undefined} />
        <div className="min-w-0">
          <h2 id="creddetail-title" className="text-lg font-semibold tracking-tight truncate">
            {g.vct}
          </h2>
          <p className="text-[13px] text-muted truncate">Verified credential</p>
        </div>
      </div>

      <div className="mb-7">
        <SectionLabel
          className="mb-2.5"
          info="A signed credential from an issuer. When an app asks, you present it revealing only the asked-for facts — never your date of birth. Each proof spends a fresh single-use copy (or, for an unlinkable credential, a fresh randomized proof), so verifiers can't link your visits."
        >
          Details
        </SectionLabel>
        <div className="divide-y divide-line border-y border-line">
          <div className="flex items-start justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted shrink-0">Issuer</span>
            <span className="text-[13px] text-ink text-right break-all min-w-0">
              {issuerName(g)}
              {g.verifiedVia ? (
                <span className="block text-[12px] text-faint">verified via {methodLabel(g.verifiedVia)}</span>
              ) : null}
            </span>
          </div>
          <div className="flex items-start justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted shrink-0">Proves</span>
            <span className="text-[13px] font-mono text-ink text-right break-all min-w-0">
              {claims.join(', ') || g.vct}
            </span>
          </div>
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">Format</span>
            <span className={`text-[13px] text-right ${g.unlinkable ? 'text-accent' : 'text-ink'}`}>
              {g.unlinkable ? 'Unlinkable (BBS)' : 'SD-JWT'}
            </span>
          </div>
          {g.oneTime && (
            <div className="flex items-center justify-between gap-4 py-3.5">
              <span className="text-[13px] text-muted">Copies left</span>
              <span className="flex items-center gap-2 text-[13px] text-ink">
                <span className={g.remaining <= 1 ? 'text-accent' : ''}>{g.remaining}</span>
                <button
                  onClick={receiveMore}
                  disabled={busy}
                  className="font-medium text-accent hover:opacity-80 transition-opacity disabled:opacity-50"
                >
                  {busy ? '…' : 'Receive more'}
                </button>
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="border-t border-line">
        <button
          onClick={() => setConfirm(true)}
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-danger hover:bg-danger-soft active:opacity-80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30"
        >
          <Trash2 size={17} strokeWidth={1.75} />
          <span className="text-[15px] font-medium">Remove credential</span>
        </button>
      </div>

      {confirm && (
        <Sheet onClose={() => !deleting && setConfirm(false)} z={80} labelledBy="del-cred-title">
          <div className="flex items-center gap-2.5 mb-3">
            <Trash2 size={18} className="text-danger" />
            <h2 id="del-cred-title" className="text-lg font-semibold tracking-tight">
              Remove this credential?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            You'll no longer be able to present <span className="font-mono text-ink">{g.vct}</span> from{' '}
            {issuerName(g)}. You can receive it again from the issuer.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setConfirm(false)} disabled={deleting}>
              Cancel
            </Btn>
            <Btn variant="danger" onClick={remove} disabled={deleting}>
              {deleting ? 'Removing…' : 'Remove'}
            </Btn>
          </div>
        </Sheet>
      )}
    </Sheet>
  );
};

export default CredentialDetailSheet;
