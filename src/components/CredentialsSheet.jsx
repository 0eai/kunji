import React, { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { BadgeCheck, Trash2, DownloadCloud, ScanLine } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Field, Monogram, SheetHeading } from './ui/primitives';
import {
  listCredentials,
  deleteCredential,
  receiveFromIssuer,
  receiveBbsFromIssuer,
  receiveViaOffer,
  groupByPool,
} from '../services/credentials';
import { parseSdJwt } from '../lib/vc';
import { bbsClaimNames } from '../lib/vcBbs';
import { useToast } from '../contexts/ToastContext';

const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));

// Claim names for the list — SD-JWT reads the disclosures; a BBS (v3) credential carries its names.
const claimNamesOf = (cred) => {
  if (!cred) return [];
  if (cred.format === 'bbs') return bbsClaimNames(cred.bbs);
  try {
    return parseSdJwt(cred.sdjwt).disclosures.map((d) => d.name);
  } catch {
    return [];
  }
};
const issuerLabel = (iss) => {
  try {
    return new URL(iss).host;
  } catch {
    return iss;
  }
};
// A kunji-operated issuer → show the bundled (same-origin) kunji mark; no external logo fetch (privacy).
const isKunjiIssuer = (iss) => {
  try {
    const h = new URL(iss).host;
    return h === 'kunji.cc' || h.endsWith('.kunji.cc') || h === 'issuer-kunji-cc.web.app';
  } catch {
    return false;
  }
};
const methodLabel = (m) => (m ? String(m).replace(/[-_]/g, ' ') : null); // 'document-review' → 'document review'
// Issuer brand captured at receipt (record.brand), else the host. No network on view.
const issuerName = (g) => g.brand || issuerLabel(g.iss);

// Verified credentials the user holds (issued by trusted issuers, stored encrypted, shared across
// linked devices). Receive one from an issuer, see what you hold, remove any. Presenting them happens
// at login (ApprovalModal). Mirrors the AgentsSheet pattern.
const CredentialsSheet = ({ masterKey, onClose }) => {
  const { showToast } = useToast();
  const [creds, setCreds] = useState(null); // null = loading
  const [issuerUrl, setIssuerUrl] = useState('');
  const [unlinkable, setUnlinkable] = useState(false); // request a BBS (v3) credential instead of SD-JWT
  const [offer, setOffer] = useState(''); // an OpenID4VCI credential offer (openid-credential-offer://…)
  const [busy, setBusy] = useState(false);
  const [showScanner, setShowScanner] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [deleting, setDeleting] = useState('');

  const refresh = useCallback(() => {
    listCredentials(masterKey)
      .then(setCreds)
      .catch(() => setCreds([]));
  }, [masterKey]);
  useEffect(() => refresh(), [refresh]);

  // A v2 issuer returns a batch of one-time copies; show how many. A v1 issuer returns one.
  const received = (r) => (r?.count > 1 ? `Received ${r.count} single-use copies.` : 'Credential received.');

  const receive = async () => {
    setBusy(true);
    try {
      if (unlinkable) {
        await receiveBbsFromIssuer(masterKey, issuerUrl);
        showToast('Unlinkable credential received.');
      } else {
        showToast(received(await receiveFromIssuer(masterKey, issuerUrl)));
      }
      setIssuerUrl('');
      refresh();
    } catch (e) {
      showToast(e.message || 'Could not receive a credential.', 'error');
    } finally {
      setBusy(false);
    }
  };

  // OpenID4VCI: redeem a credential offer (pasted or scanned) — token + a batch of copies, then store.
  const acceptOffer = async (input) => {
    const value = (input ?? offer).trim();
    if (!value) return;
    setShowScanner(false);
    setBusy(true);
    try {
      showToast(received(await receiveViaOffer(masterKey, value)));
      setOffer('');
      refresh();
    } catch (e) {
      showToast(e.message || 'Could not accept the offer.', 'error');
    } finally {
      setBusy(false);
    }
  };

  // Top up a depleted one-time pool from the same issuer (its origin is the credential's `iss`).
  const receiveMore = async (group) => {
    setBusy(true);
    try {
      showToast(received(await receiveFromIssuer(masterKey, group.iss)));
      refresh();
    } catch (e) {
      showToast(e.message || 'Could not receive more from this issuer.', 'error');
    } finally {
      setBusy(false);
    }
  };

  // Remove a whole logical credential (every one-time copy in its pool).
  const remove = async (group) => {
    setDeleting(group.key);
    try {
      for (const c of group.copies) await deleteCredential(masterKey, c.credId);
      showToast('Credential removed.');
      const gone = new Set(group.copies.map((c) => c.credId));
      setCreds((list) => (list || []).filter((x) => !gone.has(x.credId)));
      return true;
    } catch (e) {
      showToast('Could not remove: ' + (e.message || e), 'error');
      return false;
    } finally {
      setDeleting('');
    }
  };

  const pools = creds === null ? null : groupByPool(creds);

  return (
    <Sheet onClose={onClose} z={60} labelledBy="creds-title">
      <SheetHeading
        id="creds-title"
        icon={BadgeCheck}
        info="Credentials issued to you by trusted issuers. When an app asks you to prove something (like being over 18), you present one — revealing only what's asked, never your date of birth. Each proof spends a fresh single-use copy, so verifiers can't link your visits to each other."
      >
        Verified credentials
      </SheetHeading>

      {pools === null ? (
        <p className="text-[13px] text-faint mb-5">Loading…</p>
      ) : pools.length === 0 ? (
        <p className="text-[13px] text-faint mb-5">No credentials yet.</p>
      ) : (
        <div className="divide-y divide-line border-y border-line mb-5">
          {pools.map((g) => (
            <div key={g.key} className="flex items-center gap-3 py-3">
              <Monogram name={issuerName(g)} seed={g.iss} size="sm" src={isKunjiIssuer(g.iss) ? '/icons/icon.svg' : undefined} />
              <div className="flex-1 min-w-0">
                <p className="text-[14px] text-ink truncate">{g.vct}</p>
                <p className="text-[11px] text-faint truncate">
                  {claimNamesOf(g.sample).join(', ')} · Issued by {issuerName(g)}
                  {g.verifiedVia ? ` · verified via ${methodLabel(g.verifiedVia)}` : ''}
                </p>
                {g.unlinkable && (
                  <p className="text-[11px] text-accent mt-0.5">unlinkable · a fresh proof each time</p>
                )}
                {g.oneTime && (
                  <p className="text-[11px] text-faint mt-0.5">
                    {g.remaining > 0 ? (
                      <>
                        single-use · {g.remaining} {g.remaining === 1 ? 'copy' : 'copies'} left
                        {g.remaining <= 1 && (
                          <button
                            onClick={() => receiveMore(g)}
                            disabled={busy}
                            className="ml-1.5 font-medium text-accent hover:opacity-80 transition-opacity disabled:opacity-50"
                          >
                            Receive more
                          </button>
                        )}
                      </>
                    ) : (
                      <button
                        onClick={() => receiveMore(g)}
                        disabled={busy}
                        className="font-medium text-accent hover:opacity-80 transition-opacity disabled:opacity-50"
                      >
                        None left — receive more
                      </button>
                    )}
                  </p>
                )}
              </div>
              <button
                onClick={() => setConfirm(g)}
                className="shrink-0 inline-flex items-center gap-1 text-[13px] font-medium text-danger hover:opacity-80 transition-opacity"
                title="Remove"
              >
                <Trash2 size={15} />
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="text-[12px] uppercase tracking-wide text-faint mb-2">Accept a credential offer</div>
      <p className="text-[12px] text-faint leading-relaxed mb-2">
        Scan or paste an issuer's offer (<span className="font-mono">openid-credential-offer://…</span>) —
        the OpenID4VCI standard flow.
      </p>
      <Btn variant="quiet" onClick={() => setShowScanner(true)} className="w-full mb-2" disabled={busy}>
        <ScanLine size={16} /> Scan offer
      </Btn>
      <Field label="…or paste the offer" value={offer} onChange={(e) => setOffer(e.target.value)} />
      <Btn variant="primary" onClick={() => acceptOffer()} disabled={busy || !offer.trim()} className="w-full mt-3">
        <DownloadCloud size={16} /> {busy ? 'Accepting…' : 'Accept offer'}
      </Btn>

      <div className="text-[12px] uppercase tracking-wide text-faint mb-2 mt-6">Receive from an issuer</div>
      <Field label="Issuer URL (https://…)" value={issuerUrl} onChange={(e) => setIssuerUrl(e.target.value)} />
      <label className="flex items-center gap-2 mt-2 text-[13px] text-muted cursor-pointer select-none">
        <input
          type="checkbox"
          checked={unlinkable}
          onChange={(e) => setUnlinkable(e.target.checked)}
          className="accent-accent"
        />
        Unlinkable credential (BBS) — one credential, a fresh proof every time
      </label>
      <Btn variant="primary" onClick={receive} disabled={busy || !issuerUrl.trim()} className="w-full mt-3">
        <DownloadCloud size={16} /> {busy ? 'Receiving…' : 'Receive credential'}
      </Btn>

      {showScanner && (
        <Suspense fallback={<div className="fixed inset-0 z-[200] bg-black" />}>
          <QRScannerOverlay onScan={(raw) => acceptOffer(raw)} onClose={() => setShowScanner(false)} />
        </Suspense>
      )}

      {confirm && (
        <Sheet onClose={() => !deleting && setConfirm(null)} z={70} labelledBy="del-cred-title">
          <div className="flex items-center gap-2.5 mb-3">
            <Trash2 size={18} className="text-danger" />
            <h2 id="del-cred-title" className="text-lg font-semibold tracking-tight">
              Remove this credential?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            You'll no longer be able to present <span className="font-mono text-ink">{confirm.vct}</span> from{' '}
            {issuerName(confirm)}. You can receive it again from the issuer.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setConfirm(null)} disabled={!!deleting}>
              Cancel
            </Btn>
            <Btn
              variant="danger"
              onClick={async () => {
                if (await remove(confirm)) setConfirm(null);
              }}
              disabled={!!deleting}
            >
              {deleting ? 'Removing…' : 'Remove'}
            </Btn>
          </div>
        </Sheet>
      )}
    </Sheet>
  );
};

export default CredentialsSheet;
