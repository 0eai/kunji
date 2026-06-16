import React, { useState, lazy, Suspense } from 'react';
import { DownloadCloud, ScanLine } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Field, SheetHeading } from './ui/primitives';
import {
  receiveFromIssuer,
  receiveBbsFromIssuer,
  receiveViaOffer,
  offerNeedsSignIn,
  beginAuthCodeFlow,
} from '../services/credentials';
import { useToast } from '../contexts/ToastContext';

const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));

// A v2 issuer returns a batch of one-time copies; show how many. A v1 issuer returns one.
const received = (r) => (r?.count > 1 ? `Received ${r.count} single-use copies.` : 'Credential received.');

// The two ways to receive a verified credential, off the main list (its own focused sheet): accept an
// OpenID4VCI offer (scan/paste) or receive from an issuer URL (optionally as an unlinkable BBS credential).
// On success it calls `onReceived` (parent refreshes) and closes. The separate `?offer=`/scan deep link uses
// ReceiveOfferSheet — this is the user-initiated path.
const ReceiveCredentialSheet = ({ masterKey, onClose, onReceived }) => {
  const { showToast } = useToast();
  const [offer, setOffer] = useState(''); // an OpenID4VCI offer (openid-credential-offer://…)
  const [issuerUrl, setIssuerUrl] = useState('');
  const [unlinkable, setUnlinkable] = useState(false); // request a BBS (v3) credential instead of SD-JWT
  const [busy, setBusy] = useState(false);
  const [showScanner, setShowScanner] = useState(false);

  const done = (msg) => {
    showToast(msg);
    onReceived?.();
    onClose?.();
  };

  const acceptOffer = async (input) => {
    const value = (input ?? offer).trim();
    if (!value) return;
    setShowScanner(false);
    setBusy(true);
    try {
      if (offerNeedsSignIn(value)) {
        // authorization_code offer → sign-in (redirect) on-ramp; navigate to the issuer's /authorize.
        window.location.assign(await beginAuthCodeFlow(value));
        return; // navigating away — leave `busy` set
      }
      done(received(await receiveViaOffer(masterKey, value)));
    } catch (e) {
      showToast(e.message || 'Could not accept the offer.', 'error');
      setBusy(false);
    }
  };

  const receive = async () => {
    if (!issuerUrl.trim()) return;
    setBusy(true);
    try {
      if (unlinkable) {
        await receiveBbsFromIssuer(masterKey, issuerUrl);
        done('Unlinkable credential received.');
      } else {
        done(received(await receiveFromIssuer(masterKey, issuerUrl)));
      }
    } catch (e) {
      showToast(e.message || 'Could not receive a credential.', 'error');
      setBusy(false);
    }
  };

  return (
    <Sheet onClose={onClose} z={70} labelledBy="receive-cred-title">
      <SheetHeading
        id="receive-cred-title"
        icon={DownloadCloud}
        info="Two ways to get a credential: accept an issuer's OpenID4VCI offer (scan/paste), or fetch one from an issuer's URL. An unlinkable (BBS) credential is one credential that produces a fresh, unlinkable proof every time you present it."
      >
        Receive a credential
      </SheetHeading>

      <p className="text-[12px] text-faint leading-relaxed mb-6">
        kunji can't vouch for an issuer — a credential is only as trusted as whoever signs it. Receive only
        from issuers you trust.
      </p>

      <div className="text-[12px] uppercase tracking-wide text-faint mb-2">Accept a credential offer</div>
      <Btn variant="quiet" onClick={() => setShowScanner(true)} className="w-full mb-2" disabled={busy}>
        <ScanLine size={16} /> Scan offer
      </Btn>
      <Field label="…or paste the offer" value={offer} onChange={(e) => setOffer(e.target.value)} />
      <Btn variant="primary" onClick={() => acceptOffer()} disabled={busy || !offer.trim()} className="w-full mt-3">
        <DownloadCloud size={16} /> {busy ? 'Accepting…' : 'Accept offer'}
      </Btn>

      <div className="text-[12px] uppercase tracking-wide text-faint mb-2 mt-7">Receive from an issuer</div>
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
    </Sheet>
  );
};

export default ReceiveCredentialSheet;
