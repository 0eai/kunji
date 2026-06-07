import React, { useState, useEffect, useRef } from 'react';
import { ShieldCheck, Smartphone } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Spinner } from './ui/primitives';
import { startLinkAsIssuer, watchForPeerKey, depositMasterKey } from '../services/linking';
import { renderBrandedQr } from '../lib/brandedQr';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';

const LINK_TTL_MS = 2 * 60 * 1000; // matches the link session TTL

// Existing (unlocked) device = issuer. Shows a QR + an 8-digit code, waits for the new
// device to join, then shows the shared code (SAS) for the user to compare BEFORE the
// master key is released — Approve deposits the (ECDH-encrypted) key, Cancel sends nothing.
const IssueLinkSheet = ({ masterKey, userId, onClose }) => {
  const { showToast } = useToast();
  const [phase, setPhase] = useState('issuing'); // issuing → waiting → verify → depositing → done → expired
  const [qrData, setQrData] = useState('');
  const [code, setCode] = useState('');
  const [sas, setSas] = useState('');
  const qrRef = useRef(null);
  const ctx = useRef({ linkId: null, privateKey: null, pubB: null });
  const unsubRef = useRef(null);
  const expiryRef = useRef(null);
  // Keep latest callbacks in refs so the init effect can run exactly once on mount —
  // a fresh `onClose` from the parent must NOT restart the link (writing the "Device
  // Linked" activity entry re-renders the parent, which would otherwise re-issue).
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const showToastRef = useRef(showToast);
  showToastRef.current = showToast;

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { linkId, code: c, privateKey, qrData: data } = await startLinkAsIssuer();
        if (!alive) return;
        ctx.current.linkId = linkId;
        ctx.current.privateKey = privateKey;
        setCode(c);
        setQrData(data);
        setPhase('waiting');
        unsubRef.current = watchForPeerKey(
          linkId,
          privateKey,
          (sasCode, pubB) => {
            ctx.current.pubB = pubB;
            setSas(sasCode);
            setPhase('verify');
            unsubRef.current?.();
          },
          () => showToastRef.current('Linking error. Try again.', 'error'),
        );
        expiryRef.current = setTimeout(() => {
          unsubRef.current?.();
          setPhase((p) => (p === 'waiting' ? 'expired' : p));
        }, LINK_TTL_MS);
      } catch (e) {
        showToastRef.current('Could not start linking: ' + e.message, 'error');
        onCloseRef.current();
      }
    })();
    return () => {
      alive = false;
      unsubRef.current?.();
      clearTimeout(expiryRef.current);
    };
  }, []);

  // Render the brand-styled QR once the payload + the container are ready.
  useEffect(() => {
    if (qrData && qrRef.current) renderBrandedQr(qrRef.current, { data: qrData, size: 224 });
  }, [qrData]);

  const approve = async () => {
    setPhase('depositing');
    try {
      await depositMasterKey(ctx.current.linkId, ctx.current.privateKey, masterKey, ctx.current.pubB);
      logActivity(userId, 'Device Linked', 'success', 'Smartphone');
      setPhase('done');
    } catch (e) {
      showToast('Failed to link: ' + e.message, 'error');
      setPhase('verify');
    }
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="issue-link-title">
      {phase === 'verify' || phase === 'depositing' ? (
        <>
          <div className="flex items-center gap-2.5 mb-1">
            <ShieldCheck size={18} className="text-success" />
            <h2 id="issue-link-title" className="text-lg font-semibold tracking-tight">
              Confirm the codes match
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            Approve only if this code matches the one on the new device. If it doesn't, cancel —
            someone may be intercepting the link.
          </p>
          <div className="font-mono tabular text-4xl tracking-[0.2em] text-ink text-center mb-6">
            {sas}
          </div>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={onClose} disabled={phase === 'depositing'}>
              Cancel
            </Btn>
            <Btn variant="primary" onClick={approve} disabled={phase === 'depositing'}>
              {phase === 'depositing' ? (
                <>
                  <Spinner /> Linking…
                </>
              ) : (
                'Approve'
              )}
            </Btn>
          </div>
        </>
      ) : phase === 'done' ? (
        <>
          <div className="flex items-center gap-2.5 mb-1">
            <Smartphone size={18} className="text-success" />
            <h2 id="issue-link-title" className="text-lg font-semibold tracking-tight">
              Device linked
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            The new device now shares this identity. Finish setting its passkey there.
          </p>
          <div className="flex justify-end">
            <Btn variant="primary" onClick={onClose}>
              Done
            </Btn>
          </div>
        </>
      ) : phase === 'expired' ? (
        <>
          <h2 id="issue-link-title" className="text-lg font-semibold tracking-tight mb-1">
            Code expired
          </h2>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            No device joined in time. Close and try again to get a fresh code.
          </p>
          <div className="flex justify-end">
            <Btn variant="primary" onClick={onClose}>
              Close
            </Btn>
          </div>
        </>
      ) : (
        <>
          <h2 id="issue-link-title" className="text-lg font-semibold tracking-tight mb-1">
            Link a device
          </h2>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            On the new device, open kunji and choose{' '}
            <strong className="text-ink font-medium">Link this device</strong>, then scan this QR or
            enter the code.
          </p>
          <div className="flex justify-center mb-4">
            <div className="rounded-2xl border border-line p-4 bg-surface min-h-[208px] flex items-center justify-center">
              <div ref={qrRef} aria-label="Device link QR" className="inline-flex" />
              {!qrData && <Spinner />}
            </div>
          </div>
          {code && (
            <div className="text-center mb-4">
              <div className="text-[11px] uppercase tracking-wide text-faint mb-1">or enter code</div>
              <div className="font-mono tabular text-3xl tracking-[0.2em] text-ink">
                {code.slice(0, 4)} {code.slice(4)}
              </div>
            </div>
          )}
          <p className="text-center text-[12px] text-faint flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-fill animate-pulse" /> Waiting for
            the new device…
          </p>
        </>
      )}
    </Sheet>
  );
};

export default IssueLinkSheet;
