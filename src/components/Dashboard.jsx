import React, { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import { ScanLine, Lock, Shield, Settings } from 'lucide-react';
import { listenToApps, deleteApp, registerApp, deriveAppIdentity, parseQRPayload, submitDiscoverableAssertion, deriveSubFromPublicKey, migrateLegacyApps, lookupSessionByCode, isSafeReturnUrl } from '../services/identity';
import { completeLink, vaultFingerprint } from '../services/linking';
import { deriveVaultId } from '../lib/crypto';
import AppRow from './AppRow';
import ApprovalModal from './ApprovalModal';
import AppDetailsModal from './AppDetailsModal';
import SecurityPanel from './SecurityPanel';
import CodeEntryModal from './CodeEntryModal';
import Sheet from './ui/Sheet';
import { SectionLabel, Btn } from './ui/primitives';
import { useToast } from '../contexts/ToastContext';

// Lazy: the camera scanner (jsqr) loads only when opened.
const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));

const Dashboard = ({ user, cryptoKey, onLock, incomingApproval }) => {
  const { showToast } = useToast();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [vaultId, setVaultId] = useState(null);

  const [showScanner, setShowScanner] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [pendingSession, setPendingSession] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);
  const [pendingDelete, setPendingDelete] = useState(null); // app awaiting remove confirmation
  const [codeApp, setCodeApp] = useState(null); // app awaiting a typed login code
  const [returnInfo, setReturnInfo] = useState(null); // { audience, returnUrl } after same-device approval
  const [linkConfirm, setLinkConfirm] = useState(null); // { fingerprint } after linking a device (compare on both)
  const incomingHandled = useRef(false);

  // Derive the shared vault id from the master key (same on every linked device).
  useEffect(() => {
    deriveVaultId(cryptoKey).then(setVaultId).catch(() => setVaultId(null));
  }, [cryptoKey]);

  useEffect(() => {
    if (!vaultId) return;
    const unsub = listenToApps(vaultId, cryptoKey, (data) => {
      setApps(data);
      setLoading(false);
    });
    return unsub;
  }, [vaultId, cryptoKey]);

  // One-time: bring forward apps registered before the move to vaultId storage.
  useEffect(() => {
    if (!vaultId) return;
    const flag = `kunji_migrated_${user.uid}`;
    if (localStorage.getItem(flag)) return;
    migrateLegacyApps(user.uid, vaultId, cryptoKey)
      .then((n) => { localStorage.setItem(flag, '1'); if (n) showToast(`Restored ${n} app${n > 1 ? 's' : ''}.`); })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, user.uid]);

  // Same-device deep-link: process an incoming approval payload once the vault is ready.
  useEffect(() => {
    if (!vaultId || !incomingApproval || incomingHandled.current) return;
    incomingHandled.current = true;
    handleQRScan(incomingApproval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, incomingApproval]);

  // useCallback so QRScannerOverlay's [onScan] effect doesn't tear down the camera
  // on every parent re-render.
  const handleQRScan = useCallback(async (rawValue) => {
    setShowScanner(false);

    // A device-link QR ({kunjiLink:'v1'}) — transfer the master key to the new device.
    try {
      const maybeLink = JSON.parse(rawValue);
      if (maybeLink?.kunjiLink === 'v1') {
        try {
          await completeLink(rawValue, cryptoKey);
          setLinkConfirm({ fingerprint: await vaultFingerprint(cryptoKey) });
        } catch (e) {
          const m = e.message === 'link_expired' ? 'Link QR expired.'
            : e.message === 'link_already_used' ? 'That link was already used.'
            : 'Linking failed: ' + e.message;
          showToast(m, 'error');
        }
        return;
      }
    } catch { /* not JSON / not a link QR — fall through to login parsing */ }

    try {
      const qr = parseQRPayload(rawValue);

      // Derive the per-app identity for the approval screen WITHOUT writing to the
      // vault — registration is persisted only after the user approves (handleApprove).
      const { registeredAppId, publicKey, isNew } = await deriveAppIdentity(vaultId, cryptoKey, qr.audience);

      const sub = await deriveSubFromPublicKey(publicKey);
      setPendingSession({
        ...qr,
        registeredAppId,
        publicKey,
        appName: qr.appName || qr.audience,
        domain: qr.audience,
        sub,
        isNew,
      });
    } catch (err) {
      const msg = err.message === 'expired_qr' ? 'QR code has expired.'
        : err.message === 'untrusted_callback' ? 'Untrusted login request (callback domain mismatch).'
        : 'Invalid QR code.';
      showToast(msg, 'error');
    }
  }, [vaultId, cryptoKey, user.uid, showToast]);

  const handleApprove = async () => {
    if (!pendingSession) return;
    const { audience, returnUrl, appName, domain, iconUrl } = pendingSession;
    try {
      // Persist the app to the vault only now that the user has consented (idempotent).
      await registerApp(vaultId, cryptoKey, { name: appName, domain, iconUrl: iconUrl || '' }, user.uid);
      await submitDiscoverableAssertion(user.uid, cryptoKey, pendingSession);
      showToast(`Signed in to ${audience}`);
      // Only offer the "Return to …" link if it's https + same-site as the audience.
      setReturnInfo({ audience, returnUrl: isSafeReturnUrl(returnUrl, audience) ? returnUrl : null });
    } catch (e) {
      showToast('Login failed: ' + e.message, 'error');
    } finally {
      setPendingSession(null);
    }
  };

  const handleDeny = () => {
    // No shared session to update — kunji simply declines locally.
    showToast('Login request declined.');
    setPendingSession(null);
  };

  // Device-authorization: resolve a typed code for a known app, then show the
  // normal approval. Throws on failure so CodeEntryModal can surface the error.
  const handleCodeSubmit = async (app, code) => {
    const session = await lookupSessionByCode(app.domain, code);
    const sub = await deriveSubFromPublicKey(app.publicKey);
    setCodeApp(null);
    setPendingSession({
      ...session,
      registeredAppId: app.id,
      publicKey: app.publicKey,
      appName: app.name,
      domain: session.audience,
      sub,
      isNew: false,
    });
  };

  const confirmDelete = async () => {
    const app = pendingDelete;
    setPendingDelete(null);
    if (!app) return;
    try {
      await deleteApp(vaultId, app.id, app.name, cryptoKey, user.uid);
      showToast(`Removed ${app.name}`);
    } catch (e) {
      showToast('Delete failed: ' + e.message, 'error');
    }
  };

  return (
    <div className="h-[100dvh] bg-paper text-ink flex flex-col overflow-hidden">
      {/* Header — wordmark + minimal glyph actions */}
      <header className="flex items-center justify-between max-w-[34rem] w-full mx-auto px-6 pt-[max(1.5rem,env(safe-area-inset-top))] pb-5 shrink-0">
        <div className="flex items-center gap-2">
          <img src="/icons/icon.svg" alt="" className="w-6 h-6" />
          <span className="text-[15px] font-semibold tracking-tight lowercase">kunji</span>
        </div>
        <div className="flex items-center gap-0.5 -mr-2">
          <button onClick={() => setShowScanner(true)} title="Scan a code" aria-label="Scan a code"
            className="p-2.5 rounded-full text-muted hover:text-ink hover:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40">
            <ScanLine size={18} strokeWidth={1.75} />
          </button>
          <button onClick={() => setShowSecurity(true)} title="Security" aria-label="Security"
            className="p-2.5 rounded-full text-muted hover:text-ink hover:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40">
            <Settings size={18} strokeWidth={1.75} />
          </button>
          <button onClick={onLock} title="Lock" aria-label="Lock"
            className="p-2.5 rounded-full text-muted hover:text-ink hover:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40">
            <Lock size={18} strokeWidth={1.75} />
          </button>
        </div>
      </header>

      {/* App list — hairline rows, no cards */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-[34rem] w-full mx-auto px-6">
          {loading ? (
            <div className="pt-7">
              <div className="divide-y divide-line">
                {[0, 1, 2].map((i) => (
                  <div key={i} className="flex items-center gap-4 py-4">
                    <span className="w-10 h-10 rounded-xl shimmer shrink-0" />
                    <div className="flex-1 space-y-2">
                      <span className="block h-3 w-1/3 rounded shimmer" />
                      <span className="block h-3 w-1/2 rounded shimmer" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : apps.length === 0 ? (
            <div className="flex flex-col justify-center min-h-[55vh] max-w-sm">
              <h1 className="text-[1.75rem] leading-tight font-semibold tracking-tight mb-3">No apps yet</h1>
              <p className="text-[15px] text-muted leading-relaxed mb-6">
                Scan an app's login code to sign in. It's added here automatically — one private identity per app.
              </p>
              <button onClick={() => setShowScanner(true)}
                className="inline-flex items-center gap-2 text-accent hover:text-ink font-medium text-sm transition-colors w-fit">
                <ScanLine size={16} /> Scan a code
              </button>
            </div>
          ) : (
            <>
              <SectionLabel count={apps.length} className="pt-1 pb-1">Apps</SectionLabel>
              <div className="divide-y divide-line animate-rise">
                {apps.map(app => (
                  <AppRow key={app.id} app={app} onOpen={() => setSelectedApp(app)} />
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Slim bottom action — hairline-topped, not a slab */}
      {!loading && apps.length > 0 && (
        <div className="shrink-0 border-t border-line">
          <div className="max-w-[34rem] w-full mx-auto px-6 py-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
            <button onClick={() => setShowScanner(true)}
              className="w-full flex items-center justify-center gap-2 py-2.5 text-accent hover:text-ink font-medium text-sm transition-colors">
              <ScanLine size={17} /> Scan a login code
            </button>
          </div>
        </div>
      )}

      {/* Modals */}
      {showScanner && (
        <Suspense fallback={<div className="fixed inset-0 z-[200] bg-black" />}>
          <QRScannerOverlay
            onScan={handleQRScan}
            onClose={() => setShowScanner(false)}
          />
        </Suspense>
      )}

      {pendingSession && (
        <ApprovalModal
          session={pendingSession}
          onApprove={handleApprove}
          onDeny={handleDeny}
          onClose={() => setPendingSession(null)}
        />
      )}

      {selectedApp && (
        <AppDetailsModal
          app={selectedApp}
          userId={user.uid}
          cryptoKey={cryptoKey}
          onClose={() => setSelectedApp(null)}
          onEnterCode={() => { const a = selectedApp; setSelectedApp(null); setCodeApp(a); }}
          onDelete={() => { const a = selectedApp; setSelectedApp(null); setPendingDelete(a); }}
        />
      )}

      {showSecurity && (
        <SecurityPanel
          userId={user.uid}
          cryptoKey={cryptoKey}
          onLock={onLock}
          onClose={() => setShowSecurity(false)}
        />
      )}

      {codeApp && (
        <CodeEntryModal
          app={codeApp}
          onSubmit={handleCodeSubmit}
          onClose={() => setCodeApp(null)}
        />
      )}

      {pendingDelete && (
        <Sheet onClose={() => setPendingDelete(null)} z={60} labelledBy="remove-title">
          <h2 id="remove-title" className="text-lg font-semibold tracking-tight mb-1">Remove {pendingDelete.name}?</h2>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            It's removed from your list on all your devices. You can re-add it anytime by scanning its login code —
            your identity for it stays the same.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setPendingDelete(null)}>Cancel</Btn>
            <Btn variant="danger" onClick={confirmDelete}>Remove</Btn>
          </div>
        </Sheet>
      )}

      {returnInfo && (
        <Sheet onClose={() => setReturnInfo(null)} labelledBy="signed-in-title">
          <div className="flex items-center gap-2.5 mb-1">
            <Shield size={18} className="text-success" />
            <h2 id="signed-in-title" className="text-lg font-semibold tracking-tight">Signed in</h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            You approved sign-in to <span className="font-mono text-ink">{returnInfo.audience}</span>.
          </p>
          {returnInfo.returnUrl && (
            <a href={returnInfo.returnUrl}
              className="inline-flex items-center justify-center gap-2 w-full px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full transition-colors">
              Return to {returnInfo.audience}
            </a>
          )}
          <button onClick={() => setReturnInfo(null)}
            className="mt-2 w-full text-center text-sm font-medium text-muted hover:text-ink py-2 transition-colors">
            {returnInfo.returnUrl ? 'Stay in kunji' : 'Done'}
          </button>
        </Sheet>
      )}

      {linkConfirm && (
        <Sheet onClose={() => setLinkConfirm(null)} labelledBy="link-title">
          <div className="flex items-center gap-2.5 mb-1">
            <Shield size={18} className="text-success" />
            <h2 id="link-title" className="text-lg font-semibold tracking-tight">Device linked</h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            Confirm this code matches the one shown on the new device. If it doesn't, that device may have received the wrong key — don't approve it there.
          </p>
          <div className="font-mono tabular text-4xl tracking-[0.2em] text-ink text-center mb-6">{linkConfirm.fingerprint}</div>
          <div className="flex justify-end">
            <Btn variant="primary" onClick={() => setLinkConfirm(null)}>Done</Btn>
          </div>
        </Sheet>
      )}
    </div>
  );
};

export default Dashboard;
