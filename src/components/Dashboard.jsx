import React, { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import { ScanLine, Lock, Shield, Settings, Bot, KeyRound } from 'lucide-react';
import {
  listenToApps,
  deleteApp,
  registerApp,
  deriveAppIdentity,
  parseQRPayload,
  submitDiscoverableAssertion,
  deriveSubFromPublicKey,
  migrateLegacyApps,
  lookupSessionByCode,
  isSafeReturnUrl,
  requestsProfile,
  requestsCredentials,
} from '../services/identity';
import { loadProfile } from '../services/profile';
import {
  listCredentials,
  responseTargetTrusted,
  fetchVerifierKeys,
  resolveVerifierDidKey,
  verifyVerifierX509,
  WALLET_TRUST_ANCHORS,
  selectForPresentation,
  holderKeyFor,
  spendIfOneTime,
  presentBbsForLogin,
} from '../services/credentials';
import { buildPresentation } from '../lib/vc';
import { resolveAuthorizationRequest, requestQuery, verifyRequestObject } from '../lib/oid4vc';
import { recordThisDevice } from '../services/devices';
import { deriveVaultId } from '../lib/crypto';
import AppRow from './AppRow';
import ApprovalModal from './ApprovalModal';
import AppDetailsModal from './AppDetailsModal';
import SecurityPanel from './SecurityPanel';
import AgentsSheet from './AgentsSheet';
import AuthorizeAgentSheet from './AuthorizeAgentSheet';
import PresentCredentialSheet from './PresentCredentialSheet';
import CodeEntryModal from './CodeEntryModal';
import CodePickerSheet from './CodePickerSheet';
import Sheet from './ui/Sheet';
import { SectionLabel, Btn } from './ui/primitives';
import { listAgents, lookupAgentRequest } from '../services/capability';
import { useToast } from '../contexts/ToastContext';

// Lazy: the camera scanner (jsqr) loads only when opened.
const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));

const Dashboard = ({
  user,
  cryptoKey,
  onLock,
  incomingApproval,
  incomingAuthorize,
  incomingPresentation,
  incomingPush,
}) => {
  const { showToast } = useToast();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [vaultId, setVaultId] = useState(null);
  const [profile, setProfile] = useState(null); // user's optional custom profile (Layer 2)

  const [showScanner, setShowScanner] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [showAgents, setShowAgents] = useState(false);
  const [agentCount, setAgentCount] = useState(0); // active (non-expired) authorized agents
  const [pendingSession, setPendingSession] = useState(null);
  const [pendingAuthorize, setPendingAuthorize] = useState(null); // raw agent request from ?authorize= deep link
  const [pendingPresentation, setPendingPresentation] = useState(null); // { request, query, matches } — OpenID4VP
  const [selectedApp, setSelectedApp] = useState(null);
  const [pendingDelete, setPendingDelete] = useState(null); // app awaiting remove confirmation
  const [codeApp, setCodeApp] = useState(null); // app awaiting a typed login code
  const [showCodePicker, setShowCodePicker] = useState(false); // top-level "enter a code": pick which app first
  const [returnInfo, setReturnInfo] = useState(null); // { audience, returnUrl } — same-device (deep-link) approval only
  const incomingHandled = useRef(false);
  const authorizeHandled = useRef(false);
  const presentationHandled = useRef(false);
  const pushHandled = useRef(false);

  // Derive the shared vault id from the master key (same on every linked device).
  useEffect(() => {
    deriveVaultId(cryptoKey)
      .then(setVaultId)
      .catch(() => setVaultId(null));
  }, [cryptoKey]);

  useEffect(() => {
    if (!vaultId) return;
    const unsub = listenToApps(vaultId, cryptoKey, (data) => {
      setApps(data);
      setLoading(false);
    });
    return unsub;
  }, [vaultId, cryptoKey]);

  // Load the optional custom profile so the approval screen can offer to share it.
  useEffect(() => {
    if (!vaultId) return;
    loadProfile(vaultId, cryptoKey)
      .then(setProfile)
      .catch(() => setProfile(null));
  }, [vaultId, cryptoKey]);

  // Register this device in the shared linked-devices list (once per device). Best-effort — never
  // blocks; covers vault creation, unlock, recovery, and device-link (all reach an unlocked Dashboard).
  useEffect(() => {
    if (cryptoKey) recordThisDevice(cryptoKey).catch(() => {});
  }, [cryptoKey]);

  // Active-agents count — drives the header chip. listAgents already drops expired ones, so the
  // length is the live count. Re-run after the agents/security sheets close (either can change it).
  const refreshAgents = useCallback(() => {
    listAgents(cryptoKey)
      .then((a) => setAgentCount(a.length))
      .catch(() => setAgentCount(0));
  }, [cryptoKey]);
  useEffect(() => {
    if (cryptoKey) refreshAgents();
  }, [cryptoKey, refreshAgents]);

  // One-time: bring forward apps registered before the move to vaultId storage.
  useEffect(() => {
    if (!vaultId) return;
    const flag = `kunji_migrated_${user.uid}`;
    if (localStorage.getItem(flag)) return;
    migrateLegacyApps(user.uid, vaultId, cryptoKey)
      .then((n) => {
        localStorage.setItem(flag, '1');
        if (n) showToast(`Restored ${n} app${n > 1 ? 's' : ''}.`);
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, user.uid]);

  // Same-device deep-link: process an incoming login-approval payload once the vault is ready.
  useEffect(() => {
    if (!vaultId || !incomingApproval || incomingHandled.current) return;
    incomingHandled.current = true;
    handleQRScan(incomingApproval, 'deeplink');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, incomingApproval]);

  // Same-device deep-link: an app/agent asking for (more) scope opens the agent re-consent sheet
  // directly (push-relay.md Transport ① step-up). The sheet validates + ingests the request itself.
  useEffect(() => {
    if (!vaultId || !incomingAuthorize || authorizeHandled.current) return;
    authorizeHandled.current = true;
    setPendingAuthorize(incomingAuthorize);
  }, [vaultId, incomingAuthorize]);

  // Same-device deep-link: an OpenID4VP request (?vp=) opens the present sheet once the vault is ready.
  useEffect(() => {
    if (!vaultId || !incomingPresentation || presentationHandled.current) return;
    presentationHandled.current = true;
    handlePresentationRequest(incomingPresentation);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, incomingPresentation]);

  // Web Push (push-relay.md Transport ②): a tapped notification points at a step-up request id (the
  // agent-relay code). Look it up and open the SAME re-consent sheet as the ?authorize= deep link.
  const handlePushPointer = useCallback(
    async (requestId) => {
      try {
        const raw = await lookupAgentRequest(requestId);
        setPendingAuthorize(raw);
      } catch {
        showToast('Could not load the pushed request.', 'error');
      }
    },
    [showToast],
  );

  // Cold open from a tapped notification: app.kunji.cc/?push=<requestId>, once the vault is ready.
  useEffect(() => {
    if (!vaultId || !incomingPush || pushHandled.current) return;
    pushHandled.current = true;
    handlePushPointer(incomingPush);
  }, [vaultId, incomingPush, handlePushPointer]);

  // Warm open: the service worker postMessages an already-open wallet when a notification is tapped.
  useEffect(() => {
    if (!vaultId || typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return;
    const onMsg = (e) => {
      if (e?.data?.type === 'kunji-push' && /^\d{6}$/.test(e.data.requestId || '')) handlePushPointer(e.data.requestId);
    };
    navigator.serviceWorker.addEventListener('message', onMsg);
    return () => navigator.serviceWorker.removeEventListener('message', onMsg);
  }, [vaultId, handlePushPointer]);

  // OpenID4VP: a verifier asked the wallet to present a credential (a distinct flow from the kunji
  // login QR — docs/oid4vc.md). Match held credentials to the request and open the present sheet.
  const handlePresentationRequest = useCallback(
    async (raw) => {
      setShowScanner(false);
      try {
        // Resolve a by-reference request (request_uri) by fetching the signed request object; an inline
        // request is parsed directly. The signature check below is the trust anchor either way.
        const request = await resolveAuthorizationRequest(raw);
        // Verifier authentication: a SIGNED request must verify against the verifier's published key
        // (the HTTPS-anchored client_id scheme) — proves who's asking. [oid4vc hardening]
        let verified = false;
        if (request.signed) {
          const vr = await verifyRequestObject({
            requestJwt: request.requestJwt,
            getVerifierKeys: fetchVerifierKeys,
            resolveDidKey: resolveVerifierDidKey, // did:jwk / did:web
            verifyX509: verifyVerifierX509, // x509_san_dns (fails closed without pinned anchors)
            trustAnchors: WALLET_TRUST_ANCHORS,
            clientId: request.clientId,
          });
          if (!vr.ok) {
            showToast('Untrusted presentation request (bad signature).', 'error');
            return;
          }
          verified = true;
        }
        // Refuse a request whose response endpoint isn't bound to the verifier identity it shows. A did:jwk
        // verifier has no host to bind to, so it's only allowed with an encrypted response. [S20]
        const targetOk =
          responseTargetTrusted(request.clientId, request.responseUri) ||
          (request.clientId?.startsWith('did:jwk:') && request.responseMode === 'direct_post.jwt');
        if (!targetOk) {
          showToast('Untrusted presentation request.', 'error');
          return;
        }
        const q = requestQuery(request); // unified DCQL / presentation_definition view
        const scopeId =
          'vc:' + q.vct + (q.iss ? '@' + q.iss : '') + (q.disclose?.length ? '#' + q.disclose.join(',') : '');
        // One copy per logical credential; offer only credentials whose format the request asked for
        // (a `vc+bbs` request → BBS creds; SD-JWT request → SD-JWT creds).
        const wantBbs = q.format === 'vc+bbs';
        const matches = selectForPresentation(await listCredentials(cryptoKey), [scopeId]).filter(
          (m) => (m.cred.format === 'bbs') === wantBbs,
        );
        setPendingPresentation({ request, query: q, matches, verified });
      } catch {
        showToast('Invalid presentation request.', 'error');
      }
    },
    [cryptoKey, showToast],
  );

  // useCallback so QRScannerOverlay's [onScan] effect doesn't tear down the camera
  // on every parent re-render.
  const handleQRScan = useCallback(
    async (rawValue, origin = 'qr') => {
      setShowScanner(false);

      // An OpenID4VP request (scanned or via the ?vp= deep link) routes to the present sheet, not login.
      const raw = typeof rawValue === 'string' ? rawValue.trim() : rawValue;
      if (typeof raw === 'string' && raw.startsWith('openid4vp://')) return handlePresentationRequest(raw);

      try {
        const qr = parseQRPayload(rawValue);

        // Derive the per-app identity for the approval screen WITHOUT writing to the
        // vault — registration is persisted only after the user approves (handleApprove).
        const { registeredAppId, publicKey, isNew } = await deriveAppIdentity(
          vaultId,
          cryptoKey,
          qr.audience,
        );

        const sub = await deriveSubFromPublicKey(publicKey);
        // If the app requested a verified credential (a `vc:` scope), find held credentials that can
        // satisfy it so the approval screen can offer to present one.
        let credentialMatches = [];
        if (requestsCredentials(qr)) {
          try {
            // One copy per logical credential (a v2 pool presents — and spends — a single copy).
            const all = selectForPresentation(await listCredentials(cryptoKey), qr.scope);
            // Login has no format negotiation: prefer SD-JWT when both formats satisfy the same request
            // (max RP compatibility); present a BBS credential only when it's the sole match for its vct.
            const sdjwtKeys = new Set(
              all.filter((m) => m.cred.format !== 'bbs').map((m) => `${m.cred.vct}@${m.cred.iss}`),
            );
            credentialMatches = all.filter(
              (m) => m.cred.format !== 'bbs' || !sdjwtKeys.has(`${m.cred.vct}@${m.cred.iss}`),
            );
          } catch {
            credentialMatches = [];
          }
        }
        setPendingSession({
          ...qr,
          registeredAppId,
          publicKey,
          appName: qr.appName || qr.audience,
          domain: qr.audience,
          sub,
          isNew,
          requestProfile: requestsProfile(qr),
          requestCredentials: requestsCredentials(qr),
          credentialMatches,
          // Only the same-device deep link returns to a tab on THIS device; a scanned
          // QR is cross-device, so its post-approval "Return to…" sheet is suppressed.
          sameDevice: origin === 'deeplink',
        });
      } catch (err) {
        const msg =
          err.message === 'expired_qr'
            ? 'QR code has expired.'
            : err.message === 'untrusted_callback'
              ? 'Untrusted login request (callback domain mismatch).'
              : 'Invalid QR code.';
        showToast(msg, 'error');
      }
    },
    [vaultId, cryptoKey, showToast, handlePresentationRequest],
  );

  const handleApprove = async ({ shareProfile, credentials = [] } = {}) => {
    if (!pendingSession) return;
    const { audience, returnUrl, appName, domain, iconUrl } = pendingSession;
    try {
      // Persist the app to the vault only now that the user has consented (idempotent).
      await registerApp(
        vaultId,
        cryptoKey,
        { name: appName, domain, iconUrl: iconUrl || '', sharedProfile: !!shareProfile },
        user.uid,
      );
      // Share the custom profile only if the user toggled it on for this login.
      const claims =
        shareProfile && profile
          ? { name: profile.displayName, picture: profile.avatar }
          : undefined;
      // Build a presentation for each verified credential the user chose: selective disclosure +
      // a holder-of-key proof bound to THIS session's challenge. A v2 one-time copy presents with its
      // own stored holder key; a v1 credential re-derives the per-issuer key (holderKeyFor handles both).
      let vcPresentations;
      if (credentials.length) {
        vcPresentations = [];
        for (const { cred, disclose } of credentials) {
          if (cred.format === 'bbs') {
            // Unlinkable (v3): a fresh BBS proof bound to this session, as a tagged string.
            vcPresentations.push(
              await presentBbsForLogin(cryptoKey, {
                cred,
                disclose,
                audience: pendingSession.audience,
                nonce: pendingSession.challenge,
              }),
            );
          } else {
            vcPresentations.push(
              await buildPresentation({
                sdjwt: cred.sdjwt,
                disclose,
                audience: pendingSession.audience,
                nonce: pendingSession.challenge,
                holderSecretKey: await holderKeyFor(cryptoKey, cred),
              }),
            );
          }
        }
      }
      await submitDiscoverableAssertion(user.uid, cryptoKey, pendingSession, claims, vcPresentations);
      // A one-time copy is spent once the assertion is in (best-effort; v1 credentials stay put).
      for (const { cred } of credentials) await spendIfOneTime(cryptoKey, cred);
      showToast(`Signed in to ${audience}`);
      // The toast above is the confirmation for cross-device (QR) / device-code sign-ins.
      // Only the same-device deep link shows the "Return to …" sheet (it returns to the
      // tab on THIS device). The Return link itself stays gated to https + same-site.
      if (pendingSession.sameDevice) {
        setReturnInfo({
          audience,
          returnUrl: isSafeReturnUrl(returnUrl, audience) ? returnUrl : null,
        });
      }
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
          <img src="/icons/icon.svg" alt="" className="w-7 h-7" />
          <div className="flex flex-col leading-none">
            <span className="text-[15px] font-semibold tracking-tight lowercase">kunji</span>
            <span className="hidden min-[380px]:block text-[10px] text-faint tracking-tight mt-0.5">
              Be your own key.
            </span>
          </div>
        </div>
        <div className="flex items-center gap-0.5 -mr-2">
          {agentCount > 0 && (
            <button
              onClick={() => setShowAgents(true)}
              title={`${agentCount} active agent${agentCount > 1 ? 's' : ''}`}
              aria-label={`${agentCount} active agent${agentCount > 1 ? 's' : ''} — manage`}
              className="inline-flex items-center gap-1 mr-1 px-2.5 py-1 rounded-full text-[12px] font-medium bg-accent-soft text-accent hover:opacity-80 transition-opacity focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
            >
              <Bot size={14} strokeWidth={1.75} /> {agentCount}
            </button>
          )}
          <button
            onClick={() => setShowScanner(true)}
            title="Scan a code"
            aria-label="Scan a code"
            className="p-2.5 rounded-full text-muted hover:text-ink hover:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <ScanLine size={18} strokeWidth={1.75} />
          </button>
          <button
            onClick={() => setShowSecurity(true)}
            title="Security"
            aria-label="Security"
            className="p-2.5 rounded-full text-muted hover:text-ink hover:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <Settings size={18} strokeWidth={1.75} />
          </button>
          <button
            onClick={onLock}
            title="Lock"
            aria-label="Lock"
            className="p-2.5 rounded-full text-muted hover:text-ink hover:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
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
              <h1 className="text-[1.75rem] leading-tight font-semibold tracking-tight mb-3">
                No apps yet
              </h1>
              <p className="text-[15px] text-muted leading-relaxed mb-6">
                Scan an app's login code to sign in. It's added here automatically — one private
                identity per app.
              </p>
              <button
                onClick={() => setShowScanner(true)}
                className="inline-flex items-center gap-2 text-accent hover:text-ink font-medium text-sm transition-colors w-fit"
              >
                <ScanLine size={16} /> Scan a code
              </button>
            </div>
          ) : (
            <>
              <SectionLabel count={apps.length} className="pt-1 pb-1">
                Apps
              </SectionLabel>
              <div className="divide-y divide-line animate-rise">
                {apps.map((app) => (
                  <AppRow key={app.id} app={app} onOpen={() => setSelectedApp(app)} />
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Slim bottom action — hairline-topped, not a slab. Two ways in: scan the QR or type the
          code it shows (the typed path resolves against an app you've already added). */}
      {!loading && apps.length > 0 && (
        <div className="shrink-0 border-t border-line">
          <div className="max-w-[34rem] w-full mx-auto px-6 py-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] flex items-center">
            <button
              onClick={() => setShowScanner(true)}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 text-accent hover:text-ink font-medium text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded-lg"
            >
              <ScanLine size={17} /> Scan a code
            </button>
            <span className="w-px h-5 bg-line" aria-hidden="true" />
            <button
              onClick={() => setShowCodePicker(true)}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 text-accent hover:text-ink font-medium text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded-lg"
            >
              <KeyRound size={17} /> Enter a code
            </button>
          </div>
        </div>
      )}

      {/* Modals */}
      {showScanner && (
        <Suspense fallback={<div className="fixed inset-0 z-[200] bg-black" />}>
          <QRScannerOverlay onScan={handleQRScan} onClose={() => setShowScanner(false)} />
        </Suspense>
      )}

      {pendingSession && (
        <ApprovalModal
          session={pendingSession}
          profile={profile}
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
          profile={profile}
          onClose={() => setSelectedApp(null)}
          onEnterCode={() => {
            const a = selectedApp;
            setSelectedApp(null);
            setCodeApp(a);
          }}
          onDelete={() => {
            const a = selectedApp;
            setSelectedApp(null);
            setPendingDelete(a);
          }}
        />
      )}

      {showSecurity && (
        <SecurityPanel
          userId={user.uid}
          cryptoKey={cryptoKey}
          onLock={onLock}
          onClose={() => {
            setShowSecurity(false);
            refreshAgents();
          }}
        />
      )}

      {showAgents && (
        <AgentsSheet
          userId={user.uid}
          masterKey={cryptoKey}
          onClose={() => {
            setShowAgents(false);
            refreshAgents();
          }}
        />
      )}

      {pendingAuthorize && (
        <AuthorizeAgentSheet
          userId={user.uid}
          masterKey={cryptoKey}
          initialRequest={pendingAuthorize}
          onClose={() => {
            setPendingAuthorize(null);
            refreshAgents();
          }}
        />
      )}

      {pendingPresentation && (
        <PresentCredentialSheet
          request={pendingPresentation.request}
          query={pendingPresentation.query}
          matches={pendingPresentation.matches}
          verified={pendingPresentation.verified}
          masterKey={cryptoKey}
          onClose={() => setPendingPresentation(null)}
        />
      )}

      {showCodePicker && (
        <CodePickerSheet
          apps={apps}
          onPick={(app) => {
            setShowCodePicker(false);
            setCodeApp(app);
          }}
          onClose={() => setShowCodePicker(false)}
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
          <h2 id="remove-title" className="text-lg font-semibold tracking-tight mb-1">
            Remove {pendingDelete.name}?
          </h2>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            It's removed from your list on all your devices. You can re-add it anytime by scanning
            its login code — your identity for it stays the same.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setPendingDelete(null)}>
              Cancel
            </Btn>
            <Btn variant="danger" onClick={confirmDelete}>
              Remove
            </Btn>
          </div>
        </Sheet>
      )}

      {returnInfo && (
        <Sheet onClose={() => setReturnInfo(null)} labelledBy="signed-in-title">
          <div className="flex items-center gap-2.5 mb-1">
            <Shield size={18} className="text-success" />
            <h2 id="signed-in-title" className="text-lg font-semibold tracking-tight">
              Signed in
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            You approved sign-in to{' '}
            <span className="font-mono text-ink">{returnInfo.audience}</span>.
          </p>
          {returnInfo.returnUrl && (
            <a
              href={returnInfo.returnUrl}
              className="inline-flex items-center justify-center gap-2 w-full px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full transition-colors"
            >
              Return to {returnInfo.audience}
            </a>
          )}
          <button
            onClick={() => setReturnInfo(null)}
            className="mt-2 w-full text-center text-sm font-medium text-muted hover:text-ink py-2 transition-colors"
          >
            {returnInfo.returnUrl ? 'Stay in kunji' : 'Done'}
          </button>
        </Sheet>
      )}

    </div>
  );
};

export default Dashboard;
