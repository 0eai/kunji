import React, { useEffect, useState } from 'react';
import { useVault } from './contexts/VaultContext';
import {
  auth,
  ensureAnonymousAuth,
  onAuthStateChanged,
  isEmailSignInLink,
  completeEmailLink,
} from './lib/firebase';
import { logActivity } from './services/activityLog';
import LockScreen from './components/LockScreen';
import Dashboard from './components/Dashboard';

// Default auto-lock timeout in minutes (20 hours) when the user hasn't set one.
const AUTO_LOCK_DEFAULT_MIN = 1200;

// Decode one base64url(JSON) query param into its JSON string (validated), or null.
function decodeB64urlParam(name) {
  try {
    const raw = new URLSearchParams(window.location.search).get(name);
    if (!raw) return null;
    const json = atob(raw.replace(/-/g, '+').replace(/_/g, '/'));
    JSON.parse(json); // validate it's JSON
    return json;
  } catch {
    return null;
  }
}

// Same-device deep links an RP/agent/verifier/issuer can open:
//   app.kunji.cc/?approve=<base64url(JSON login QR)>        → the login approval modal
//   app.kunji.cc/?authorize=<base64url(JSON agent request)> → the agent re-consent sheet (step-up);
//        a portfolio-v1 request (kunjiCap:'portfolio-v1') routes to the multi-app AuthorizePortfolioSheet
//   app.kunji.cc/?vp=<url-encoded openid4vp:// request>     → the OpenID4VP present sheet
//   app.kunji.cc/?offer=<url-encoded openid-credential-offer:// uri> → the OpenID4VCI receive-offer sheet
// Decode once at startup; clear the query so a refresh doesn't replay it.
function readIncomingLinks() {
  const approve = decodeB64urlParam('approve');
  const authorize = decodeB64urlParam('authorize');
  // The OpenID4VP request / OpenID4VCI offer are URIs (not JSON); URLSearchParams decodes the value for us.
  const vpRaw = new URLSearchParams(window.location.search).get('vp');
  const vp = vpRaw && vpRaw.startsWith('openid4vp://') ? vpRaw : null;
  const offerRaw = new URLSearchParams(window.location.search).get('offer');
  const offer = offerRaw && offerRaw.startsWith('openid-credential-offer://') ? offerRaw : null;
  // A Web Push notification opens app.kunji.cc/?push=<requestId> (the agent-request relay code).
  const pushRaw = new URLSearchParams(window.location.search).get('push');
  const push = pushRaw && /^\d{6}$/.test(pushRaw) ? pushRaw : null;
  // An OpenID4VCI authorization_code issuer redirects back to app.kunji.cc/?code=&state= (leg 2 of the
  // sign-in on-ramp). Both must be present + token-safe; completed by Dashboard after unlock.
  const sp = new URLSearchParams(window.location.search);
  const codeRaw = sp.get('code');
  const stateRaw = sp.get('state');
  const tokenSafe = (s) => typeof s === 'string' && /^[A-Za-z0-9._~-]{1,512}$/.test(s);
  const authCode = tokenSafe(codeRaw) && tokenSafe(stateRaw) ? { code: codeRaw, state: stateRaw } : null;
  if (approve || authorize || vp || offer || push || authCode)
    history.replaceState(null, '', window.location.pathname);
  return { approve, authorize, vp, offer, push, authCode };
}

export default function App() {
  const { user, cryptoKey, loading, lockReason, setAuthUser, unlockVault, lockVault } = useVault();
  const [incoming] = useState(readIncomingLinks);
  const [authError, setAuthError] = useState(false);
  // Set when an inbound email sign-in link arrives but we can't determine the email
  // (it was requested on another device) — prompt for it. Holds the link href.
  const [emailLinkHref, setEmailLinkHref] = useState(null);
  const [emailPrompt, setEmailPrompt] = useState('');
  const [emailPromptBusy, setEmailPromptBusy] = useState(false);

  // Sign in anonymously on first load, persist session.
  // If the URL is a Firebase email sign-in link, complete it first: link the credential to
  // the current (anonymous → permanent) account when this device requested it (uid preserved),
  // or sign in as the linked uid on a fresh device. Either way the existing flow then runs.
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (firebaseUser) => {
      const href = window.location.href;
      if (isEmailSignInLink(href)) {
        try {
          await completeEmailLink(href, firebaseUser);
          history.replaceState(null, '', window.location.pathname); // strip oobCode/apiKey/mode
        } catch (e) {
          if (e.message === 'EMAIL_REQUIRED') {
            setEmailLinkHref(href);
            setAuthUser(null); // clear "loading" so the email prompt can render
            return;
          }
          console.error('Email link sign-in failed:', e);
        }
      }
      if (firebaseUser) {
        setAuthUser(firebaseUser);
        setAuthError(false);
      } else {
        try {
          const anonUser = await ensureAnonymousAuth();
          setAuthUser(anonUser);
          setAuthError(false);
        } catch (e) {
          console.error('Anonymous auth failed:', e);
          setAuthError(true);
        }
      }
    });
    return unsub;
  }, [setAuthUser]);

  // Cross-device email-link completion: the user opened the link on a device that didn't
  // request it, so we ask for the email, then sign in as the linked uid.
  const submitEmailPrompt = async () => {
    if (!emailPrompt.trim()) return;
    setEmailPromptBusy(true);
    try {
      await completeEmailLink(emailLinkHref, auth.currentUser, emailPrompt.trim());
      history.replaceState(null, '', window.location.pathname);
      setEmailLinkHref(null); // onAuthStateChanged fires with the signed-in user
    } catch (e) {
      console.error('Email link sign-in failed:', e);
      setEmailPromptBusy(false);
    }
  };

  // If no session is established within a few seconds (blocked storage, offline,
  // private mode), surface an actionable error instead of a perpetual "Connecting…".
  useEffect(() => {
    if (user) return;
    const t = setTimeout(() => setAuthError(true), 8000);
    return () => clearTimeout(t);
  }, [user]);

  // Auto-lock on inactivity (default 20 hours, stored in localStorage as kunji_autolock minutes)
  useEffect(() => {
    if (!cryptoKey || !user) return;
    const getTimeout = () => {
      const saved = localStorage.getItem('kunji_autolock');
      const minutes = saved ? parseInt(saved) : AUTO_LOCK_DEFAULT_MIN;
      return minutes === 0 ? null : minutes * 60000;
    };
    let timer = null;
    const resetTimer = () => {
      if (timer) clearTimeout(timer);
      const timeout = getTimeout();
      if (timeout) {
        timer = setTimeout(() => {
          logActivity(user.uid, 'Vault Auto-Locked', 'info', 'Lock', cryptoKey);
          lockVault('Session expired due to inactivity.');
        }, timeout);
      }
    };
    resetTimer();
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((e) => window.addEventListener(e, resetTimer, { passive: true }));
    return () => {
      if (timer) clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, resetTimer));
    };
  }, [cryptoKey, user, lockVault]);

  // Lock when tab is hidden (opt-in, stored in localStorage as kunji_lock_on_hidden)
  useEffect(() => {
    if (!cryptoKey || !user) return;
    const handle = () => {
      if (
        localStorage.getItem('kunji_lock_on_hidden') === 'true' &&
        document.visibilityState === 'hidden'
      ) {
        logActivity(user.uid, 'Vault Auto-Locked (Hidden)', 'info', 'Lock', cryptoKey);
        lockVault('Locked because the tab was hidden.');
      }
    };
    document.addEventListener('visibilitychange', handle);
    return () => document.removeEventListener('visibilitychange', handle);
  }, [cryptoKey, user, lockVault]);

  // Inbound email sign-in link opened on a device that didn't request it — confirm the email.
  if (emailLinkHref) {
    return (
      <div className="h-[100dvh] w-full flex flex-col items-center justify-center gap-4 bg-paper text-ink px-6 text-center">
        <p className="text-[15px] font-medium">Confirm your email</p>
        <p className="text-[14px] text-muted max-w-xs leading-relaxed">
          Enter the email this sign-in link was sent to, to finish signing in.
        </p>
        <input
          type="email"
          value={emailPrompt}
          onChange={(e) => setEmailPrompt(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submitEmailPrompt()}
          placeholder="you@example.com"
          autoFocus
          className="w-full max-w-xs bg-transparent border-0 border-b border-line rounded-none px-0 py-3 text-ink placeholder:text-faint outline-none focus:border-accent transition-colors text-center"
        />
        <button
          onClick={submitEmailPrompt}
          disabled={emailPromptBusy || !emailPrompt.trim()}
          className="inline-flex items-center justify-center px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full transition-colors disabled:opacity-40"
        >
          {emailPromptBusy ? 'Signing in…' : 'Continue'}
        </button>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="h-[100dvh] w-full flex items-center justify-center bg-paper">
        <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!user) {
    if (authError) {
      return (
        <div className="h-[100dvh] w-full flex flex-col items-center justify-center gap-4 bg-paper text-ink px-6 text-center">
          <p className="text-[15px] font-medium">Couldn't connect</p>
          <p className="text-[14px] text-muted max-w-xs leading-relaxed">
            kunji needs storage and network access. Check your connection, and if you're in private
            mode or have strict tracking protection on, allow this site.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center justify-center px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full transition-colors"
          >
            Try again
          </button>
        </div>
      );
    }
    return (
      <div className="h-[100dvh] w-full flex items-center justify-center bg-paper text-faint text-sm">
        Connecting…
      </div>
    );
  }

  if (!cryptoKey) {
    return (
      <LockScreen
        user={user}
        onUnlock={(key) => {
          unlockVault(key);
          logActivity(user.uid, 'Vault Unlocked', 'success', 'Unlock', key);
        }}
        initialMessage={lockReason || ''}
      />
    );
  }

  return (
    <Dashboard
      user={user}
      cryptoKey={cryptoKey}
      incomingApproval={incoming.approve}
      incomingAuthorize={incoming.authorize}
      incomingPresentation={incoming.vp}
      incomingOffer={incoming.offer}
      incomingPush={incoming.push}
      incomingAuthCode={incoming.authCode}
      onLock={() => {
        logActivity(user.uid, 'Vault Locked', 'info', 'Lock', cryptoKey);
        lockVault();
      }}
    />
  );
}
