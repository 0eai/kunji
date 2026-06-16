import { useState, useEffect, useRef, useCallback } from 'react';
import QRCode from 'qrcode';
import { Btn, Spinner, SectionLabel } from './ui.jsx';
import * as api from './api.js';

const WALLET = 'https://app.kunji.cc';

// Resize + re-encode to JPEG via a data: URL (FileReader) so the issuer CSP stays `img-src 'self' data:`
// (no blob:). Strips EXIF/GPS before the image leaves the device.
const fileToDataUrl = (file, max = 1600, quality = 0.85) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('bad_image'));
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, max / Math.max(img.width, img.height));
        const c = document.createElement('canvas');
        c.width = Math.round(img.width * scale);
        c.height = Math.round(img.height * scale);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        resolve(c.toDataURL('image/jpeg', quality));
      };
      img.onerror = () => reject(new Error('bad_image'));
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });

const availableMethods = (t) => (t?.methods || []).filter((m) => m.status === 'available');
// Pick the verification to resume: verified > pending_review > collecting.
const pickActive = (items) => {
  const rank = { verified: 3, pending_review: 2, collecting: 1 };
  return (items || []).slice().sort((a, b) => (rank[b.status] || 0) - (rank[a.status] || 0))[0] || null;
};

const BackLink = ({ onClick }) => (
  <button onClick={onClick} className="block w-fit text-[13px] text-muted hover:text-ink transition-colors mb-4">
    ← Back
  </button>
);

const Header = ({ onSignOut }) => (
  <header className="flex items-center gap-2 px-6 pt-6">
    <img src="https://kunji.cc/icon.svg" alt="" className="w-6 h-6 rounded-md" />
    <span className="text-[14px] text-muted">
      kunji <span className="text-faint">· issuer</span>
    </span>
    {onSignOut && (
      <button onClick={onSignOut} className="ml-auto text-[13px] text-muted hover:text-ink transition-colors">
        Sign out
      </button>
    )}
  </header>
);

export default function App() {
  const [phase, setPhase] = useState('loading'); // loading | login | flow
  const [catalog, setCatalog] = useState(null);
  const [err, setErr] = useState('');
  // flow
  const [step, setStep] = useState('chooseType'); // chooseType | chooseProvider | upload | review | done | rejected
  const [selType, setSelType] = useState(null); // the chosen type object (catalog)
  const [sid, setSid] = useState('');
  const [preview, setPreview] = useState('');
  const [offerLink, setOfferLink] = useState('');
  const [busy, setBusy] = useState(false);
  // login
  const [login, setLogin] = useState(null); // { sessionId, code, qr }
  const loginPoll = useRef(null);
  const poll = useRef(null);
  const fileRef = useRef(null);

  const fetchOffer = useCallback(async (s) => {
    try {
      const { offerUri } = await api.getOffer(s);
      setOfferLink(`${WALLET}/?offer=${encodeURIComponent(offerUri)}`);
      setStep('done');
    } catch (e) {
      if (e.status === 401) {
        api.setToken('');
        setPhase('login');
      } else {
        setErr('Verified, but preparing the credential failed. Please try again.');
        setStep('rejected');
      }
    }
  }, []);

  // Boot: load the catalog, then resume (if a session token exists) or show login.
  useEffect(() => {
    (async () => {
      try {
        setCatalog(await api.fetchCatalog());
      } catch {
        setErr('Could not reach the issuer.');
      }
      if (api.getToken()) {
        try {
          const active = pickActive((await api.myVerifications()).items);
          if (active) {
            setSid(active.sid);
            setPhase('flow');
            if (active.status === 'collecting') setStep('upload');
            else setStep('review'); // pending_review | verified → the review poll resolves it
            return;
          }
          setPhase('flow');
          setStep('chooseType');
          return;
        } catch (e) {
          if (e.status === 401) api.setToken(''); // expired → re-login
        }
      }
      setPhase('login');
    })();
  }, []);

  // Auto-start a login session when the login screen appears (renders the QR + code).
  useEffect(() => {
    if (phase !== 'login' || login) return undefined;
    (async () => {
      setErr('');
      try {
        const s = await api.loginSession();
        const payload = JSON.stringify({
          kunjiAuth: 'v2',
          sessionId: s.sessionId,
          challenge: s.challenge,
          audience: s.audience,
          appName: 'kunji',
          callbackUrl: s.callbackUrl,
          expiresAt: s.expiresAt,
        });
        const qr = await QRCode.toDataURL(payload, { margin: 1, width: 232 });
        setLogin({ sessionId: s.sessionId, code: s.code, qr });
      } catch {
        setErr('Could not start sign-in. Reload to retry.');
      }
    })();
    return undefined;
  }, [phase, login]);

  // Poll the login session until approved → store the token → enter the flow.
  useEffect(() => {
    if (phase !== 'login' || !login?.sessionId) return undefined;
    const tick = async () => {
      try {
        const { status, sessionToken } = await api.loginStatus(login.sessionId);
        if (status === 'approved' && sessionToken) {
          clearInterval(loginPoll.current);
          api.setToken(sessionToken);
          setLogin(null);
          setPhase('flow');
          setStep('chooseType');
        }
      } catch {
        /* transient / not-yet — keep polling */
      }
    };
    loginPoll.current = setInterval(tick, 2500);
    return () => clearInterval(loginPoll.current);
  }, [phase, login]);

  // Auto-collapse the type stage when there's exactly one type.
  useEffect(() => {
    if (phase === 'flow' && step === 'chooseType' && catalog?.types?.length === 1) chooseType(catalog.types[0]);
  }, [phase, step, catalog]);

  // Poll the verification status while under review; resolve to offer / rejected / restart.
  useEffect(() => {
    if (step !== 'review' || !sid) return undefined;
    const tick = async () => {
      try {
        const { status } = await api.checkStatus(sid);
        if (status === 'verified') {
          clearInterval(poll.current);
          fetchOffer(sid);
        } else if (status === 'rejected') {
          clearInterval(poll.current);
          setStep('rejected');
        } else if (status === 'collecting') {
          clearInterval(poll.current);
          setStep('upload');
        }
      } catch (e) {
        if (e.status === 404) {
          // The session is genuinely gone/expired — only then reset (a transient error keeps polling).
          clearInterval(poll.current);
          setSid('');
          setErr('That verification expired. Please start again.');
          setStep('chooseType');
        }
      }
    };
    tick();
    poll.current = setInterval(tick, 3000);
    return () => clearInterval(poll.current);
  }, [step, sid, fetchOffer]);

  const chooseType = (t) => {
    setErr('');
    setSelType(t);
    const avail = availableMethods(t);
    if (avail.length === 1) beginVerify(t.id, avail[0].id);
    else setStep('chooseProvider');
  };

  const beginVerify = async (type, method) => {
    setBusy(true);
    setErr('');
    try {
      const { sid: s, kind } = await api.startVerify(type, method);
      setSid(s);
      setPreview('');
      setStep(kind === 'manual' ? 'upload' : 'review');
    } catch (e) {
      if (e.status === 401) {
        api.setToken('');
        setPhase('login');
      } else setErr('Could not start. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  const onFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setErr('');
    try {
      setPreview(await fileToDataUrl(file));
    } catch {
      setErr('Could not read that image — use a clear JPG or PNG.');
    }
  };

  const submit = async () => {
    if (!preview) return;
    setBusy(true);
    setErr('');
    try {
      await api.uploadDoc(sid, preview, 'image/jpeg');
      setStep('review');
    } catch (e) {
      if (e.status === 401) {
        api.setToken('');
        setPhase('login');
      } else setErr(e.message === 'bad_image' ? 'That image was rejected — use a clear JPG/PNG under 8 MB.' : 'Upload failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  const restart = () => {
    setSid('');
    setPreview('');
    setOfferLink('');
    setErr('');
    setSelType(null);
    setStep('chooseType');
  };

  const signOut = () => {
    api.setToken('');
    setLogin(null);
    restart();
    setPhase('login');
  };

  const body = () => {
    if (phase === 'loading') return <p className="text-muted text-sm">Loading…</p>;
    if (phase === 'login') return <LoginView login={login} />;
    return <FlowView />;
  };

  // ── login view ──
  function LoginView({ login }) {
    return (
      <>
        <SectionLabel>Sign in</SectionLabel>
        <h1 className="text-[1.7rem] leading-[1.1] font-semibold tracking-tight mt-2">Sign in with kunji</h1>
        <p className="text-[15px] text-muted mt-2">
          Scan with the kunji app to start. Signing in keeps your verification recoverable — refresh, close the
          tab, or switch devices and pick up right where you left off.
        </p>
        {login ? (
          <div className="mt-6 flex flex-col items-center">
            <img src={login.qr} alt="Sign-in QR" className="w-[232px] h-[232px] rounded-2xl border border-line bg-white p-2" />
            <p className="text-[13px] text-muted mt-4">or enter this code in the kunji app:</p>
            <p className="text-2xl font-mono tabular tracking-[0.3em] text-ink mt-1">{login.code}</p>
            <p className="text-[12px] text-faint mt-3 flex items-center gap-1.5">
              <Spinner size={13} /> Waiting for approval…
            </p>
          </div>
        ) : (
          <p className="text-[13px] text-faint mt-6 flex items-center gap-2">
            <Spinner size={14} /> Preparing sign-in…
          </p>
        )}
      </>
    );
  }

  // ── flow view ──
  function FlowView() {
    if (step === 'chooseType') {
      return (
        <>
          <SectionLabel>Get a credential</SectionLabel>
          <h1 className="text-[1.7rem] leading-[1.1] font-semibold tracking-tight mt-2">What do you want to prove?</h1>
          <div className="mt-6 divide-y divide-line border-y border-line">
            {(catalog?.types || []).map((t) => (
              <button key={t.id} onClick={() => chooseType(t)} className="w-full text-left py-4 hover:bg-line/30 transition-colors -mx-6 px-6">
                <p className="text-[15px] text-ink">{t.label}</p>
                {t.description && <p className="text-[12px] text-faint mt-0.5">{t.description}</p>}
              </button>
            ))}
          </div>
        </>
      );
    }
    if (step === 'chooseProvider') {
      return (
        <>
          <BackLink onClick={() => { setSelType(null); setStep('chooseType'); }} />
          <SectionLabel>Choose a verifier</SectionLabel>
          <h1 className="text-[1.6rem] leading-tight font-semibold tracking-tight mt-2">How do you want to prove {selType?.label?.toLowerCase()}?</h1>
          <div className="mt-6 divide-y divide-line border-y border-line">
            {(selType?.methods || []).map((m) => {
              const soon = m.status !== 'available';
              return (
                <button
                  key={m.id}
                  disabled={soon || busy}
                  onClick={() => beginVerify(selType.id, m.id)}
                  className={`w-full text-left py-4 -mx-6 px-6 transition-colors ${soon ? 'opacity-50 cursor-default' : 'hover:bg-line/30'}`}
                >
                  <p className="text-[15px] text-ink flex items-center gap-2">
                    {m.label}
                    {soon && <span className="text-[10px] uppercase tracking-wide text-faint border border-line rounded-full px-1.5 py-0.5">soon</span>}
                    {m.region && m.region !== 'global' && <span className="text-[11px] text-faint">· {m.region}</span>}
                  </p>
                  {m.description && <p className="text-[12px] text-faint mt-0.5">{m.description}</p>}
                </button>
              );
            })}
          </div>
        </>
      );
    }
    if (step === 'upload') {
      return (
        <>
          {(catalog?.types?.length || 0) > 1 && <BackLink onClick={restart} />}
          <SectionLabel>Step 1 · Your ID</SectionLabel>
          <h1 className="text-[1.6rem] leading-tight font-semibold tracking-tight mt-2">Upload a government ID</h1>
          <p className="text-[15px] text-muted mt-2">
            A passport or driver&rsquo;s license, all corners visible. A kunji operator reviews it, then it&rsquo;s deleted —
            we keep only the verified result{selType?.label ? ` for ${selType.label.toLowerCase()}` : ''}, never the document itself.
          </p>
          <input ref={fileRef} type="file" accept="image/*" capture="environment" onChange={onFile} className="hidden" />
          {preview ? (
            <button type="button" onClick={() => fileRef.current?.click()} className="mt-5 block w-full rounded-2xl border border-line overflow-hidden">
              <img src={preview} alt="ID preview" className="w-full max-h-72 object-contain bg-surface" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className="mt-5 w-full rounded-2xl border border-dashed border-line-strong py-12 text-sm text-muted hover:text-ink hover:border-accent transition-colors"
            >
              Tap to take a photo or choose a file
            </button>
          )}
          <div className="flex items-center gap-2 mt-6">
            <Btn onClick={submit} disabled={busy || !preview}>
              {busy ? (
                <>
                  <Spinner /> Uploading…
                </>
              ) : (
                'Submit for review'
              )}
            </Btn>
            {preview && (
              <Btn variant="quiet" onClick={() => fileRef.current?.click()} disabled={busy}>
                Retake
              </Btn>
            )}
          </div>
        </>
      );
    }
    if (step === 'review') {
      return (
        <>
          <SectionLabel>Step 2 · Under review</SectionLabel>
          <div className="flex items-center gap-3 mt-3">
            <Spinner size={20} />
            <h1 className="text-[1.5rem] font-semibold tracking-tight">We&rsquo;re reviewing your ID</h1>
          </div>
          <p className="text-[15px] text-muted mt-3">
            A kunji operator is confirming your details. This page updates on its own — and because you&rsquo;re signed in,
            you can safely close it and come back (any device). Your document is deleted the moment the review is done.
          </p>
        </>
      );
    }
    if (step === 'done') {
      return (
        <>
          <SectionLabel>Verified</SectionLabel>
          <h1 className="text-[1.7rem] leading-tight font-semibold tracking-tight mt-2">Verified ✓</h1>
          <p className="text-[15px] text-muted mt-2">
            Open kunji to add your {selType?.label?.toLowerCase() || 'verified'} credential, then present it anywhere
            that trusts kunji — only the minimal verified claim is shared, never the document you uploaded.
          </p>
          <a
            href={offerLink}
            className="inline-flex items-center justify-center gap-2 px-5 py-3 text-sm font-semibold rounded-full bg-accent-fill hover:bg-accent text-on-accent transition-colors mt-7"
          >
            Open in kunji
          </a>
        </>
      );
    }
    // rejected
    return (
      <>
        <SectionLabel>Not verified</SectionLabel>
        <h1 className="text-[1.6rem] leading-tight font-semibold tracking-tight mt-2">We couldn&rsquo;t verify your ID</h1>
        <p className="text-[15px] text-muted mt-2">The review didn&rsquo;t pass, or the session expired. You can try again with a clearer photo.</p>
        <div className="mt-7">
          <Btn onClick={restart}>Try again</Btn>
        </div>
      </>
    );
  }

  return (
    <div className="min-h-[100dvh] flex flex-col">
      <Header onSignOut={phase === 'flow' ? signOut : null} />
      <main className="flex-1 flex flex-col justify-center max-w-[28rem] w-full mx-auto px-6 py-10">
        {err && <p className="text-[13px] text-danger mb-4">{err}</p>}
        <div key={`${phase}:${step}`} className="animate-rise">
          {body()}
        </div>
      </main>
      <footer className="max-w-[28rem] w-full mx-auto px-6 pb-8 text-[12px] text-faint leading-relaxed">
        kunji verifies you once and issues a credential with minimal claims only — never the document you uploaded
        or its raw details. Your ID is reviewed by an operator and deleted right after.
      </footer>
    </div>
  );
}
