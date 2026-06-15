import { useState, useEffect, useRef, useCallback } from 'react';
import { Btn, Spinner, SectionLabel } from './ui.jsx';
import { startVerify, uploadDoc, checkStatus, getOffer } from './api.js';

const WALLET = 'https://app.kunji.cc';
const SID_KEY = 'kunji_verify_sid';

// Resize + re-encode to JPEG client-side: shrinks the upload and strips EXIF/GPS before it leaves the device.
const fileToDataUrl = (file, max = 1600, quality = 0.85) =>
  new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      const scale = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * scale);
      c.height = Math.round(img.height * scale);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      resolve(c.toDataURL('image/jpeg', quality));
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('bad_image'));
    };
    img.src = url;
  });

const Header = () => (
  <header className="flex items-center gap-2 px-6 pt-6">
    <img src="https://kunji.cc/icon.svg" alt="" className="w-6 h-6 rounded-md" />
    <span className="text-[14px] text-muted">
      kunji <span className="text-faint">· age issuer</span>
    </span>
  </header>
);

export default function App() {
  const [step, setStep] = useState('intro'); // intro | upload | review | done | rejected
  const [sid, setSid] = useState(() => sessionStorage.getItem(SID_KEY) || '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [preview, setPreview] = useState('');
  const [offerLink, setOfferLink] = useState('');
  const pollRef = useRef(null);
  const fileRef = useRef(null);

  const fetchOffer = useCallback(async (s) => {
    try {
      const { offerUri } = await getOffer(s);
      sessionStorage.removeItem(SID_KEY);
      setOfferLink(`${WALLET}/?offer=${encodeURIComponent(offerUri)}`);
      setStep('done');
    } catch {
      setErr('Verified, but preparing the credential failed. Please try again.');
      setStep('rejected');
    }
  }, []);

  // Resume a pending verification on reload (a stashed sid); runs once on mount.
  useEffect(() => {
    if (sid) setStep('review');
  }, []);

  // Poll while under review; route on the resolved status.
  useEffect(() => {
    if (step !== 'review' || !sid) return undefined;
    const tick = async () => {
      try {
        const { status } = await checkStatus(sid);
        if (status === 'verified') {
          clearInterval(pollRef.current);
          fetchOffer(sid);
        } else if (status === 'rejected') {
          clearInterval(pollRef.current);
          sessionStorage.removeItem(SID_KEY);
          setStep('rejected');
        } else if (status === 'collecting') {
          clearInterval(pollRef.current);
          setStep('upload'); // started but never uploaded — let them finish
        }
      } catch {
        clearInterval(pollRef.current);
        sessionStorage.removeItem(SID_KEY);
        setSid('');
        setStep('intro');
        setErr('That verification expired. Please start again.');
      }
    };
    tick();
    pollRef.current = setInterval(tick, 3000);
    return () => clearInterval(pollRef.current);
  }, [step, sid, fetchOffer]);

  const begin = async () => {
    setErr('');
    setBusy(true);
    try {
      const { sid: s } = await startVerify();
      sessionStorage.setItem(SID_KEY, s);
      setSid(s);
      setStep('upload');
    } catch {
      setErr('Could not start. Please try again.');
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
      setErr('Could not read that image — try another.');
    }
  };

  const submit = async () => {
    if (!preview) return;
    setErr('');
    setBusy(true);
    try {
      await uploadDoc(sid, preview, 'image/jpeg');
      setStep('review');
    } catch (e) {
      setErr(e.message === 'bad_image' ? 'That image was rejected — use a clear JPG/PNG under 8 MB.' : 'Upload failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  const restart = () => {
    sessionStorage.removeItem(SID_KEY);
    setSid('');
    setPreview('');
    setOfferLink('');
    setErr('');
    setStep('intro');
  };

  return (
    <div className="min-h-[100dvh] flex flex-col">
      <Header />
      <main className="flex-1 flex flex-col justify-center max-w-[28rem] w-full mx-auto px-6 py-10">
        {err && <p className="text-[13px] text-danger mb-4">{err}</p>}
        <div key={step} className="animate-rise">
          {step === 'intro' && (
            <>
              <SectionLabel>Age credential</SectionLabel>
              <h1 className="text-[1.9rem] leading-[1.1] font-semibold tracking-tight mt-2">Prove you&rsquo;re old enough — privately.</h1>
              <p className="text-[15px] text-muted mt-3">
                kunji checks your government ID once, then issues an age credential to your wallet. You present{' '}
                <span className="font-mono text-ink">age_over_18</span> anywhere — without revealing your date of birth.
              </p>
              <div className="mt-7">
                <Btn onClick={begin} disabled={busy}>
                  {busy ? (
                    <>
                      <Spinner /> Starting…
                    </>
                  ) : (
                    'Verify your age'
                  )}
                </Btn>
              </div>
              <p className="text-[12px] text-faint mt-4">Verified by document review. More methods (PASS, Aadhaar, …) coming.</p>
            </>
          )}

          {step === 'upload' && (
            <>
              <SectionLabel>Step 1 · Your ID</SectionLabel>
              <h1 className="text-[1.6rem] leading-tight font-semibold tracking-tight mt-2">Upload a government ID</h1>
              <p className="text-[15px] text-muted mt-2">
                A passport or driver&rsquo;s license, all corners visible. An operator reviews it, then it&rsquo;s deleted — we keep
                only your verified age thresholds.
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
          )}

          {step === 'review' && (
            <>
              <SectionLabel>Step 2 · Under review</SectionLabel>
              <div className="flex items-center gap-3 mt-3">
                <Spinner size={20} />
                <h1 className="text-[1.5rem] font-semibold tracking-tight">We&rsquo;re reviewing your ID</h1>
              </div>
              <p className="text-[15px] text-muted mt-3">
                An operator is confirming your age. This page updates on its own — keep it open. Your document is deleted the
                moment the review is done.
              </p>
            </>
          )}

          {step === 'done' && (
            <>
              <SectionLabel>Verified</SectionLabel>
              <h1 className="text-[1.7rem] leading-tight font-semibold tracking-tight mt-2">Age verified ✓</h1>
              <p className="text-[15px] text-muted mt-2">
                Open kunji to add your age credential, then present it anywhere that trusts kunji — boolean thresholds only, no
                date of birth.
              </p>
              <a
                href={offerLink}
                className="inline-flex items-center justify-center gap-2 px-5 py-3 text-sm font-semibold rounded-full bg-accent-fill hover:bg-accent text-on-accent transition-colors mt-7"
              >
                Open in kunji
              </a>
            </>
          )}

          {step === 'rejected' && (
            <>
              <SectionLabel>Not verified</SectionLabel>
              <h1 className="text-[1.6rem] leading-tight font-semibold tracking-tight mt-2">We couldn&rsquo;t verify your ID</h1>
              <p className="text-[15px] text-muted mt-2">The review didn&rsquo;t pass, or the session expired. You can try again with a clearer photo.</p>
              <div className="mt-7">
                <Btn onClick={restart}>Try again</Btn>
              </div>
            </>
          )}
        </div>
      </main>
      <footer className="max-w-[28rem] w-full mx-auto px-6 pb-8 text-[12px] text-faint leading-relaxed">
        kunji verifies your age once and issues a credential with boolean thresholds only — never your date of birth. Your ID is
        reviewed by an operator and deleted right after.
      </footer>
    </div>
  );
}
