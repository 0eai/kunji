import { useState, useEffect, useCallback } from 'react';
import { onAuthStateChanged, signInWithPopup, signOut } from 'firebase/auth';
import { auth, googleProvider } from './firebase.js';
import { fetchLedger, fetchStats, fetchReviews, reviewDoc, reviewDecision, revoke, unrevoke } from './api.js';
import { Btn, Spinner, SectionLabel, Field } from './ui.jsx';

const ISSUER_ORIGIN = import.meta.env.VITE_ISSUER_ORIGIN || 'https://issuer-kunji-cc.web.app';
// Compact ledger display of a credential's coarse claims, across types: age_over_N → ≥N, other true
// booleans → the key, key:value → "key:value". (Booleans that are false are omitted.)
const claimSummary = (c) => {
  if (!c || typeof c !== 'object') return '—';
  const parts = Object.entries(c)
    .map(([k, v]) => {
      if (k.startsWith('age_over_')) return v ? k.replace('age_over_', '≥') : null;
      if (v === true) return k;
      if (v === false) return null;
      return `${k}:${v}`;
    })
    .filter(Boolean);
  return parts.join(' ') || 'none';
};

export default function App() {
  const [user, setUser] = useState(undefined); // undefined = resolving, null = signed out
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(
    () =>
      onAuthStateChanged(auth, async (u) => {
        setUser(u);
        setIsAdmin(u ? (await u.getIdTokenResult()).claims.admin === true : false);
      }),
    [],
  );

  let body;
  if (user === undefined) body = <p className="text-muted text-sm mt-16 text-center">Loading…</p>;
  else if (!user) body = <SignIn />;
  else if (!isAdmin) body = <NotAuthorized email={user.email} />;
  else body = <Dashboard />;

  return (
    <div className="min-h-[100dvh] flex flex-col">
      <header className="flex items-center gap-2 max-w-3xl w-full mx-auto px-6 pt-6 pb-5">
        <img src="https://kunji.cc/icon.svg" alt="" className="w-6 h-6 rounded-md" />
        <span className="text-[14px] text-muted">
          kunji <span className="text-faint">· admin</span>
        </span>
        {user && (
          <button onClick={() => signOut(auth)} className="ml-auto text-[13px] text-muted hover:text-ink transition-colors">
            Sign out{user.email ? ` · ${user.email}` : ''}
          </button>
        )}
      </header>
      <main className="flex-1 max-w-3xl w-full mx-auto px-6 py-6 animate-rise">{body}</main>
    </div>
  );
}

function SignIn() {
  const [err, setErr] = useState('');
  return (
    <div className="max-w-sm mx-auto mt-16 text-center">
      <h1 className="text-[1.5rem] font-semibold tracking-tight">Operator sign-in</h1>
      <p className="text-[15px] text-muted mt-2">Sign in with an authorized Google account.</p>
      <div className="mt-6 flex justify-center">
        <Btn
          onClick={async () => {
            setErr('');
            try {
              await signInWithPopup(auth, googleProvider);
            } catch (e) {
              const sr = e?.customData?.serverResponse;
              setErr(`${e?.code || 'error'}${sr ? ' · ' + (typeof sr === 'string' ? sr : JSON.stringify(sr)) : ''}`.slice(0, 400));
            }
          }}
        >
          Sign in with Google
        </Btn>
      </div>
      {err && <p className="text-[13px] text-danger mt-3 break-words">{err}</p>}
    </div>
  );
}

function NotAuthorized({ email }) {
  return (
    <div className="max-w-sm mx-auto mt-16 text-center">
      <h1 className="text-[1.5rem] font-semibold tracking-tight">Not authorized</h1>
      <p className="text-[15px] text-muted mt-2">
        {email} is signed in but isn&rsquo;t an issuer operator. Ask an admin to grant access, then sign out and in again to
        refresh your token.
      </p>
    </div>
  );
}

function Stat({ n, l }) {
  return (
    <div>
      <div className="text-[1.6rem] font-semibold tabular leading-none">{n}</div>
      <div className="text-[12px] text-faint mt-1">{l}</div>
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [items, setItems] = useState([]);
  const [keys, setKeys] = useState(null);
  const [err, setErr] = useState('');
  const [review, setReview] = useState(null); // the pending-review item being reviewed

  const load = useCallback(async () => {
    setErr('');
    try {
      const [s, r, l] = await Promise.all([fetchStats(), fetchReviews(), fetchLedger()]);
      setStats(s);
      setReviews(r.items || []);
      setItems(l.items || []);
    } catch (e) {
      setErr(e.message);
    }
    try {
      const k = await fetch(`${ISSUER_ORIGIN}/.well-known/kunji-issuer.json`);
      if (k.ok) setKeys(await k.json());
    } catch {
      /* keys view best-effort */
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Live refresh: poll every 10s while the dashboard is visible (not in a backgrounded tab, not mid-review).
  useEffect(() => {
    if (review) return undefined;
    const id = setInterval(() => {
      if (!document.hidden) load();
    }, 10000);
    return () => clearInterval(id);
  }, [review, load]);

  if (review)
    return (
      <ReviewPanel
        review={review}
        onDone={() => {
          setReview(null);
          load();
        }}
      />
    );

  const toggle = async (it) => {
    try {
      await (it.revoked ? unrevoke(it.type, it.idx) : revoke(it.type, it.idx));
      setItems((xs) => xs.map((x) => (x.id === it.id ? { ...x, revoked: !it.revoked } : x)));
      fetchStats().then(setStats).catch(() => {});
    } catch (e) {
      setErr(e.message);
    }
  };

  return (
    <div className="space-y-10">
      <div className="flex justify-end -mt-2">
        <button onClick={load} className="text-[13px] text-muted hover:text-ink transition-colors">↻ Refresh</button>
      </div>
      {err && <p className="text-[13px] text-danger">{err}</p>}

      {stats && (
        <section>
          <SectionLabel>Overview</SectionLabel>
          <div className="flex flex-wrap gap-x-9 gap-y-4 mt-3">
            <Stat n={stats.issued} l="Issued" />
            <Stat n={stats.revoked} l="Revoked" />
            <Stat n={stats.verification.pending_review} l="Pending review" />
            <Stat n={stats.verification.verified} l="Verified" />
            <Stat n={stats.verification.rejected} l="Rejected" />
          </div>
        </section>
      )}

      <section>
        <SectionLabel count={reviews.length}>Pending reviews</SectionLabel>
        <div className="mt-2 border-t border-line divide-y divide-line">
          {reviews.map((r) => (
            <div key={r.sid} className="flex items-center gap-3 py-3.5">
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">
                  {r.type} <span className="text-faint">· {r.method}</span>
                </div>
                <div className="text-[12px] text-faint font-mono">{r.submittedAt ? new Date(r.submittedAt).toLocaleString() : ''}</div>
              </div>
              <Btn variant="quiet" onClick={() => setReview(r)}>
                Review
              </Btn>
            </div>
          ))}
          {!reviews.length && <div className="py-4 text-sm text-muted">No submissions waiting.</div>}
        </div>
      </section>

      <section>
        <SectionLabel count={items.length}>Issuance ledger</SectionLabel>
        <div className="mt-2 border-t border-line divide-y divide-line">
          {items.map((it) => (
            <div key={it.id} className={`flex items-center gap-3 py-3 ${it.revoked ? 'opacity-50' : ''}`}>
              <div className="flex-1 min-w-0">
                <div className="text-sm">
                  {it.type} #{it.idx} <span className="font-mono text-[12px] text-muted">{claimSummary(it.claims)}</span>
                </div>
                <div className="text-[12px] text-faint font-mono">
                  {it.kid} · {it.issuedAt ? new Date(it.issuedAt).toISOString().slice(0, 10) : ''}
                </div>
              </div>
              <span className={`text-[12px] ${it.revoked ? 'text-danger' : 'text-success'}`}>{it.revoked ? 'revoked' : 'valid'}</span>
              <Btn variant="quiet" onClick={() => toggle(it)}>
                {it.revoked ? 'Un-revoke' : 'Revoke'}
              </Btn>
            </div>
          ))}
          {!items.length && <div className="py-4 text-sm text-muted">Nothing issued yet.</div>}
        </div>
      </section>

      {keys && (
        <section>
          <SectionLabel>Signing keys</SectionLabel>
          <p className="text-[12px] text-faint mt-1">Read-only. Rotate via the CLI runbook in docs/issuer.md.</p>
          <ul className="mt-2 space-y-1">
            {(keys.keys || []).map((k) => (
              <li key={k.kid} className="font-mono text-[12px] text-muted">
                {k.kid} · {k.kty}/{k.crv}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

// Fallback for a session whose type predates reviewFields (only `age` ever shipped without it).
const DEFAULT_FIELDS = [{ key: 'dob', label: 'Date of birth (from ID)', type: 'date', required: true }];

function ReviewPanel({ review, onDone }) {
  const { sid, type } = review;
  const fields = review.reviewFields?.length ? review.reviewFields : DEFAULT_FIELDS;
  const [img, setImg] = useState('');
  const [data, setData] = useState({}); // the verifiedData the operator fills in
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let url;
    reviewDoc(sid)
      .then((u) => {
        url = u;
        setImg(u);
      })
      .catch(() => setErr('Could not load the document.'));
    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [sid]);

  const setField = (k, v) => setData((d) => ({ ...d, [k]: v }));
  const ready = fields.every((f) => !f.required || String(data[f.key] || '').trim());

  const decide = async (approve) => {
    setErr('');
    setBusy(true);
    try {
      await reviewDecision(sid, approve, approve ? data : undefined);
      onDone();
    } catch (e) {
      setErr(['bad_claims', 'bad_dob'].includes(e.message) ? 'Check the details entered from the ID.' : 'Decision failed — try again.');
      setBusy(false);
    }
  };

  return (
    <div>
      <button onClick={onDone} className="text-[13px] text-muted hover:text-ink transition-colors">
        ← Back to dashboard
      </button>
      <h1 className="text-[1.4rem] font-semibold tracking-tight mt-3">
        Review submission <span className="text-faint text-[1rem]">· {type}</span>
      </h1>
      <p className="text-[13px] text-faint mt-1">
        Confirm the details below from the ID, then approve. The image is deleted on your decision.
      </p>
      <div className="mt-5 rounded-2xl border border-line overflow-hidden bg-surface">
        {img ? (
          <img src={img} alt="Submitted ID" className="w-full max-h-[60vh] object-contain" />
        ) : (
          <div className="py-20 flex justify-center text-muted">{err ? <span className="text-danger text-sm">{err}</span> : <Spinner size={22} />}</div>
        )}
      </div>
      <div className="mt-5 max-w-xs space-y-4">
        {fields.map((f) =>
          f.type === 'select' ? (
            <label key={f.key} className="block">
              <span className="block text-[11px] uppercase tracking-[0.14em] text-faint mb-1.5">{f.label}</span>
              <select
                value={data[f.key] || ''}
                onChange={(e) => setField(f.key, e.target.value)}
                className="w-full bg-transparent border-0 border-b border-line rounded-none px-0 py-2.5 text-ink outline-none transition-colors focus:border-accent"
              >
                <option value="">Select…</option>
                {(f.options || []).map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <Field
              key={f.key}
              label={f.label}
              type={f.type === 'date' ? 'date' : 'text'}
              value={data[f.key] || ''}
              onChange={(e) => setField(f.key, e.target.value)}
            />
          ),
        )}
      </div>
      {err && img && <p className="text-[13px] text-danger mt-3">{err}</p>}
      <div className="flex items-center gap-2 mt-6">
        <Btn onClick={() => decide(true)} disabled={busy || !ready}>
          {busy ? (
            <>
              <Spinner /> Working…
            </>
          ) : (
            'Approve & issue'
          )}
        </Btn>
        <Btn variant="danger" onClick={() => decide(false)} disabled={busy}>
          Reject
        </Btn>
      </div>
    </div>
  );
}
