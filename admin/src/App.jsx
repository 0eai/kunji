import { useState, useEffect, useCallback } from 'react';
import { onAuthStateChanged, signInWithPopup, signOut } from 'firebase/auth';
import { auth, googleProvider } from './firebase.js';
import { fetchLedger, fetchStats, revoke, unrevoke } from './api.js';

const ISSUER_ORIGIN = import.meta.env.VITE_ISSUER_ORIGIN || 'https://issuer-kunji-cc.web.app';

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
  if (user === undefined) body = <p className="muted">Loading…</p>;
  else if (!user) body = <SignIn />;
  else if (!isAdmin) body = <NotAuthorized email={user.email} />;
  else body = <Dashboard />;

  return (
    <div className="wrap">
      <header className="bar">
        <span className="brand">kunji issuer · admin</span>
        {user && (
          <button className="link" onClick={() => signOut(auth)}>
            Sign out ({user.email})
          </button>
        )}
      </header>
      <main>{body}</main>
    </div>
  );
}

function SignIn() {
  const [err, setErr] = useState('');
  return (
    <div className="card center">
      <h1>Operator sign-in</h1>
      <p className="muted">Sign in with an authorized Google account.</p>
      <button
        className="btn"
        onClick={async () => {
          setErr('');
          try {
            await signInWithPopup(auth, googleProvider);
          } catch (e) {
            // Surface the underlying cause. auth/internal-error wraps the Identity Toolkit response in
            // customData.serverResponse (e.g. CONFIGURATION_NOT_FOUND, API key / referrer block) — that's
            // the real signal. Also log the full error for the console.
            console.error('sign-in error', e);
            const sr = e?.customData?.serverResponse;
            const extra = sr ? (typeof sr === 'string' ? sr : JSON.stringify(sr)) : '';
            setErr(`${e?.code || 'error'}${extra ? ' · ' + extra : ''}${e?.message ? ' · ' + e.message : ''}`.slice(0, 600));
          }
        }}
      >
        Sign in with Google
      </button>
      {err && <p className="danger">{err}</p>}
    </div>
  );
}

function NotAuthorized({ email }) {
  return (
    <div className="card center">
      <h1>Not authorized</h1>
      <p className="muted">
        {email} is signed in but is not an issuer operator. Ask an admin to grant access, then sign out and in
        again to refresh your token.
      </p>
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [items, setItems] = useState([]);
  const [keys, setKeys] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(0);

  const load = useCallback(async () => {
    setErr('');
    try {
      const [s, l] = await Promise.all([fetchStats(), fetchLedger()]);
      setStats(s);
      setItems(l.items);
    } catch (e) {
      setErr(e.message);
    }
    try {
      const r = await fetch(`${ISSUER_ORIGIN}/.well-known/kunji-issuer.json`);
      if (r.ok) setKeys(await r.json());
    } catch {
      /* keys view is best-effort */
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (idx, currentlyRevoked) => {
    setBusy(idx);
    try {
      await (currentlyRevoked ? unrevoke(idx) : revoke(idx));
      setItems((xs) => xs.map((x) => (x.idx === idx ? { ...x, revoked: !currentlyRevoked } : x)));
      fetchStats().then(setStats).catch(() => {});
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(0);
    }
  };

  return (
    <div className="stack">
      {err && <p className="danger">{err}</p>}
      {stats && (
        <section className="card">
          <h2>Overview</h2>
          <div className="stats">
            <Stat label="Issued" value={stats.issued} />
            <Stat label="Revoked" value={stats.revoked} />
            <Stat label="IDV verified" value={stats.idv.verified} />
            <Stat label="IDV pending" value={stats.idv.pending} />
            <Stat label="IDV failed" value={stats.idv.failed} />
          </div>
        </section>
      )}

      <section className="card">
        <h2>Issuance ledger</h2>
        <table>
          <thead>
            <tr>
              <th>idx</th>
              <th>thresholds</th>
              <th>kid</th>
              <th>vendor ref</th>
              <th>issued</th>
              <th>status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((x) => (
              <tr key={x.idx} className={x.revoked ? 'is-revoked' : ''}>
                <td>{x.idx}</td>
                <td className="mono">{thresholds(x.claims)}</td>
                <td className="mono small">{x.kid}</td>
                <td className="mono small">{x.vendorRef || '—'}</td>
                <td className="small">{x.issuedAt ? new Date(x.issuedAt).toISOString().slice(0, 10) : '—'}</td>
                <td>{x.revoked ? <span className="danger">revoked</span> : <span className="ok">valid</span>}</td>
                <td>
                  <button className="link" disabled={busy === x.idx} onClick={() => toggle(x.idx, x.revoked)}>
                    {x.revoked ? 'Un-revoke' : 'Revoke'}
                  </button>
                </td>
              </tr>
            ))}
            {!items.length && (
              <tr>
                <td colSpan="7" className="muted">
                  No credentials issued yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {keys && (
        <section className="card">
          <h2>Signing keys</h2>
          <p className="muted small">Read-only. Rotate via the CLI runbook in docs/issuer.md.</p>
          <ul className="keys">
            {(keys.keys || []).map((k) => (
              <li key={k.kid} className="mono small">
                {k.kid} · {k.kty}/{k.crv}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

const thresholds = (c) =>
  c
    ? Object.entries(c)
        .filter(([, v]) => v)
        .map(([k]) => k.replace('age_over_', '≥'))
        .join(' ') || 'none'
    : '—';

function Stat({ label, value }) {
  return (
    <div className="stat">
      <div className="num">{value}</div>
      <div className="lbl">{label}</div>
    </div>
  );
}
