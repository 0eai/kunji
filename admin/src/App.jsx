import { useState, useEffect } from 'react';
import { onAuthStateChanged, signInWithPopup, signOut } from 'firebase/auth';
import { auth, googleProvider } from './firebase.js';
import { ToastProvider } from './contexts/ToastContext.jsx';
import { Btn } from './ui.jsx';
import { ROUTES, useHashRoute } from './lib.js';
import { getThemePref, setThemePref } from './theme.js';
import Overview from './views/Overview.jsx';
import Reviews from './views/Reviews.jsx';
import Ledger from './views/Ledger.jsx';
import Users from './views/Users.jsx';
import DataHealth from './views/DataHealth.jsx';
import Metrics from './views/Metrics.jsx';
import Keys from './views/Keys.jsx';

const VIEWS = { overview: Overview, reviews: Reviews, ledger: Ledger, users: Users, data: DataHealth, metrics: Metrics, keys: Keys };

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
  else if (!user) body = <CenteredCard><SignIn /></CenteredCard>;
  else if (!isAdmin) body = <CenteredCard><NotAuthorized email={user.email} /></CenteredCard>;
  else
    return (
      <ToastProvider>
        <Console user={user} />
      </ToastProvider>
    );

  return (
    <div className="min-h-[100dvh] flex flex-col">
      <Header user={user} />
      <main className="flex-1 max-w-3xl w-full mx-auto px-6 py-6 animate-rise">{body}</main>
    </div>
  );
}

const CenteredCard = ({ children }) => <div className="max-w-sm mx-auto mt-16 text-center">{children}</div>;

function Header({ user, children }) {
  return (
    <header className="flex items-center gap-3 max-w-6xl w-full mx-auto px-6 pt-5 pb-4 border-b border-line">
      <img src="https://kunji.cc/icon.svg" alt="" className="w-6 h-6 rounded-md" />
      <span className="text-[14px] text-muted">
        kunji <span className="text-faint">· admin</span>
      </span>
      <div className="ml-auto flex items-center gap-4">
        {children}
        <ThemeToggle />
        {user && (
          <button onClick={() => signOut(auth)} className="text-[13px] text-muted hover:text-ink transition-colors">
            Sign out{user.email ? ` · ${user.email}` : ''}
          </button>
        )}
      </div>
    </header>
  );
}

function ThemeToggle() {
  const [pref, setPref] = useState(getThemePref());
  const opts = [
    ['light', 'Light'],
    ['dark', 'Dark'],
    ['system', 'Auto'],
  ];
  return (
    <div className="hidden sm:flex gap-0.5 p-0.5 rounded-full border border-line" role="group" aria-label="Theme">
      {opts.map(([v, l]) => (
        <button
          key={v}
          onClick={() => {
            setThemePref(v);
            setPref(v);
          }}
          aria-pressed={pref === v}
          className={`px-2.5 py-1 rounded-full text-[11px] font-medium transition-colors ${pref === v ? 'bg-accent-soft text-accent' : 'text-muted hover:text-ink'}`}
        >
          {l}
        </button>
      ))}
    </div>
  );
}

function Console({ user }) {
  const [route, navigate] = useHashRoute();
  const View = VIEWS[route] || Overview;
  const current = ROUTES.find((r) => r.id === route);

  return (
    <div className="min-h-[100dvh] flex flex-col">
      <Header user={user} />
      <div className="flex-1 w-full max-w-6xl mx-auto flex flex-col md:flex-row">
        {/* Nav: a vertical sidebar on md+, a horizontal scrollable tab strip on mobile. */}
        <nav className="md:w-48 md:shrink-0 border-b md:border-b-0 md:border-r border-line">
          <div className="flex md:flex-col gap-1 px-3 py-3 overflow-x-auto md:overflow-visible md:sticky md:top-4">
            {ROUTES.map((r) => (
              <button
                key={r.id}
                onClick={() => navigate(r.id)}
                aria-current={route === r.id ? 'page' : undefined}
                className={`shrink-0 text-left px-3 py-2 rounded-lg text-[13px] font-medium transition-colors whitespace-nowrap ${
                  route === r.id ? 'bg-accent-soft text-accent' : 'text-muted hover:text-ink hover:bg-line/40'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </nav>
        <main className="flex-1 min-w-0 px-6 py-6">
          <h1 className="text-[1.3rem] font-semibold tracking-tight mb-5">{current?.label}</h1>
          <div className="animate-rise" key={route}>
            <View navigate={navigate} />
          </div>
        </main>
      </div>
    </div>
  );
}

function SignIn() {
  const [err, setErr] = useState('');
  return (
    <>
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
    </>
  );
}

function NotAuthorized({ email }) {
  return (
    <>
      <h1 className="text-[1.5rem] font-semibold tracking-tight">Not authorized</h1>
      <p className="text-[15px] text-muted mt-2">
        {email} is signed in but isn&rsquo;t an issuer operator. Ask an admin to grant access, then sign out and in again to
        refresh your token.
      </p>
    </>
  );
}
