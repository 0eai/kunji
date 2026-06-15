import React, { useState, useEffect } from 'react';
import LoginPage from './LoginPage.jsx';
import Dashboard from './Dashboard.jsx';
import CredentialsDemo from './CredentialsDemo.jsx';

export default function App() {
  const [auth, setAuth] = useState(null); // { sub, claims }
  // A hash route (#credentials) selects the verified-credentials demo without touching the login flow's
  // query params (?approve / resume). Default view = the Sign-in demo.
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHash = () => setHash(window.location.hash);
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  return (
    <div className="min-h-[100dvh] bg-paper text-ink flex flex-col">
      {hash === '#credentials' ? (
        <CredentialsDemo onBack={() => (window.location.hash = '')} />
      ) : auth ? (
        <Dashboard sub={auth.sub} claims={auth.claims} onLogout={() => setAuth(null)} />
      ) : (
        <>
          <LoginPage onSuccess={setAuth} />
          <a
            href="#credentials"
            className="text-[13px] text-muted hover:text-ink text-center pb-8 underline-offset-2 hover:underline"
          >
            Try the verified-credentials demo →
          </a>
        </>
      )}
    </div>
  );
}
