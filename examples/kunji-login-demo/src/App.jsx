import React, { useState } from 'react';
import LoginPage from './LoginPage.jsx';
import Dashboard from './Dashboard.jsx';

export default function App() {
  const [auth, setAuth] = useState(null); // { sub }

  return (
    <div className="min-h-[100dvh] bg-paper text-ink flex flex-col">
      {auth ? (
        <Dashboard sub={auth.sub} onLogout={() => setAuth(null)} />
      ) : (
        <LoginPage onSuccess={setAuth} />
      )}
    </div>
  );
}
