import React, { useState } from 'react';
import LoginPage from './LoginPage.jsx';
import Dashboard from './Dashboard.jsx';

export default function App() {
  const [auth, setAuth] = useState(null); // { sub }

  return (
    <div className="min-h-[100dvh] bg-[#0f0d09] text-[#f5f0e6] flex items-center justify-center p-6">
      {auth
        ? <Dashboard sub={auth.sub} onLogout={() => setAuth(null)} />
        : <LoginPage onSuccess={setAuth} />}
    </div>
  );
}
