import React, { useState } from 'react';
import LoginPage from './LoginPage.jsx';
import Dashboard from './Dashboard.jsx';

export default function App() {
  const [auth, setAuth] = useState(null); // { sub }

  return (
    <div className="min-h-[100dvh] bg-[#f6f7f9] text-[#18181b] flex items-center justify-center p-6">
      {auth
        ? <Dashboard sub={auth.sub} onLogout={() => setAuth(null)} />
        : <LoginPage onSuccess={setAuth} />}
    </div>
  );
}
