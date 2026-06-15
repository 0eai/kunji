import React, { useState, useEffect } from 'react';
import Hub from './Hub.jsx';
import LoginPage from './LoginPage.jsx';
import Dashboard from './Dashboard.jsx';
import CredentialsDemo from './CredentialsDemo.jsx';
import RpjsDemo from './RpjsDemo.jsx';
import AgenticDemo from './AgenticDemo.jsx';
import StepUpDemo from './StepUpDemo.jsx';
import StepUpAppDemo from './StepUpAppDemo.jsx';

export default function App() {
  const [auth, setAuth] = useState(null); // { sub, claims }
  // Hash routes pick a demo without touching the login flow's query params (?approve / resume):
  //   (none)        → the demos hub
  //   #login        → the Sign-in demo (LoginPage → Dashboard)
  //   #rpjs         → the drop-in rp.js widget demo
  //   #credentials  → the verified-credentials demo
  //   #agentic      → the agent-authorization demo
  //   #stepup       → the AGENT step-up demo (capability + delta re-consent)
  //   #appstepup    → the APP step-up demo (login path: a returning RP asks for a credential)
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHash = () => setHash(window.location.hash);
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const toHub = () => (window.location.hash = '');

  let view;
  if (hash === '#login') {
    view = auth ? (
      <Dashboard sub={auth.sub} claims={auth.claims} onLogout={() => { setAuth(null); window.location.hash = '#login'; }} />
    ) : (
      <LoginPage onSuccess={setAuth} />
    );
  } else if (hash === '#rpjs') {
    view = <RpjsDemo onBack={toHub} />;
  } else if (hash === '#credentials') {
    view = <CredentialsDemo onBack={toHub} />;
  } else if (hash === '#agentic') {
    view = <AgenticDemo onBack={toHub} />;
  } else if (hash === '#stepup') {
    view = <StepUpDemo onBack={toHub} />;
  } else if (hash === '#appstepup') {
    view = <StepUpAppDemo onBack={toHub} />;
  } else {
    view = <Hub />;
  }

  return <div className="min-h-[100dvh] bg-paper text-ink flex flex-col">{view}</div>;
}
