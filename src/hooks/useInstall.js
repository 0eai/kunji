import { useState, useEffect } from 'react';

const isStandalone = () =>
  window.matchMedia?.('(display-mode: standalone)').matches || window.navigator.standalone === true;

const isIOS = () =>
  /iphone|ipad|ipod/i.test(window.navigator.userAgent) && !window.MSStream;

/**
 * PWA install state. Chrome/Android exposes a deferred `beforeinstallprompt`
 * (captured in main.jsx) that we can trigger; iOS Safari can't be prompted
 * programmatically, so callers show Add-to-Home-Screen instructions instead.
 */
export function useInstall() {
  const [canPrompt, setCanPrompt] = useState(!!window.__kunjiDeferredInstall);

  useEffect(() => {
    const onAvailable = () => setCanPrompt(!!window.__kunjiDeferredInstall);
    const onInstalled = () => { window.__kunjiDeferredInstall = null; setCanPrompt(false); };
    window.addEventListener('kunji-installable', onAvailable);
    window.addEventListener('appinstalled', onInstalled);
    return () => {
      window.removeEventListener('kunji-installable', onAvailable);
      window.removeEventListener('appinstalled', onInstalled);
    };
  }, []);

  const promptInstall = async () => {
    const e = window.__kunjiDeferredInstall;
    if (!e) return false;
    e.prompt();
    const { outcome } = await e.userChoice;
    window.__kunjiDeferredInstall = null;
    setCanPrompt(false);
    return outcome === 'accepted';
  };

  return { isStandalone: isStandalone(), isIOS: isIOS(), canPrompt, promptInstall };
}
