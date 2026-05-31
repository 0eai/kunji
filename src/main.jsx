import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import App from './App';
import { VaultProvider } from './context/VaultContext';
import { ToastProvider } from './contexts/ToastContext';
import { watchSystem } from './lib/theme';
import './index.css';

// Keep "System" mode in sync if the OS theme flips while the app is open.
watchSystem();

// Capture the PWA install prompt early (Chrome fires it before React mounts) so a
// custom "Install kunji" button can trigger it later. iOS Safari never fires this.
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  window.__kunjiDeferredInstall = e;
  window.dispatchEvent(new Event('kunji-installable'));
});

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <VaultProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </VaultProvider>
  </React.StrictMode>
);
