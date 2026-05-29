import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { VaultProvider } from './context/VaultContext';
import { ToastProvider } from './contexts/ToastContext';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <VaultProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </VaultProvider>
  </React.StrictMode>
);
