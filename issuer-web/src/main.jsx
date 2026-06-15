import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './index.css';
import { applyTheme, watchSystem } from './theme.js';

applyTheme();
watchSystem();

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
