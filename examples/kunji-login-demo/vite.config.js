import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      // Proxy the RP backend so the browser stays on a single origin.
      '/api': 'http://localhost:8787',
      '/kunji': 'http://localhost:8787',
    },
  },
});
