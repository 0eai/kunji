import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Allow importing the shared kunji default-identity helper (src/lib/kunjiHandle.js)
  // from the repo root, so this reference RP renders names/identicons the same way
  // the wallet and rp.js do.
  server: { port: 5173, fs: { allow: ['../../..'] } },
});
