import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Standalone issuer flow (issuer.kunji.cc). Builds to issuer-web/dist, served by the `issuer` Hosting target.
export default defineConfig({
  plugins: [react()],
});
