import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Standalone admin SPA (admin.kunji.cc). Builds to admin/dist, served by the `admin` Hosting target.
export default defineConfig({
  plugins: [react()],
});
