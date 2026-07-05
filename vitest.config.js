import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./vitest.setup.js'],
    include: ['tests/**/*.test.js'],
    // The emulator-backed Firestore rules tests run via `npm run test:rules` (vitest.rules.config.js);
    // exclude them here so the default `npm test` stays offline (no emulator/Java required).
    exclude: [...configDefaults.exclude, 'tests/rules/**'],
    testTimeout: 20000,
  },
});
