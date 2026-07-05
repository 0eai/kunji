import { defineConfig } from 'vitest/config';

// Firestore security-rules tests run against the emulator (started by `firebase emulators:exec` via the
// `test:rules` script, which sets FIRESTORE_EMULATOR_HOST for @firebase/rules-unit-testing). Kept in a
// SEPARATE config so the default `npm test` (pure unit tests, no emulator/Java) stays fast + offline.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/rules/**/*.test.js'],
    testTimeout: 30000,
    hookTimeout: 30000,
    // No vitest.setup.js here — these tests use the Firebase SDK against the emulator, not the wallet crypto.
  },
});
