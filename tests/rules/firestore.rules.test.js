import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { collection, doc, getDoc, getDocs, setDoc } from 'firebase/firestore';

// S42 regression guard: the `vaults` collection must NOT be enumerable (no top-level `list`), while a
// `get`/subcollection `list` by a known 256-bit vaultId stays allowed, and direct client writes stay denied.
// Runs under the Firestore emulator (see the `test:rules` script). FIRESTORE_EMULATOR_HOST is set by
// `firebase emulators:exec` and auto-discovered by initializeTestEnvironment.

const rulesPath = resolve(dirname(fileURLToPath(import.meta.url)), '../../firestore.rules');
const VID = 'a'.repeat(64); // a well-formed 64-hex vaultId
let testEnv;

beforeAll(async () => {
  testEnv = await initializeTestEnvironment({
    projectId: 'demo-kunji',
    firestore: { rules: readFileSync(rulesPath, 'utf8') },
  });
  // Seed a vault + a subcollection doc with rules disabled, so the read-back below exercises the rules.
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    await setDoc(doc(db, 'vaults', VID), { writePublicKey: 'pk' });
    await setDoc(doc(db, 'vaults', VID, 'credentials', 'c1'), { blob: 'x' });
  });
});

afterAll(async () => {
  if (testEnv) await testEnv.cleanup();
});

describe('firestore.rules — vaults (S42: no top-level enumeration)', () => {
  // kunji signs every visitor in with anonymous Auth, so model an authenticated anonymous uid.
  const db = () => testEnv.authenticatedContext('anon-uid').firestore();

  it('DENIES a top-level list of the vaults collection (enumeration)', async () => {
    await assertFails(getDocs(collection(db(), 'vaults')));
  });

  it('ALLOWS get of a vault root doc by a known vaultId', async () => {
    await assertSucceeds(getDoc(doc(db(), 'vaults', VID)));
  });

  it('ALLOWS listing a subcollection within a known vault', async () => {
    await assertSucceeds(getDocs(collection(db(), 'vaults', VID, 'credentials')));
  });

  it('DENIES direct client writes to a vault', async () => {
    await assertFails(setDoc(doc(db(), 'vaults', VID, 'apps', 'x'), { foo: 1 }));
  });
});
