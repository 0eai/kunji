// The crypto modules reference `window.crypto` / `window.btoa` / `window.atob`.
// Provide a minimal `window` backed by Node's WebCrypto so they run under Vitest.
import { webcrypto } from 'node:crypto';

const cryptoImpl = globalThis.crypto ?? webcrypto;
if (!globalThis.crypto) globalThis.crypto = cryptoImpl;

globalThis.window = globalThis.window || {};
globalThis.window.crypto = cryptoImpl;
globalThis.window.btoa = globalThis.btoa ?? ((s) => Buffer.from(s, 'binary').toString('base64'));
globalThis.window.atob = globalThis.atob ?? ((s) => Buffer.from(s, 'base64').toString('binary'));
