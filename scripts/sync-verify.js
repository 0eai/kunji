#!/usr/bin/env node
// Sync the canonical @kunji/verify sources into the in-repo demo RPs / issuer.
//
// `packages/verify/src/{verify,capability}.js` is the single source of truth. The demo RPs and the
// live issuer ship byte-identical mirrors (they deploy in different contexts — Firebase Functions
// bundles + plain-Node demos — where a shared import/workspace dep would break zero-config deploys),
// so we COPY rather than import. tests/sdk.parity.test.js fails the build if a mirror drifts.
//
//   node scripts/sync-verify.js          # copy canonical → all mirrors
//   node scripts/sync-verify.js --check  # verify mirrors match (no write); exit 1 on drift
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const at = (rel) => fileURLToPath(new URL(rel, root));

// canonical source → [mirror paths]
const MIRRORS = {
  'packages/verify/src/verify.js': [
    'examples/kunji-node-demo/verify.js',
    'examples/kunji-agent-demo/verify.js',
    'examples/kunji-login-demo/functions/verify.js',
    'examples/kunji-selfhosted-demo/functions/verify.js',
    'examples/kunji-relay-demo/functions/verify.js',
    'issuer-functions/loginVerify.js',
  ],
  'packages/verify/src/capability.js': [
    'examples/kunji-agent-demo/capability.js',
    'examples/kunji-login-demo/functions/capability.js',
  ],
};

const check = process.argv.includes('--check');
let drift = 0;
let synced = 0;

for (const [source, mirrors] of Object.entries(MIRRORS)) {
  const canonical = readFileSync(at(source), 'utf8');
  for (const mirror of mirrors) {
    const current = (() => {
      try {
        return readFileSync(at(mirror), 'utf8');
      } catch {
        return null;
      }
    })();
    if (current === canonical) continue;
    if (check) {
      console.error(`DRIFT: ${mirror} differs from ${source}`);
      drift++;
    } else {
      writeFileSync(at(mirror), canonical);
      console.log(`synced ${mirror}  ←  ${source}`);
      synced++;
    }
  }
}

if (check) {
  if (drift) {
    console.error(`\n${drift} mirror(s) drifted. Run: node scripts/sync-verify.js`);
    process.exit(1);
  }
  console.log('@kunji/verify mirrors are in sync.');
} else {
  console.log(synced ? `\nsynced ${synced} mirror(s).` : 'mirrors already in sync.');
}
