/**
 * Publish the built widget as an IMMUTABLE, SRI-pinnable artifact.
 *
 * Why this exists: `rp.js` and `rp.v1.js` are *rolling* URLs — every widget build
 * rewrites them. An RP that pins an SRI hash to either one has its login break on
 * our next deploy, with no signal. So each build also emits a versioned file that is
 * never rewritten, plus a manifest publishing its hash.
 *
 * Emits (into ../landing/):
 *   rp-<version>.js   immutable, content-frozen; refuses to overwrite with new bytes
 *   rp.v1.js          rolling "latest v1" alias (kept: existing integrators load it)
 *   rp.versions.json  {latest, rolling, versions[{version,url,integrity,bytes,released}]}
 *
 * Bump `version` in widget/package.json to cut a new pinned build. Rebuilding the
 * same version is idempotent as long as the bytes are identical — if they differ,
 * this fails rather than silently re-defining a hash someone has already pinned.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANDING = join(HERE, '..', 'landing');
const ORIGIN = 'https://kunji.cc';

const fail = (msg) => {
  console.error(`\n  publish: ${msg}\n`);
  process.exit(1);
};

const { version } = JSON.parse(readFileSync(join(HERE, 'package.json'), 'utf8'));
if (!/^\d+\.\d+\.\d+$/.test(version)) fail(`widget/package.json version "${version}" is not x.y.z`);

const bundle = readFileSync(join(LANDING, 'rp.js')); // Buffer — compare/hash raw bytes
const integrity = `sha384-${createHash('sha384').update(bundle).digest('base64')}`;

// 1 · the immutable artifact. Never re-defined once published.
const pinnedName = `rp-${version}.js`;
const pinnedPath = join(LANDING, pinnedName);
if (existsSync(pinnedPath) && !readFileSync(pinnedPath).equals(bundle)) {
  fail(
    `${pinnedName} already exists with different bytes.\n` +
      `  Pinned builds are immutable — an RP may have this hash in an integrity= attribute.\n` +
      `  Bump "version" in widget/package.json and rebuild.`,
  );
}
writeFileSync(pinnedPath, bundle);

// 2 · the rolling major alias. Mutable by design; documented as not pinnable.
writeFileSync(join(LANDING, 'rp.v1.js'), bundle);

// 3 · the manifest. Existing entries keep their original release date.
const manifestPath = join(LANDING, 'rp.versions.json');
const prev = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : {};
const kept = (prev.versions ?? []).filter((v) => v.version !== version);
const released =
  (prev.versions ?? []).find((v) => v.version === version)?.released ??
  new Date().toISOString().slice(0, 10);

const cmp = (a, b) => {
  const [x, y] = [a, b].map((s) => s.version.split('.').map(Number));
  return y[0] - x[0] || y[1] - x[1] || y[2] - x[2];
};
const versions = [
  { version, url: `${ORIGIN}/${pinnedName}`, integrity, bytes: bundle.length, released },
  ...kept,
].sort(cmp);

writeFileSync(
  manifestPath,
  JSON.stringify(
    {
      $comment:
        'Immutable, SRI-pinnable builds of the kunji "Sign in with kunji" widget. ' +
        'Pin a versions[] url + integrity. The rolling urls below are rewritten on every ' +
        'release — do NOT attach an integrity hash to them.',
      latest: version,
      rolling: [`${ORIGIN}/rp.js`, `${ORIGIN}/rp.v1.js`],
      versions,
    },
    null,
    2,
  ) + '\n',
);

console.log(`  rp.js            ${bundle.length} bytes  ${integrity}`);
console.log(`  ${pinnedName}      pinnable → ${ORIGIN}/${pinnedName}`);
console.log(`  rp.versions.json latest=${version}, ${versions.length} version(s)`);
