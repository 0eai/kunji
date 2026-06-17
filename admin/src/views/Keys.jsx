import { useState, useEffect } from 'react';
import { fetchKeys } from '../api.js';
import { SectionLabel, SkeletonRows, EmptyState } from '../ui.jsx';

// Read-only view of the issuer's active signing keys (from the public .well-known). Rotation is a CLI runbook.
export default function Keys() {
  const [keys, setKeys] = useState(undefined); // undefined = loading, null = unavailable

  useEffect(() => {
    fetchKeys()
      .then(setKeys)
      .catch(() => setKeys(null));
  }, []);

  if (keys === undefined) return <SkeletonRows rows={2} />;

  return (
    <section>
      <SectionLabel className="mb-1">Signing keys</SectionLabel>
      <p className="text-[12px] text-faint mb-3">Read-only. Rotate via the CLI runbook in docs/issuer.md.</p>
      {!keys || !(keys.keys || []).length ? (
        <EmptyState title="Keys unavailable.">Could not reach the issuer&rsquo;s public key set.</EmptyState>
      ) : (
        <div className="border-t border-line divide-y divide-line">
          {keys.keys.map((k) => (
            <div key={k.kid} className="py-3">
              <div className="font-mono text-[13px] text-ink truncate">{k.kid}</div>
              <div className="font-mono text-[12px] text-faint">
                {k.kty}/{k.crv}
                {k.use ? ` · ${k.use}` : ''}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
