import { useState, useEffect } from 'react';
import { fetchOpsUsers, fetchOpsTrends } from '../api.js';
import { StatCard, SectionLabel, Card, BarChart, SkeletonRows } from '../ui.jsx';
import { fmtNum } from '../lib.js';

// Aggregate user counts + daily trends. kunji keeps NO per-user identity or cross-app activity by design, so
// everything here is a count — never a per-person row.
export default function Users() {
  const [users, setUsers] = useState(null);
  const [trends, setTrends] = useState(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const [u, t] = await Promise.all([fetchOpsUsers(), fetchOpsTrends(30).catch(() => null)]);
        setUsers(u);
        setTrends(t);
      } catch (e) {
        setErr(e.message);
      }
    })();
  }, []);

  if (err) return <p className="text-[13px] text-danger">{err}</p>;
  if (!users) return <SkeletonRows rows={3} />;

  const series = trends?.series || {};
  const charts = [
    { key: 'vaults', label: 'Vaults' },
    { key: 'verifiedUsers', label: 'Verified users' },
    { key: 'issued', label: 'Credentials issued' },
    { key: 'issuerLogins', label: 'Issuer logins / day' },
  ].filter((c) => (series[c.key] || []).length > 1);

  return (
    <div className="space-y-8">
      <section>
        <SectionLabel className="mb-3">Aggregate counts</SectionLabel>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <StatCard label="Vaults (wallets)" value={fmtNum(users.vaults)} />
          <StatCard label="Accounts (all-time)" value={fmtNum(users.anonAccounts)} hint="existence, not activity" />
          <StatCard label="Verified users" value={fmtNum(users.verifiedUsers)} />
          <StatCard label="Issuer logins · 7d" value={fmtNum(users.issuerLogins7d)} />
          <StatCard label="Issuer logins · 30d" value={fmtNum(users.issuerLogins30d)} />
        </div>
        <p className="text-[12px] text-muted mt-3 leading-relaxed max-w-xl">
          kunji is zero-knowledge — it keeps no per-user identity and no cross-app activity. These are aggregate
          counts only; a wallet can never be linked to a person or tracked across apps.
        </p>
      </section>

      {charts.length > 0 && (
        <section>
          <SectionLabel className="mb-3">Daily trends · last {trends.dates.length} days</SectionLabel>
          <div className="grid sm:grid-cols-2 gap-4">
            {charts.map((c) => (
              <Card key={c.key} className="px-4 py-4">
                <div className="text-[12px] text-faint mb-2">{c.label}</div>
                <BarChart values={series[c.key]} height={96} />
              </Card>
            ))}
          </div>
        </section>
      )}
      {charts.length === 0 && (
        <p className="text-[13px] text-muted">Trend charts appear once the daily snapshot has run a few times.</p>
      )}
    </div>
  );
}
