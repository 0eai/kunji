import { useState, useEffect, useCallback } from 'react';
import { fetchStats, fetchOpsUsers, fetchOpsTrends } from '../api.js';
import { StatCard, SectionLabel, Card, Sparkline, SkeletonRows, Btn } from '../ui.jsx';
import { fmtNum } from '../lib.js';

// Operator landing page: the issuance/verification funnel, a "needs attention" nudge, the headline user
// counts, and a vaults trend. Polls every 10s while visible.
export default function Overview({ navigate }) {
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState(null);
  const [trends, setTrends] = useState(null);
  const [err, setErr] = useState('');

  const load = useCallback(async () => {
    try {
      const [s, u, t] = await Promise.all([
        fetchStats(),
        fetchOpsUsers().catch(() => null),
        fetchOpsTrends(30).catch(() => null),
      ]);
      setStats(s);
      setUsers(u);
      setTrends(t);
      setErr('');
    } catch (e) {
      setErr(e.message);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(() => !document.hidden && load(), 10000);
    return () => clearInterval(id);
  }, [load]);

  if (err) return <p className="text-[13px] text-danger">{err}</p>;
  if (!stats) return <SkeletonRows rows={3} />;

  const pending = stats.verification.pending_review;
  const vaultsSeries = trends?.series?.vaults || [];

  return (
    <div className="space-y-8">
      {pending > 0 && (
        <Card className="px-4 py-3.5 flex items-center gap-3 border-accent/40 bg-accent-soft">
          <span className="text-[14px] text-ink flex-1">
            {pending === 1 ? '1 submission is' : `${pending} submissions are`} waiting for review.
          </span>
          <Btn variant="outline" onClick={() => navigate('reviews')}>
            Review now
          </Btn>
        </Card>
      )}

      <section>
        <SectionLabel className="mb-3">Issuance</SectionLabel>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <StatCard label="Issued" value={fmtNum(stats.issued)} />
          <StatCard label="Revoked" value={fmtNum(stats.revoked)} tone={stats.revoked ? 'danger' : undefined} />
          <StatCard label="Pending review" value={fmtNum(pending)} />
          <StatCard label="Verified" value={fmtNum(stats.verification.verified)} />
          <StatCard label="Rejected" value={fmtNum(stats.verification.rejected)} />
          <StatCard label="Collecting" value={fmtNum(stats.verification.collecting)} />
        </div>
      </section>

      {users && (
        <section>
          <SectionLabel className="mb-3">Users</SectionLabel>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard label="Vaults" value={fmtNum(users.vaults)} />
            <StatCard label="Verified users" value={fmtNum(users.verifiedUsers)} />
            <StatCard label="Issuer logins · 7d" value={fmtNum(users.issuerLogins7d)} />
            <StatCard label="Accounts" value={fmtNum(users.anonAccounts)} hint="all-time" />
          </div>
        </section>
      )}

      {vaultsSeries.length > 1 && (
        <section>
          <SectionLabel className="mb-2">Vaults · last {vaultsSeries.length} days</SectionLabel>
          <Card className="px-4 py-4">
            <Sparkline values={vaultsSeries} height={56} />
          </Card>
        </section>
      )}
    </div>
  );
}
