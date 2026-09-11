function Stat({ label, value, tone }) {
  return (
    <div className="flex-1 min-w-[140px] px-5 py-4 border-r border-[var(--color-ink-border)] last:border-r-0">
      <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-1.5">
        {label}
      </div>
      <div className={`text-2xl font-semibold font-mono ${tone || 'text-[var(--color-text-primary)]'}`}>
        {value}
      </div>
    </div>
  );
}

export default function StatStrip({ sessions }) {
  const total = sessions.length;
  const critical = sessions.filter((s) => s.risk_level === 'critical').length;
  const high = sessions.filter((s) => s.risk_level === 'high').length;
  const anomalies = sessions.filter((s) => s.anomaly_flag).length;
  const noPfs = sessions.filter((s) => !s.forward_secrecy).length;
  const certIssues = sessions.filter((s) => s.cert_expired || !s.cert_chain_valid).length;
  const avgScore = total ? Math.round(sessions.reduce((a, s) => a + s.risk_score, 0) / total) : 0;

  return (
    <div className="flex flex-wrap border border-[var(--color-ink-border)] bg-[var(--color-ink-850)]">
      <Stat label="Sessions Analyzed" value={total} />
      <Stat label="Critical" value={critical} tone="text-[var(--color-crit)]" />
      <Stat label="High" value={high} tone="text-[var(--color-high)]" />
      <Stat label="Anomalies Flagged" value={anomalies} tone="text-[var(--color-accent)]" />
      <Stat label="No Forward Secrecy" value={noPfs} />
      <Stat label="Certificate Issues" value={certIssues} />
      <Stat label="Avg Risk Score" value={`${avgScore}/100`} />
    </div>
  );
}
