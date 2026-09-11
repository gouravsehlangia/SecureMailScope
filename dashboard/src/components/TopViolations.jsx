export default function TopViolations({ sessions }) {
  const counts = new Map();
  for (const s of sessions) {
    for (const v of s.rule_violations || []) {
      counts.set(v, (counts.get(v) || 0) + 1);
    }
  }
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = top.length ? top[0][1] : 1;

  return (
    <div className="border border-[var(--color-ink-border)] bg-[var(--color-ink-850)] p-4">
      <h3 className="text-xs uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-3">
        Most Common Findings
      </h3>
      {top.length === 0 ? (
        <p className="text-sm text-[var(--color-text-muted)]">No rule violations in this run.</p>
      ) : (
        <div className="space-y-2.5">
          {top.map(([violation, count]) => (
            <div key={violation}>
              <div className="flex justify-between gap-3 text-xs mb-1">
                <span className="text-[var(--color-text-muted)] truncate">{violation}</span>
                <span className="font-mono text-[var(--color-text-primary)] shrink-0">{count}</span>
              </div>
              <div className="h-1.5 bg-[var(--color-ink-700)] w-full">
                <div
                  className="h-1.5 bg-[var(--color-accent)]"
                  style={{ width: `${(count / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
