export default function TopViolations({ sessions }) {
  const counts = new Map();
  for (const s of sessions) {
    for (const v of s.rule_violations || []) {
      counts.set(v, (counts.get(v) || 0) + 1);
    }
  }
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const max = top.length ? top[0][1] : 1;
  const COLORS = ['#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#f97316'];

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col">
      <h3 className="text-sm font-bold text-slate-800 mb-0.5">Top Security Findings</h3>
      <p className="text-[11px] text-slate-400 mb-4">Most frequent rule violations</p>

      {top.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center py-8 gap-2">
          <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center text-xl">✓</div>
          <p className="text-xs font-semibold text-emerald-600">No violations found</p>
        </div>
      ) : (
        <div className="space-y-3.5 flex-1">
          {top.map(([violation, count], i) => {
            const pct = Math.round((count / max) * 100);
            const color = COLORS[i];
            return (
              <div key={violation}>
                <div className="flex items-center justify-between gap-3 mb-1.5">
                  <span className="text-[11px] text-slate-600 font-medium truncate leading-tight" title={violation}>
                    {violation}
                  </span>
                  <span className="text-[10px] font-bold font-mono shrink-0 px-2 py-0.5 rounded-full"
                    style={{ color, backgroundColor: `${color}18`, border: `1px solid ${color}30` }}>
                    {count}
                  </span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: `${color}15` }}>
                  <div className="h-full rounded-full transition-all duration-700 ease-out"
                    style={{ width: `${pct}%`, background: `linear-gradient(90deg, ${color}88, ${color})` }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
