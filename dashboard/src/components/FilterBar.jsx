import { SEVERITY, SEVERITY_ORDER } from '../lib/severity';

export default function FilterBar({ filters, setFilters, resultCount }) {
  function toggleSeverity(level) {
    setFilters((f) => ({
      ...f,
      severity: f.severity === level ? null : level,
    }));
  }

  return (
    <div className="flex flex-wrap items-center gap-3 px-1">
      <div className="flex gap-1.5">
        {SEVERITY_ORDER.map((level) => {
          const sev = SEVERITY[level];
          const active = filters.severity === level;
          return (
            <button
              key={level}
              onClick={() => toggleSeverity(level)}
              className={`px-2.5 py-1 text-[11px] font-mono uppercase tracking-wide border transition-colors ${
                active
                  ? `${sev.bg} ${sev.text} ${sev.border}`
                  : 'border-[var(--color-ink-border)] text-[var(--color-text-dim)] hover:text-[var(--color-text-muted)]'
              }`}
            >
              {sev.label}
            </button>
          );
        })}
      </div>

      <div className="w-px h-5 bg-[var(--color-ink-border)]" />

      <button
        onClick={() => setFilters((f) => ({ ...f, anomalyOnly: !f.anomalyOnly }))}
        className={`px-2.5 py-1 text-[11px] font-mono uppercase tracking-wide border transition-colors ${
          filters.anomalyOnly
            ? 'border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 text-[var(--color-accent)]'
            : 'border-[var(--color-ink-border)] text-[var(--color-text-dim)] hover:text-[var(--color-text-muted)]'
        }`}
      >
        Anomalies Only
      </button>

      <div className="w-px h-5 bg-[var(--color-ink-border)]" />

      <input
        value={filters.search}
        onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
        placeholder="Search session ID / cipher suite…"
        className="flex-1 min-w-[200px] bg-transparent border border-[var(--color-ink-border)] px-2.5 py-1 text-[13px] font-mono text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:border-[var(--color-accent)]"
      />

      <span className="text-[11px] font-mono text-[var(--color-text-dim)] whitespace-nowrap">
        {resultCount} shown
      </span>

      {(filters.severity || filters.anomalyOnly || filters.search) && (
        <button
          onClick={() => setFilters({ severity: null, anomalyOnly: false, search: '' })}
          className="text-[11px] font-mono text-[var(--color-accent)] hover:underline"
        >
          Clear
        </button>
      )}
    </div>
  );
}
