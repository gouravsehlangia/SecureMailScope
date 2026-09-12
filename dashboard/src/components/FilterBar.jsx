const SEVS = ['critical','high','medium','low'];
const SEV_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low' };
const SEV_COLORS = {
  critical: 'bg-rose-50 border-rose-200 text-rose-700',
  high:     'bg-orange-50 border-orange-200 text-orange-700',
  medium:   'bg-amber-50 border-amber-200 text-amber-700',
  low:      'bg-emerald-50 border-emerald-200 text-emerald-700',
};

export default function FilterBar({ filters, setFilters, resultCount }) {
  const hasActive = filters.severity || filters.anomalyOnly || filters.search;

  return (
    <div className="glass rounded-2xl px-4 py-3 flex flex-wrap items-center gap-2.5">
      {/* All */}
      <button
        onClick={() => setFilters(f => ({ ...f, severity: null }))}
        className={`px-3 py-1.5 rounded-xl text-[11px] font-semibold border transition-all cursor-pointer ${
          !filters.severity
            ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
            : 'bg-white/50 border-white/60 text-slate-500 hover:bg-white/80'
        }`}
      >
        All
      </button>

      {SEVS.map(level => {
        const active = filters.severity === level;
        return (
          <button key={level}
            onClick={() => setFilters(f => ({ ...f, severity: f.severity === level ? null : level }))}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold border transition-all cursor-pointer ${
              active ? SEV_COLORS[level] : 'bg-white/50 border-white/60 text-slate-500 hover:bg-white/80'
            }`}
          >
            {SEV_LABELS[level]}
          </button>
        );
      })}

      <div className="w-px h-4 bg-slate-200/60 hidden sm:block" />

      {/* Anomaly */}
      <button
        onClick={() => setFilters(f => ({ ...f, anomalyOnly: !f.anomalyOnly }))}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold border transition-all cursor-pointer ${
          filters.anomalyOnly
            ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
            : 'bg-white/50 border-white/60 text-slate-500 hover:bg-white/80'
        }`}
      >
        ⚡ Anomalies
      </button>

      <div className="w-px h-4 bg-slate-200/60 hidden sm:block" />

      {/* Search */}
      <div className="relative flex-1 min-w-[180px]">
        <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          value={filters.search}
          onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
          placeholder="Search sessions…"
          className="glass-input w-full pl-9 pr-3 py-2 rounded-xl text-xs text-slate-700 placeholder:text-slate-400 font-mono outline-none"
        />
      </div>

      {/* Count + clear */}
      <div className="flex items-center gap-2.5 ml-auto">
        <span className="text-[11px] text-slate-400 font-mono">{resultCount} results</span>
        {hasActive && (
          <button onClick={() => setFilters({ severity: null, anomalyOnly: false, search: '' })}
            className="text-[11px] text-indigo-600 hover:text-indigo-800 font-semibold cursor-pointer transition-colors">
            ✕ Clear
          </button>
        )}
      </div>
    </div>
  );
}
