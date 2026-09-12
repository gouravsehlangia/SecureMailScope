export default function StatStrip({ sessions = [] }) {
  const total = sessions.length || 10;
  const secureCount = sessions.filter(s => s.risk_level === 'low').length || (sessions.length ? 0 : 6);
  const mediumCount = sessions.filter(s => s.risk_level === 'medium').length || (sessions.length ? 0 : 2);
  const highCount = sessions.filter(s => s.risk_level === 'high' || s.risk_level === 'critical').length || (sessions.length ? 0 : 2);

  const securePct = total ? Math.round((secureCount / total) * 100) : 60;
  const mediumPct = total ? Math.round((mediumCount / total) * 100) : 20;
  const highPct = total ? Math.round((highCount / total) * 100) : 20;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {/* 1. Total Sessions */}
      <div className="glass-card rounded-2xl p-5 flex items-center gap-4 group">
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-sky-400 to-blue-600 flex items-center justify-center text-white shadow-md shadow-sky-500/25 shrink-0 group-hover:scale-105 transition-transform">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-500">Total Sessions</p>
          <h3 className="text-2xl sm:text-3xl font-extrabold text-slate-800 tracking-tight font-mono">
            {total}
          </h3>
          <p className="text-[11px] font-bold text-emerald-600 flex items-center gap-1 mt-0.5">
            <span>↑</span>
            <span>Analyzed successfully</span>
          </p>
        </div>
      </div>

      {/* 2. Secure */}
      <div className="glass-card rounded-2xl p-5 flex items-center gap-4 group">
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-emerald-400 to-teal-600 flex items-center justify-center text-white shadow-md shadow-emerald-500/25 shrink-0 group-hover:scale-105 transition-transform">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-500">Secure</p>
          <h3 className="text-2xl sm:text-3xl font-extrabold text-slate-800 tracking-tight font-mono">
            {secureCount}
          </h3>
          <p className="text-[11px] font-bold text-emerald-600 mt-0.5">
            {securePct}% of total
          </p>
        </div>
      </div>

      {/* 3. Medium Risk */}
      <div className="glass-card rounded-2xl p-5 flex items-center gap-4 group">
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-amber-400 to-orange-500 flex items-center justify-center text-white shadow-md shadow-amber-500/25 shrink-0 group-hover:scale-105 transition-transform">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-500">Medium Risk</p>
          <h3 className="text-2xl sm:text-3xl font-extrabold text-slate-800 tracking-tight font-mono">
            {mediumCount}
          </h3>
          <p className="text-[11px] font-bold text-amber-600 mt-0.5">
            {mediumPct}% of total
          </p>
        </div>
      </div>

      {/* 4. High Risk */}
      <div className="glass-card rounded-2xl p-5 flex items-center gap-4 group">
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-rose-400 to-red-600 flex items-center justify-center text-white shadow-md shadow-rose-500/25 shrink-0 group-hover:scale-105 transition-transform">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2"
              d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-500">High Risk</p>
          <h3 className="text-2xl sm:text-3xl font-extrabold text-slate-800 tracking-tight font-mono">
            {highCount}
          </h3>
          <p className="text-[11px] font-bold text-rose-600 mt-0.5">
            {highPct}% of total
          </p>
        </div>
      </div>
    </div>
  );
}
