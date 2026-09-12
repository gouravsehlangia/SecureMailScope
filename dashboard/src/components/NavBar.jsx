import ExportMenu from './ExportMenu';

const NAV_TABS = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
          d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    id: 'upload',
    label: 'Analyse Capture',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
          d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
      </svg>
    ),
  },
  {
    id: 'history',
    label: 'History',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
          d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
  {
    id: 'compare',
    label: 'Compare',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
];

export default function NavBar({ currentPage, source, onNavigate, onRefresh, sessions = [] }) {
  const isLive = source === 'live';
  const sessionCount = sessions.length || 10;

  return (
    <header className="glass-nav sticky top-0 z-50 border-b border-white/80">
      <div className="max-w-[1680px] mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">

        {/* ── Brand & Tagline ── */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-sky-400 via-blue-500 to-indigo-600 flex items-center justify-center shadow-md shadow-sky-500/20 ring-2 ring-white/80">
            <svg className="w-5 h-5 text-white drop-shadow-sm" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2"
                d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-extrabold text-slate-800 tracking-tight leading-tight">
                SecureMailScope
              </span>
              <span className="hidden xl:inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-sky-100/90 text-sky-700 border border-sky-200">
                SIH 2026
              </span>
            </div>
            <p className="hidden md:block text-[10.5px] font-medium text-slate-500 tracking-tight leading-none mt-0.5">
              AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
            </p>
          </div>
        </div>

        {/* ── Nav Tabs (centre) ── */}
        <nav className="flex items-center gap-1.5 p-1 rounded-2xl bg-white/50 border border-white/80 shadow-inner">
          {NAV_TABS.map((tab) => {
            const active = currentPage === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onNavigate(tab.id)}
                className={`relative flex items-center gap-2 px-4 py-1.5 rounded-xl text-xs font-bold transition-all duration-200 cursor-pointer ${
                  active
                    ? 'text-sky-800 bg-white shadow-sm shadow-sky-100 border border-sky-100/80 scale-[1.02]'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
                }`}
              >
                <span className={`transition-colors ${active ? 'text-sky-600' : 'text-slate-400'}`}>
                  {tab.icon}
                </span>
                {tab.label}
                {active && (
                  <span className="w-1.5 h-1.5 rounded-full bg-sky-500 ml-0.5 animate-pulse" />
                )}
              </button>
            );
          })}
        </nav>

        {/* ── Right Status & Actions ── */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">

          {/* PCAP Telemetry pill (from reference image header) */}
          <div className="hidden lg:flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-white/65 border border-white/90 shadow-sm text-xs">
            <div className="w-7 h-7 rounded-lg bg-sky-50 flex items-center justify-center text-sky-600">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div className="leading-tight">
              <p className="font-semibold text-slate-800 text-[11px]">
                {isLive ? 'live_traffic.pcap' : 'sample_emails.pcap'}
              </p>
              <p className="text-[10px] text-slate-400 font-mono">
                {sessionCount} sessions · 2.4 MB
              </p>
            </div>
          </div>

          {/* Analysis Complete pill */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/65 border border-white/90 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-emerald-500 glow-pulse" />
            <div className="leading-tight">
              <p className="text-[11px] font-bold text-slate-700">Analysis Complete</p>
              <p className="text-[10px] text-slate-400 font-mono">{new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })}</p>
            </div>
          </div>

          {/* Refresh */}
          <button
            onClick={onRefresh}
            title="Refresh Analysis Telemetry"
            className="glass-btn w-9 h-9 flex items-center justify-center rounded-xl text-slate-500 hover:text-sky-600 cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>

          {/* Export Menu */}
          <ExportMenu sessions={sessions} />

        </div>
      </div>
    </header>
  );
}
