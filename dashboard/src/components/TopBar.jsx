import ExportMenu from './ExportMenu';

export default function TopBar({ source, onRefresh, sessions, onUploadNew, onCompare, currentPage }) {
  const isLive = source === 'live';

  return (
    <header className="sticky top-0 z-40 border-b border-[#1e2744] bg-[#0c1024]/90 backdrop-blur-xl">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">

        {/* Brand */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-lg shadow-indigo-500/25">
            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5"
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div className="hidden sm:block">
            <span className="text-sm font-bold text-white tracking-tight">SecureMailScope</span>
            <span className="ml-2 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-[#1e2744] text-[#6c86f5] border border-[#6c86f5]/30">
              v1.0
            </span>
          </div>
        </div>

        {/* Nav tabs */}
        <nav className="hidden md:flex items-center gap-1">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: '▦' },
            { id: 'upload',    label: 'Analyse Capture', icon: '↑' },
            { id: 'compare',   label: 'Compare', icon: '⊞' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                if (tab.id === 'upload' && onUploadNew) onUploadNew();
                if (tab.id === 'compare' && onCompare) onCompare();
                if (tab.id === 'dashboard' && onRefresh) onRefresh();
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                currentPage === tab.id
                  ? 'bg-[#6c86f5]/15 text-[#6c86f5] border border-[#6c86f5]/30'
                  : 'text-[#7b8ab8] hover:text-white hover:bg-[#1e2744]'
              }`}
            >
              <span className="font-mono text-[11px]">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Right side */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Data source indicator */}
          <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold border ${
            isLive
              ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400'
              : source === null
              ? 'bg-[#1e2744] border-[#1e2744] text-[#4d5a82]'
              : 'bg-amber-500/10 border-amber-500/25 text-amber-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              isLive ? 'bg-emerald-400 animate-pulse' : 'bg-[#4d5a82]'
            }`} />
            {isLive ? 'Live' : source === null ? 'Loading…' : 'Offline'}
          </div>

          {/* Refresh */}
          <button
            onClick={onRefresh}
            className="w-8 h-8 flex items-center justify-center rounded-lg text-[#7b8ab8] hover:text-white hover:bg-[#1e2744] border border-transparent hover:border-[#1e2744] transition-all cursor-pointer"
            title="Refresh data"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>

          {/* Export */}
          <ExportMenu sessions={sessions} />
        </div>
      </div>
    </header>
  );
}
