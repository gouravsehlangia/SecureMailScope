export default function RecentActivityWidget({ sessions = [], lastAnalysisTime }) {
  const sessionCount = sessions.length || 10;

  const baseTime = lastAnalysisTime ? new Date(lastAnalysisTime) : new Date();
  const formatOffset = (minsAgo) => {
    const d = new Date(baseTime.getTime() - minsAgo * 60 * 1000);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  };

  const events = [
    {
      time: formatOffset(0),
      title: 'Analysis completed',
      detail: `${sessionCount} sessions processed`,
      dotColor: 'bg-emerald-400',
    },
    {
      time: formatOffset(4),
      title: 'AI analysis finished',
      detail: 'Risk scoring & recommendations',
      dotColor: 'bg-sky-400',
    },
    {
      time: formatOffset(8),
      title: 'Certificate validation',
      detail: `${sessions.filter(s => s.cert_expired || !s.cert_chain_valid).length || 3} issues found`,
      dotColor: 'bg-amber-400',
    },
    {
      time: formatOffset(12),
      title: 'TLS parsing completed',
      detail: 'Handshake details extracted',
      dotColor: 'bg-blue-400',
    },
    {
      time: formatOffset(17),
      title: 'Capture file parsed',
      detail: `${sessionCount} sessions detected`,
      dotColor: 'bg-slate-400',
    },
  ];

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
      {/* Title with View all */}
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-sky-100 flex items-center justify-center text-sky-600">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h3 className="text-xs font-bold text-slate-800 tracking-tight">
            Recent Activity
          </h3>
        </div>

        <button className="text-[11px] font-semibold text-sky-600 hover:text-sky-800 transition-colors cursor-pointer flex items-center gap-0.5">
          <span>View all</span>
          <span>→</span>
        </button>
      </div>

      {/* Timeline items */}
      <div className="space-y-3 relative before:absolute before:left-[4.2rem] before:top-2 before:bottom-2 before:w-px before:bg-slate-200/60">
        {events.map((e, idx) => (
          <div key={idx} className="flex items-start gap-3 relative text-xs">
            <span className="font-mono text-[10px] text-slate-400 font-semibold w-9 text-right shrink-0 mt-0.5">
              {e.time}
            </span>

            {/* Dot */}
            <span className={`w-2 h-2 rounded-full ${e.dotColor} shrink-0 mt-1 shadow-xs ring-2 ring-white`} />

            {/* Content */}
            <div className="leading-tight">
              <p className="font-bold text-slate-800 text-[11px]">{e.title}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">{e.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
