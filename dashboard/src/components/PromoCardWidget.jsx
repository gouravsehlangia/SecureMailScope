export default function PromoCardWidget({ onAction }) {
  return (
    <div className="relative overflow-hidden rounded-2xl p-5 border border-sky-200/80 bg-gradient-to-br from-sky-400/20 via-blue-500/20 to-sky-600/30 backdrop-blur-2xl shadow-lg shadow-sky-500/10 flex items-center justify-between gap-4 group">
      {/* Ambient background glow inside card */}
      <div className="absolute -right-8 -bottom-8 w-32 h-32 bg-sky-400/20 rounded-full blur-2xl pointer-events-none" />

      <div className="flex items-center gap-3.5 relative z-10">
        <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-sky-500 to-blue-600 flex items-center justify-center text-white shadow-md shadow-sky-500/30 shrink-0">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <h4 className="text-xs font-extrabold text-slate-800 tracking-tight leading-tight">
            Stronger Email Security
          </h4>
          <p className="text-[10.5px] text-slate-600 font-medium leading-snug mt-0.5 max-w-[210px]">
            Get actionable insights with AI-powered risk analysis and detailed forensic reports.
          </p>
        </div>
      </div>

      {/* Action Button */}
      <button
        onClick={onAction}
        className="w-9 h-9 rounded-full bg-white/90 hover:bg-white text-sky-700 shadow-md shadow-sky-600/10 flex items-center justify-center shrink-0 cursor-pointer group-hover:scale-105 group-hover:translate-x-0.5 transition-all"
        title="Open AI Insights & Reports"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M14 5l7 7m0 0l-7 7m7-7H3" />
        </svg>
      </button>
    </div>
  );
}
