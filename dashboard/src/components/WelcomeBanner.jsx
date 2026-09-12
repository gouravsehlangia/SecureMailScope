export default function WelcomeBanner() {
  return (
    <div className="glass-card rounded-2xl px-6 py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
      <div>
        <h1 className="text-xl sm:text-2xl font-extrabold text-slate-800 tracking-tight flex items-center gap-2">
          <span>Welcome back, Team</span>
          <span className="text-xl inline-block hover:rotate-12 transition-transform cursor-default">👋</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-500 font-medium mt-1">
          Here's a quick overview of your email security analysis and key insights.
        </p>
      </div>

      {/* Stylized Right Slogan matching image */}
      <div className="flex items-center gap-3 self-end sm:self-center px-4 py-2 rounded-2xl bg-sky-50/60 border border-sky-100/80 shadow-xs">
        <div className="text-right">
          <p className="text-[13px] font-bold italic text-sky-800 tracking-tight" style={{ fontFamily: 'Georgia, serif' }}>
            Better Insights
          </p>
          <p className="text-[11px] font-semibold italic text-sky-600/90" style={{ fontFamily: 'Georgia, serif' }}>
            Safer Communications
          </p>
        </div>
        {/* Audio waveform / frequency icon */}
        <div className="flex items-center gap-0.5 text-sky-600 h-6 px-1">
          <span className="w-0.5 h-2 bg-sky-400 rounded-full animate-pulse" style={{ animationDelay: '0ms' }} />
          <span className="w-0.5 h-4 bg-sky-500 rounded-full animate-pulse" style={{ animationDelay: '150ms' }} />
          <span className="w-0.5 h-6 bg-sky-600 rounded-full animate-pulse" style={{ animationDelay: '300ms' }} />
          <span className="w-0.5 h-3 bg-sky-500 rounded-full animate-pulse" style={{ animationDelay: '450ms' }} />
          <span className="w-0.5 h-5 bg-sky-600 rounded-full animate-pulse" style={{ animationDelay: '200ms' }} />
          <span className="w-0.5 h-2 bg-sky-400 rounded-full animate-pulse" style={{ animationDelay: '100ms' }} />
        </div>
      </div>
    </div>
  );
}
