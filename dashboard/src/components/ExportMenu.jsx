import { useState, useRef, useEffect } from 'react';
import { exportJson, exportHtml, exportPdfViaPrint } from '../lib/report';

export default function ExportMenu({ sessions }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const actions = [
    { label: 'JSON Data',   desc: 'Machine-readable output',    icon: '{}', run: () => exportJson(sessions) },
    { label: 'HTML Report', desc: 'Stand-alone audit document',  icon: '<>', run: () => exportHtml(sessions) },
    { label: 'Print / PDF', desc: 'Formatted printable sheet',   icon: '⎙',  run: () => exportPdfViaPrint(sessions) },
  ];

  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold text-white
          bg-gradient-to-br from-indigo-500 to-blue-500 shadow-lg shadow-indigo-200
          hover:shadow-indigo-300 hover:-translate-y-0.5 transition-all cursor-pointer">
        <svg className="w-3.5 h-3.5 opacity-90" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
        Export
        <span className="text-[10px] opacity-70">▾</span>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-52 glass-strong rounded-2xl p-1.5 z-50 fade-up">
          <p className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-400">
            Format
          </p>
          {actions.map(a => (
            <button key={a.label} onClick={() => { a.run(); setOpen(false); }}
              className="w-full text-left px-3 py-2 rounded-xl text-xs hover:bg-white/60 transition-colors flex items-center gap-3 cursor-pointer group">
              <span className="w-7 h-7 rounded-lg bg-white/60 group-hover:bg-indigo-50 text-slate-600 group-hover:text-indigo-600 font-mono font-bold text-[11px] flex items-center justify-center shrink-0 transition-colors border border-white/80">
                {a.icon}
              </span>
              <div>
                <div className="font-semibold text-slate-700 group-hover:text-slate-900">{a.label}</div>
                <div className="text-[10px] text-slate-400">{a.desc}</div>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
