import React from 'react';

export default function ActionHistoryTable({ history, onClear, onItemClick }) {
  return (
    <div className="glass-card rounded-2xl overflow-hidden fade-up" style={{ animationDelay: '100ms' }}>
      <div className="px-5 py-4 border-b border-white/60 bg-white/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-black text-slate-800 tracking-tight flex items-center gap-2">
            <span className="text-sky-500">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </span>
            Analysis History
          </h3>
          <p className="text-[11px] text-slate-500 font-medium mt-0.5">
            Recent files analyzed or compared on this dashboard (Max 10).
          </p>
        </div>
        <button
          onClick={onClear}
          className="px-3 py-1.5 rounded-lg text-xs font-bold text-rose-500 bg-rose-50 hover:bg-rose-100 hover:text-rose-600 transition-colors border border-rose-100"
        >
          Clear History
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[11px] whitespace-nowrap">
          <thead className="bg-slate-50/50">
            <tr>
              <th className="px-5 py-3 font-bold text-slate-400 uppercase tracking-wider w-12">#</th>
              <th className="px-5 py-3 font-bold text-slate-400 uppercase tracking-wider">Action</th>
              <th className="px-5 py-3 font-bold text-slate-400 uppercase tracking-wider">File(s)</th>
              <th className="px-5 py-3 font-bold text-slate-400 uppercase tracking-wider">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/50 text-slate-600">
            {history.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-5 py-12 text-center">
                  <div className="inline-flex flex-col items-center">
                    <span className="text-3xl mb-2 opacity-50">📋</span>
                    <span className="font-semibold text-slate-500">No recent activity</span>
                    <span className="text-[10px] text-slate-400 mt-1">Upload a PCAP to start analyzing.</span>
                  </div>
                </td>
              </tr>
            ) : (
              history.map((item, idx) => (
                <tr 
                  key={item.id} 
                  className="hover:bg-sky-50/60 transition-colors cursor-pointer"
                  onClick={() => onItemClick && onItemClick(item)}
                >
                  <td className="px-5 py-3 font-mono text-slate-400">{history.length - idx}</td>
                  <td className="px-5 py-3">
                    <span className={`px-2 py-1 rounded-md font-bold text-[10px] ${
                      item.type === 'analyze' ? 'bg-indigo-50 text-indigo-600 border border-indigo-100' : 'bg-emerald-50 text-emerald-600 border border-emerald-100'
                    }`}>
                      {item.type === 'analyze' ? 'Analyzed' : 'Compared'}
                    </span>
                  </td>
                  <td className="px-5 py-3 font-semibold text-slate-700">
                    {item.type === 'analyze' ? (
                      item.files[0]
                    ) : (
                      <span className="flex items-center gap-2">
                        {item.files.map((f, i) => (
                          <React.Fragment key={i}>
                            {i > 0 && <span className="text-slate-300 font-bold">/</span>}
                            <span>{f}</span>
                          </React.Fragment>
                        ))}
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-slate-400">
                    {new Date(item.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
