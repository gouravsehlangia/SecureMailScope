import { useEffect, useState } from 'react';
import { fetchHistory, fetchHistoryRun, deleteHistoryRun } from '../lib/api';

const RISK_COLORS = {
  critical: 'bg-rose-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-400',
  low: 'bg-emerald-500',
};

const RISK_TEXT = {
  critical: 'text-rose-600',
  high: 'text-orange-600',
  medium: 'text-amber-600',
  low: 'text-emerald-600',
};

function formatDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function RiskBar({ summary, total }) {
  if (!total) return null;
  const levels = ['critical', 'high', 'medium', 'low'];
  return (
    <div className="flex h-2 rounded-full overflow-hidden bg-slate-100">
      {levels.map(level => {
        const count = summary?.[level] || 0;
        const pct = (count / total) * 100;
        if (!pct) return null;
        return (
          <div
            key={level}
            className={`${RISK_COLORS[level]} transition-all duration-500`}
            style={{ width: `${pct}%` }}
            title={`${level}: ${count}`}
          />
        );
      })}
    </div>
  );
}

export default function HistoryPage({ onLoadRun }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingRun, setLoadingRun] = useState(null);
  const [error, setError] = useState(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const { history: data, source } = await fetchHistory();
      setHistory(data);
      if (source === 'offline' && data.length === 0) {
        setError('Backend offline — no history available. Start the backend with python pipeline.py');
      }
    } catch {
      setError('Could not load analysis history.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleLoadRun(runId) {
    setLoadingRun(runId);
    try {
      const { run } = await fetchHistoryRun(runId);
      if (run && run.sessions) {
        onLoadRun(run.sessions, run.metadata);
      }
    } catch {
      // silently fail
    } finally {
      setLoadingRun(null);
    }
  }

  async function handleDelete(runId) {
    const ok = await deleteHistoryRun(runId);
    if (ok) {
      setHistory(prev => prev.filter(h => h.run_id !== runId));
    }
  }

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8 space-y-5 fade-up">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violet-50/80 border border-violet-200/60 text-violet-600 text-[11px] font-semibold backdrop-blur-sm mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-500 glow-pulse" />
            Analysis History
          </div>
          <h1 className="text-2xl font-black text-slate-800 tracking-tight">Past Analyses</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Last {Math.min(history.length, 10)} analysis runs are saved. Click to reload results.
          </p>
        </div>
        <button
          onClick={load}
          className="glass-btn px-3 py-2 rounded-xl text-xs font-bold text-violet-600 border border-violet-200/60 cursor-pointer"
        >
          Refresh
        </button>
      </div>

      {/* Loading */}
      {loading && (
        <div className="py-16 flex flex-col items-center gap-3">
          <div className="w-10 h-10 rounded-full border-3 border-violet-300 border-t-violet-600 spin" />
          <p className="text-sm font-semibold text-slate-500">Loading history…</p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="glass-card rounded-2xl p-4 border-amber-200/70 bg-amber-50/50">
          <p className="text-sm text-amber-700 font-semibold">{error}</p>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && history.length === 0 && (
        <div className="glass-card rounded-2xl py-16 text-center">
          <div className="text-4xl mb-3">📭</div>
          <p className="text-sm font-semibold text-slate-500">No analysis history yet</p>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Upload a PCAP file or JSON dataset through the "Analyse Capture" page.
            Each completed run will be saved here automatically.
          </p>
        </div>
      )}

      {/* History List */}
      {!loading && history.length > 0 && (
        <div className="space-y-3 stagger">
          {history.map((run, idx) => {
            const isLoading = loadingRun === run.run_id;
            const summary = run.risk_summary || {};
            const total = run.session_count || 0;

            return (
              <div
                key={run.run_id}
                className="glass-card rounded-2xl p-4 sm:p-5 transition-all duration-200 hover:scale-[1.005] group"
              >
                <div className="flex items-start gap-4">
                  {/* Index badge */}
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-100 to-indigo-100 flex items-center justify-center shrink-0">
                    <span className="text-sm font-black text-violet-600">#{idx + 1}</span>
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-slate-800 text-sm truncate">
                        {run.source_filename || 'Unknown file'}
                      </span>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-500 uppercase">
                        {run.pipeline_type || 'pcap'}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 mt-1.5 text-[11px] text-slate-400 font-medium">
                      <span className="flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {formatDate(run.timestamp)}
                      </span>
                      <span className="font-mono">{total} sessions</span>
                      {run.anomaly_count > 0 && (
                        <span className="text-amber-600 font-bold">
                          {run.anomaly_count} anomalies
                        </span>
                      )}
                      <span className="font-mono text-slate-500">
                        avg score: {run.avg_risk_score ?? '—'}
                      </span>
                    </div>

                    {/* Risk distribution bar */}
                    <div className="mt-2.5 max-w-xs">
                      <RiskBar summary={summary} total={total} />
                      <div className="flex gap-3 mt-1.5">
                        {['critical', 'high', 'medium', 'low'].map(level => (
                          <span
                            key={level}
                            className={`text-[10px] font-bold ${RISK_TEXT[level]}`}
                          >
                            {summary[level] || 0} {level}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleLoadRun(run.run_id)}
                      disabled={isLoading}
                      className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                        isLoading
                          ? 'bg-violet-100 text-violet-400'
                          : 'bg-gradient-to-r from-violet-500 to-indigo-500 text-white shadow-sm shadow-violet-200 hover:shadow-violet-300 hover:-translate-y-0.5'
                      }`}
                    >
                      {isLoading ? (
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full border-2 border-violet-500 border-t-transparent spin" />
                          Loading…
                        </div>
                      ) : (
                        <>
                          <svg className="w-3.5 h-3.5 inline mr-1 -mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                          </svg>
                          Load
                        </>
                      )}
                    </button>
                    <button
                      onClick={() => handleDelete(run.run_id)}
                      title="Delete this run"
                      className="w-9 h-9 flex items-center justify-center rounded-xl text-slate-400 hover:text-rose-500 hover:bg-rose-50/70 cursor-pointer transition-all opacity-0 group-hover:opacity-100"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                          d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Info footer */}
      {!loading && history.length > 0 && (
        <div className="text-center text-[11px] text-slate-400 font-medium pt-2">
          Only the last 10 analysis runs are kept. Older runs are automatically pruned.
        </div>
      )}
    </div>
  );
}
