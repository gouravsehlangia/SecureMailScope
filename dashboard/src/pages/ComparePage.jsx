import { useRef, useState } from 'react';
import { validatePcapFile, uploadPcapForAnalysis } from '../lib/api';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const SORDER    = ['critical', 'high', 'medium', 'low'];
const DS_COLORS = ['#6366f1', '#06b6d4', '#f472b6', '#a78bfa', '#34d399', '#f59e0b'];
const TOOLTIP_STYLE = {
  background: 'rgba(255,255,255,0.85)', backdropFilter: 'blur(12px)',
  border: '1px solid rgba(255,255,255,0.9)', borderRadius: '12px',
  fontSize: 12, color: '#334155', padding: '8px 14px',
  boxShadow: '0 8px 32px rgba(99,102,241,0.12)',
};

const fmtBytes = (b) => {
  if (!b) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(2)} MB`;
};

function computeMetrics(sessions) {
  const t = sessions.length;
  if (!t) return null;
  return {
    total:      t,
    critical:   sessions.filter(s => s.risk_level === 'critical').length,
    high:       sessions.filter(s => s.risk_level === 'high').length,
    medium:     sessions.filter(s => s.risk_level === 'medium').length,
    low:        sessions.filter(s => s.risk_level === 'low').length,
    anomalies:  sessions.filter(s => s.anomaly_flag).length,
    avgScore:   Math.round(sessions.reduce((a, s) => a + (s.risk_score || 0), 0) / t),
    noPfs:      sessions.filter(s => !s.forward_secrecy).length,
    tls13:      sessions.filter(s => s.tls_version === 'TLS 1.3').length,
    certIssues: sessions.filter(s => s.cert_expired || !s.cert_chain_valid).length,
  };
}

// ── Single upload slot — uploads to REAL backend, NO demo fallback ────────────
function UploadSlot({ index, color, onReady, onClear, ready }) {
  const [dragging,   setDragging]   = useState(false);
  const [uploading,  setUploading]  = useState(false);
  const [progress,   setProgress]   = useState(0);
  const [file,       setFile]       = useState(null);
  const [validation, setValidation] = useState(null);
  const [error,      setError]      = useState(null);
  const ref = useRef(null);

  const handleFile = async (f) => {
    setFile(f);
    setError(null);
    setValidation(null);
    onClear(index);
    const v = await validatePcapFile(f);
    setValidation(v);
    if (!v.valid) setError(v.error);
  };

  const handleUpload = async () => {
    if (!file || !validation?.valid) return;
    setUploading(true);
    setProgress(0);
    setError(null);

    try {
      const res = await uploadPcapForAnalysis(file, (pct) => setProgress(pct));

      // Strict check — require real sessions from the backend
      if (!res || !Array.isArray(res.sessions) || res.sessions.length === 0) {
        setError(
          'Backend returned no sessions. Ensure the PCAP contains SMTP/IMAP/POP3 traffic and the pipeline is running.'
        );
        setUploading(false);
        return;
      }

      setUploading(false);
      onReady(index, {
        label:     file.name.replace(/\.(pcap|pcapng)$/i, ''),
        sessions:  res.sessions,
        timestamp: new Date().toLocaleTimeString('en-US', {
          hour: '2-digit', minute: '2-digit', second: '2-digit',
        }),
        metadata:  res.metadata || null,
      });
    } catch (err) {
      setUploading(false);
      // Surface the real error — no silent fallback to demo data
      if (err.message === 'BACKEND_ENDPOINT_MISSING') {
        setError('Backend /analyze endpoint not found. Make sure FastAPI (pipeline.py) is running on port 8000.');
      } else if (err.message?.includes('Network error')) {
        setError('Cannot reach backend. Run: python pipeline.py');
      } else {
        setError(err.message || 'Unknown backend error.');
      }
    }
  };

  const handleClear = () => {
    setFile(null);
    setValidation(null);
    setError(null);
    setProgress(0);
    onClear(index);
  };

  return (
    <div
      onDrop={(e) => { e.preventDefault(); setDragging(false); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); }}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      className={`glass-card rounded-2xl p-5 flex flex-col items-center justify-center gap-3 min-h-[180px] cursor-pointer transition-all duration-300
        ${dragging ? 'scale-[1.02] ring-2 ring-indigo-400/60' : ''}
        ${ready    ? 'ring-2 ring-emerald-400/60' : ''}
      `}
    >
      <input ref={ref} type="file" accept=".pcap,.pcapng" className="hidden"
        onChange={(e) => { if (e.target.files[0]) handleFile(e.target.files[0]); }} />

      <div className="w-6 h-6 rounded-full shrink-0" style={{ backgroundColor: color }} />

      {uploading ? (
        <div className="flex flex-col items-center gap-2 w-full">
          <div className="w-5 h-5 rounded-full border-2 border-indigo-500 border-t-transparent spin" />
          <p className="text-[10.5px] font-semibold text-slate-500">Uploading & analyzing… {progress}%</p>
          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className="h-1.5 bg-gradient-to-r from-indigo-500 to-sky-400 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      ) : ready ? (
        <div className="flex flex-col items-center gap-1 text-center">
          <span className="text-emerald-600 text-lg">✓</span>
          <p className="text-xs font-bold text-slate-700">{file?.name}</p>
          <p className="text-[10px] text-emerald-600 font-semibold">Analysis complete</p>
          <button onClick={handleClear}
            className="mt-1 px-2 py-1 rounded-lg text-[10px] font-semibold text-slate-500 glass-btn cursor-pointer hover:text-rose-500">
            Remove
          </button>
        </div>
      ) : file ? (
        <>
          <p className="text-xs font-bold text-slate-700 text-center">{file.name}</p>
          <p className="text-[10px] text-slate-400 font-mono">{fmtBytes(file.size)}</p>

          {validation && (
            <p className={`text-[10px] font-semibold text-center ${validation.valid ? 'text-emerald-600' : 'text-rose-600'}`}>
              {validation.valid ? `✓ ${validation.format}` : '✕ ' + validation.error}
            </p>
          )}

          {error && (
            <p className="text-[10px] text-rose-600 font-semibold text-center max-w-[180px]">{error}</p>
          )}

          <div className="flex gap-2">
            <button onClick={handleUpload} disabled={!validation?.valid}
              className={`px-3 py-1.5 rounded-xl text-[11px] font-bold cursor-pointer transition-all ${
                validation?.valid
                  ? 'bg-gradient-to-r from-indigo-500 to-blue-500 text-white shadow-sm hover:shadow-indigo-200'
                  : 'bg-slate-100 text-slate-400 cursor-not-allowed'
              }`}>
              Analyze Capture
            </button>
            <button onClick={handleClear}
              className="px-2 py-1.5 rounded-xl text-[11px] font-semibold text-slate-500 glass-btn cursor-pointer">
              Clear
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="text-xs font-semibold text-slate-500">Capture Slot {index + 1}</p>
          <button onClick={() => ref.current?.click()}
            className="px-3 py-1.5 rounded-xl text-[11px] font-semibold text-indigo-600 border border-indigo-200/60 hover:bg-indigo-50 cursor-pointer transition-all">
            Browse File
          </button>
          <p className="text-[10px] text-slate-400">.pcap or .pcapng</p>
        </>
      )}
    </div>
  );
}

// ── Grade helper ──────────────────────────────────────────────────────────────
const getGrade = (score) => {
  if (score <= 10) return { g: 'A+', c: 'text-emerald-600' };
  if (score <= 20) return { g: 'A',  c: 'text-emerald-600' };
  if (score <= 35) return { g: 'B',  c: 'text-blue-600' };
  if (score <= 50) return { g: 'C',  c: 'text-amber-600' };
  if (score <= 65) return { g: 'D',  c: 'text-orange-600' };
  return { g: 'F', c: 'text-rose-600' };
};

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ComparePage() {
  const [slots,      setSlots]      = useState(2);
  // readySlots[slotIdx] = { label, sessions, timestamp, metadata }
  const [readySlots, setReadySlots] = useState({});
  const [datasets,   setDatasets]   = useState([]);
  const [compared,   setCompared]   = useState(false);

  const numReady   = Object.keys(readySlots).length;
  const canCompare = numReady >= 2;

  const handleSlotReady = (idx, data) => {
    setReadySlots(prev => ({ ...prev, [idx]: data }));
    // Reset old comparison whenever a slot changes
    setCompared(false);
    setDatasets([]);
  };

  const handleSlotClear = (idx) => {
    setReadySlots(prev => {
      const copy = { ...prev };
      delete copy[idx];
      return copy;
    });
    setCompared(false);
    setDatasets([]);
  };

  const handleCompare = () => {
    const built = Object.entries(readySlots).map(([idx, data], i) => ({
      id:        `ds-${idx}`,
      slotIdx:   Number(idx),
      label:     data.label,
      sessions:  data.sessions,
      metrics:   computeMetrics(data.sessions),
      color:     DS_COLORS[i % DS_COLORS.length],
      timestamp: data.timestamp,
      metadata:  data.metadata,
    }));
    setDatasets(built);
    setCompared(true);
    setTimeout(() => {
      document.getElementById('comparison-results')?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  const riskChart = SORDER.map(level => {
    const entry = { name: level.charAt(0).toUpperCase() + level.slice(1) };
    datasets.forEach(d => { entry[d.label] = d.metrics?.[level] || 0; });
    return entry;
  });

  return (
    <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5 fade-up">

      {/* ── Title ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-slate-800 tracking-tight">Multi-Capture Security Comparison</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Upload PCAP/PCAPNG captures to evaluate side-by-side posture metrics.
          </p>
        </div>
        <button onClick={() => setSlots(n => Math.min(n + 1, 6))} disabled={slots >= 6}
          className="glass-btn px-3 py-2 rounded-xl text-xs font-bold text-indigo-600 border border-indigo-200/60 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed self-start sm:self-auto">
          + Add Slot
        </button>
      </div>

      {/* ── Upload Slots ── */}
      <div className={`grid gap-3 ${
        slots <= 2 ? 'grid-cols-1 sm:grid-cols-2' :
        slots <= 4 ? 'grid-cols-2 sm:grid-cols-4' :
        'grid-cols-2 sm:grid-cols-3 lg:grid-cols-6'
      } stagger`}>
        {Array.from({ length: slots }).map((_, i) => (
          <UploadSlot
            key={i}
            index={i}
            color={DS_COLORS[i % DS_COLORS.length]}
            ready={!!readySlots[i]}
            onReady={handleSlotReady}
            onClear={handleSlotClear}
          />
        ))}
      </div>

      {/* ── Status bar + Compare button ── */}
      <div className={`flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 px-5 py-4 rounded-2xl border transition-all ${
        canCompare ? 'bg-gradient-to-r from-indigo-50 to-sky-50 border-indigo-200' : 'bg-slate-50 border-slate-200'
      }`}>
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${canCompare ? 'bg-emerald-500 glow-pulse' : 'bg-slate-300'}`} />
          <span className="text-xs font-bold text-slate-700">
            {numReady === 0 && 'Analyze at least 2 PCAP captures to compare.'}
            {numReady === 1 && '1 capture analyzed — analyze 1 more to compare.'}
            {numReady >= 2 && `${numReady} captures ready — click Compare to generate results.`}
          </span>
        </div>

        {/* ══ THE COMPARE BUTTON ══ */}
        <button
          id="compare-btn"
          onClick={handleCompare}
          disabled={!canCompare}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold transition-all ${
            canCompare
              ? 'bg-gradient-to-r from-indigo-500 via-blue-500 to-sky-500 text-white shadow-lg shadow-indigo-200/60 hover:shadow-indigo-300/80 hover:scale-[1.02] active:scale-100 cursor-pointer'
              : 'bg-slate-100 text-slate-400 cursor-not-allowed'
          }`}
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5"
              d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          Compare {canCompare ? `${numReady} Captures` : 'Captures'}
        </button>
      </div>

      {/* ── Comparison Results ── */}
      {compared && datasets.length >= 2 ? (
        <div id="comparison-results" className="space-y-5 pt-2">

          {/* Compared captures legend */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-bold text-slate-500 mr-1">Compared Captures:</span>
            {datasets.map(d => (
              <div key={d.id} className="flex items-center gap-2 px-3 py-1.5 rounded-full glass border border-white/70 shadow-sm">
                <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                <span className="text-xs font-bold text-slate-700">{d.label}</span>
                {d.timestamp && <span className="text-[10px] text-slate-400 font-mono">({d.timestamp})</span>}
                {d.metadata?.session_count != null && (
                  <span className="text-[10px] text-slate-400">{d.metadata.session_count} sessions</span>
                )}
              </div>
            ))}
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 stagger">
            {[
              { label: 'Sessions',       key: 'total' },
              { label: 'Critical Risk',  key: 'critical' },
              { label: 'AI Anomalies',   key: 'anomalies' },
              { label: 'Avg Risk Score', key: 'avgScore' },
              { label: 'No PFS',         key: 'noPfs' },
            ].map(metric => (
              <div key={metric.label} className="glass-card rounded-2xl p-4">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">{metric.label}</p>
                <div className="space-y-2">
                  {datasets.map(d => (
                    <div key={d.id} className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                      <span className="text-[11px] text-slate-500 truncate flex-1">{d.label}</span>
                      <span className="font-mono text-xs font-bold text-slate-800">{d.metrics?.[metric.key] ?? '—'}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-bold text-slate-800 mb-1">Risk Level Distribution</h3>
              <p className="text-[11px] text-slate-400 mb-4">Sessions per severity across captures</p>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={riskChart} margin={{ left: -20, right: 8, top: 8, bottom: 0 }}>
                    <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={{ stroke: 'rgba(148,163,184,0.2)' }} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(99,102,241,0.04)', rx: 8 }} />
                    <Legend formatter={v => <span style={{ fontSize: 11, color: '#64748b' }}>{v}</span>} />
                    {datasets.map(d => (
                      <Bar key={d.id} dataKey={d.label} fill={d.color} radius={[6, 6, 0, 0]} maxBarSize={28} fillOpacity={0.85} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-3 border-b border-white/60">
                <h3 className="text-sm font-bold text-slate-800">Full Metrics Breakdown</h3>
              </div>
              <div className="divide-y divide-white/50 overflow-y-auto max-h-80">
                {[
                  ['Total Sessions', 'total'],    ['Critical', 'critical'],   ['High', 'high'],
                  ['Medium', 'medium'],            ['Low', 'low'],             ['Anomalies', 'anomalies'],
                  ['Avg Risk Score', 'avgScore'],  ['No PFS', 'noPfs'],        ['TLS 1.3', 'tls13'],
                  ['Cert Issues', 'certIssues'],
                ].map(([label, key]) => (
                  <div key={key} className="flex items-center gap-3 px-5 py-2.5">
                    <span className="text-[11px] text-slate-400 font-semibold w-36 shrink-0">{label}</span>
                    <div className="flex items-center gap-4 flex-wrap">
                      {datasets.map(d => (
                        <div key={d.id} className="flex items-center gap-1.5">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                          <span className="font-mono text-xs font-bold text-slate-700">{d.metrics?.[key] ?? '—'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Grade Cards */}
          <div className="glass-card rounded-2xl p-5">
            <h3 className="text-sm font-bold text-slate-800 mb-3">Security Posture Grades</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {datasets.map(d => {
                const { g, c } = getGrade(d.metrics.avgScore);
                return (
                  <div key={d.id} className="flex items-center gap-4 p-4 rounded-xl glass border border-white/70">
                    <div className={`text-4xl font-black font-mono ${c}`}>{g}</div>
                    <div>
                      <p className="font-bold text-slate-800 text-sm">{d.label}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        {d.metrics.critical} critical · {d.metrics.anomalies} anomalies · score {d.metrics.avgScore}
                      </p>
                      <p className="text-[10px] text-slate-400 mt-0.5">{d.metrics.total} sessions analyzed</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Reset CTA */}
          <div className="flex justify-center pt-2">
            <button
              onClick={() => { setCompared(false); setDatasets([]); setReadySlots({}); }}
              className="px-4 py-2 rounded-xl text-xs font-bold text-slate-500 glass-btn border border-slate-200 hover:text-indigo-600 cursor-pointer transition-colors"
            >
              ↺ Start New Comparison
            </button>
          </div>
        </div>
      ) : (
        !compared && numReady < 2 && (
          <div className="glass-card rounded-2xl py-16 text-center space-y-3">
            <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-500 mx-auto flex items-center justify-center text-xl font-bold">⊞</div>
            <p className="text-sm font-extrabold text-slate-700">Add at least 2 PCAP captures to compare side-by-side</p>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Upload <code>.pcap</code> or <code>.pcapng</code> files into the slots above,
              click <strong>"Analyze Capture"</strong> on each, then hit <strong>"Compare Captures"</strong>.
            </p>
          </div>
        )
      )}
    </div>
  );
}
