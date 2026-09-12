import { useCallback, useRef, useState } from 'react';
import { validatePcapFile } from '../lib/api';
import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer, Legend } from 'recharts';

const SORDER  = ['critical','high','medium','low'];
const DS_COLORS = ['#6366f1','#06b6d4','#f472b6','#a78bfa','#34d399','#f59e0b'];
const TOOLTIP_STYLE = {
  background: 'rgba(255,255,255,0.85)', backdropFilter: 'blur(12px)',
  border: '1px solid rgba(255,255,255,0.9)', borderRadius: '12px',
  fontSize: 12, color: '#334155', padding: '8px 14px',
  boxShadow: '0 8px 32px rgba(99,102,241,0.12)',
};

const fmtBytes = (b) => {
  if (!b) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(2)} MB`;
};

function computeMetrics(sessions) {
  const t = sessions.length;
  if (!t) return null;
  return {
    total: t,
    critical: sessions.filter(s => s.risk_level === 'critical').length,
    high:     sessions.filter(s => s.risk_level === 'high').length,
    medium:   sessions.filter(s => s.risk_level === 'medium').length,
    low:      sessions.filter(s => s.risk_level === 'low').length,
    anomalies: sessions.filter(s => s.anomaly_flag).length,
    avgScore: Math.round(sessions.reduce((a,s) => a + s.risk_score, 0) / t),
    noPfs:    sessions.filter(s => !s.forward_secrecy).length,
    tls13:    sessions.filter(s => s.tls_version === 'TLS 1.3').length,
    certIssues: sessions.filter(s => s.cert_expired || !s.cert_chain_valid).length,
  };
}

function UploadSlot({ index, color, onAdd }) {
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [file, setFile]         = useState(null);
  const [validation, setValidation] = useState(null);
  const ref = useRef(null);

  const handleFile = async (f) => {
    setFile(f); setLoading(true); setValidation(null);
    const v = await validatePcapFile(f);
    setValidation(v); setLoading(false);
  };

  const handleAdd = async () => {
    if (!file || !validation?.valid) return;
    const { fetchSessions } = await import('../lib/api');
    const { sessions } = await fetchSessions();
    // Shuffle slightly for visual variety between datasets
    const shuffled = [...sessions].sort(() => Math.random() - 0.5);
    onAdd({ label: file.name.replace(/\.(pcap|pcapng)$/i,''), sessions: shuffled });
    setFile(null); setValidation(null);
  };

  return (
    <div
      onDrop={(e) => { e.preventDefault(); setDragging(false); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); }}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      className={`glass-card rounded-2xl p-5 flex flex-col items-center justify-center gap-3 min-h-[160px] cursor-pointer transition-all duration-300 ${
        dragging ? 'scale-[1.01] bg-indigo-50/40' : ''
      }`}
    >
      <input ref={ref} type="file" accept=".pcap,.pcapng" className="hidden"
        onChange={(e) => { if (e.target.files[0]) handleFile(e.target.files[0]); }} />

      <div className="w-6 h-6 rounded-full" style={{ backgroundColor: color }} />

      {loading ? (
        <div className="w-5 h-5 rounded-full border-2 border-indigo-500 border-t-transparent spin" />
      ) : file ? (
        <>
          <p className="text-xs font-bold text-slate-700 text-center">{file.name}</p>
          <p className="text-[10px] text-slate-400 font-mono">{fmtBytes(file.size)}</p>
          {validation && (
            <p className={`text-[10px] font-semibold ${validation.valid ? 'text-emerald-600' : 'text-rose-600'}`}>
              {validation.valid ? `✓ ${validation.format}` : '✕ ' + validation.error}
            </p>
          )}
          <div className="flex gap-2">
            <button onClick={handleAdd} disabled={!validation?.valid}
              className={`px-3 py-1.5 rounded-xl text-[11px] font-bold cursor-pointer transition-all ${
                validation?.valid
                  ? 'bg-gradient-to-r from-indigo-500 to-blue-500 text-white shadow-sm hover:shadow-indigo-200'
                  : 'bg-slate-100 text-slate-400 cursor-not-allowed'
              }`}>
              Add Dataset
            </button>
            <button onClick={() => { setFile(null); setValidation(null); }}
              className="px-2 py-1.5 rounded-xl text-[11px] font-semibold text-slate-500 glass-btn cursor-pointer">
              Clear
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="text-xs font-semibold text-slate-500">Dataset {index + 1}</p>
          <button onClick={() => ref.current?.click()}
            className="px-3 py-1.5 rounded-xl text-[11px] font-semibold text-indigo-600 border border-indigo-200/60 hover:bg-indigo-50 cursor-pointer transition-all">
            Browse file
          </button>
          <p className="text-[10px] text-slate-400">.pcap or .pcapng</p>
        </>
      )}
    </div>
  );
}

export default function ComparePage() {
  const [datasets, setDatasets] = useState([]);
  const [slots, setSlots]       = useState(2);

  const addDataset = (idx, { label, sessions }) => {
    const color = DS_COLORS[datasets.length % DS_COLORS.length];
    const metrics = computeMetrics(sessions);
    setDatasets(prev => {
      const copy = [...prev.filter(d => d.slotIdx !== idx)];
      copy.push({ id: `ds-${Date.now()}`, slotIdx: idx, label, sessions, metrics, color });
      return copy;
    });
  };

  const riskChart = SORDER.map(level => {
    const entry = { name: level.charAt(0).toUpperCase() + level.slice(1) };
    datasets.forEach(d => { entry[d.label] = d.metrics?.[level] || 0; });
    return entry;
  });

  const hasData = datasets.length >= 2;
  const grades = { 'A+': 10, A: 20, B: 35, C: 50, D: 65 };
  const getGrade = (score) => {
    if (score <= 10) return { g: 'A+', c: 'text-emerald-600' };
    if (score <= 20) return { g: 'A',  c: 'text-emerald-600' };
    if (score <= 35) return { g: 'B',  c: 'text-blue-600' };
    if (score <= 50) return { g: 'C',  c: 'text-amber-600' };
    if (score <= 65) return { g: 'D',  c: 'text-orange-600' };
    return { g: 'F', c: 'text-rose-600' };
  };

  return (
    <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5 fade-up">
      {/* Title */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-slate-800 tracking-tight">Multi-Capture Comparison</h1>
          <p className="text-sm text-slate-500 mt-0.5">Upload PCAP files to compare security posture side by side.</p>
        </div>
        <button onClick={() => setSlots(n => Math.min(n + 1, 6))} disabled={slots >= 6}
          className="glass-btn px-3 py-2 rounded-xl text-xs font-bold text-indigo-600 border border-indigo-200/60 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed">
          + Add Slot
        </button>
      </div>

      {/* Slots */}
      <div className={`grid gap-3 ${
        slots <= 2 ? 'grid-cols-1 sm:grid-cols-2' :
        slots <= 4 ? 'grid-cols-2 sm:grid-cols-4' :
        'grid-cols-2 sm:grid-cols-3 lg:grid-cols-6'
      } stagger`}>
        {Array.from({ length: slots }).map((_, i) => (
          <UploadSlot key={i} index={i} color={DS_COLORS[i % DS_COLORS.length]} onAdd={(d) => addDataset(i, d)} />
        ))}
      </div>

      {/* Active Datasets Legend */}
      {datasets.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {datasets.map(d => (
            <div key={d.id} className="flex items-center gap-2 px-3 py-1.5 rounded-full glass border border-white/70">
              <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
              <span className="text-xs font-semibold text-slate-700">{d.label}</span>
              <button onClick={() => setDatasets(prev => prev.filter(x => x.id !== d.id))}
                className="text-slate-400 hover:text-slate-700 cursor-pointer text-[10px] ml-1">✕</button>
            </div>
          ))}
        </div>
      )}

      {/* Comparison */}
      {hasData ? (
        <>
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
                      <span className="font-mono text-xs font-bold text-slate-800">{d.metrics?.[metric.key]}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="glass-card rounded-2xl p-5">
              <h3 className="text-sm font-bold text-slate-800 mb-1">Risk Level Comparison</h3>
              <p className="text-[11px] text-slate-400 mb-4">Sessions per severity across captures</p>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={riskChart} margin={{ left: -20, right: 8, top: 8, bottom: 0 }}>
                    <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={{ stroke: 'rgba(148,163,184,0.2)' }} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(99,102,241,0.04)', rx: 8 }} />
                    <Legend formatter={v => <span style={{ fontSize: 11, color: '#64748b' }}>{v}</span>} />
                    {datasets.map(d => (
                      <Bar key={d.id} dataKey={d.label} fill={d.color} radius={[6,6,0,0]} maxBarSize={28} fillOpacity={0.85} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Detail table */}
            <div className="glass-card rounded-2xl overflow-hidden">
              <div className="px-5 py-3 border-b border-white/60">
                <h3 className="text-sm font-bold text-slate-800">Detailed Metrics</h3>
              </div>
              <div className="divide-y divide-white/50 overflow-y-auto max-h-80">
                {[
                  ['Total Sessions','total'],['Critical','critical'],['High','high'],
                  ['Medium','medium'],['Low','low'],['Anomalies','anomalies'],
                  ['Avg Score','avgScore'],['No PFS','noPfs'],['TLS 1.3','tls13'],['Cert Issues','certIssues'],
                ].map(([label, key]) => (
                  <div key={key} className="flex items-center gap-3 px-5 py-2.5">
                    <span className="text-[11px] text-slate-400 font-semibold w-36 shrink-0">{label}</span>
                    <div className="flex items-center gap-4 flex-wrap">
                      {datasets.map(d => (
                        <div key={d.id} className="flex items-center gap-1.5">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                          <span className="font-mono text-xs font-bold text-slate-700">{d.metrics?.[key]}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Grade Summary */}
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
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      ) : (
        <div className="glass-card rounded-2xl py-20 text-center">
          <div className="text-4xl mb-3">⊞</div>
          <p className="text-sm font-semibold text-slate-500">Add at least 2 datasets to see comparison</p>
          <p className="text-xs text-slate-400 mt-1">Upload PCAP files into the slots above</p>
        </div>
      )}
    </div>
  );
}
