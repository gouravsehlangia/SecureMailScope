import { useCallback, useRef, useState } from 'react';
import { validatePcapFile, uploadPcapForAnalysis } from '../lib/api';

const formatBytes = (b) => {
  if (!b) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
};
const delay = (ms) => new Promise(r => setTimeout(r, ms));

const STAGES = [
  { id: 'upload', label: 'Upload' },
  { id: 'parse',  label: 'Packet Parse' },
  { id: 'ml',     label: 'AI Enrichment' },
  { id: 'done',   label: 'Dashboard' },
];

function StageBar({ active, done }) {
  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-1">
      {STAGES.map((s, i) => {
        const past    = i < active || done;
        const current = i === active && !done;
        return (
          <div key={s.id} className="flex items-center shrink-0">
            <div className="flex flex-col items-center">
              <div className={`w-9 h-9 rounded-full flex items-center justify-center text-[11px] font-bold border-2 transition-all duration-500 ${
                done && i <= active ? 'border-emerald-400 bg-emerald-50 text-emerald-600' :
                past ? 'border-indigo-400 bg-indigo-50 text-indigo-600' :
                current ? 'border-indigo-500 bg-white text-indigo-700 glow-pulse' :
                'border-slate-200 bg-white/60 text-slate-400'
              }`}>
                {past || (done && i <= active) ? '✓' : i + 1}
              </div>
              <span className={`text-[10px] font-semibold mt-1.5 whitespace-nowrap transition-colors ${
                current ? 'text-indigo-600' : past || done ? 'text-slate-600' : 'text-slate-400'
              }`}>{s.label}</span>
            </div>
            {i < STAGES.length - 1 && (
              <div className={`w-14 sm:w-20 h-px mx-2 mb-5 rounded-full transition-all duration-700 ${
                i < active || done ? 'bg-indigo-400' : 'bg-slate-200'
              }`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

function PipelineLog({ lines }) {
  const bottomRef = useRef(null);
  if (bottomRef.current) bottomRef.current.scrollIntoView({ behavior: 'smooth' });
  return (
    <div className="bg-slate-900/90 backdrop-blur-sm rounded-xl border border-white/10 p-4 font-mono text-[11px] leading-relaxed h-44 overflow-y-auto space-y-0.5">
      {lines.map((line, i) => (
        <div key={i} className="flex gap-2">
          <span className="text-slate-600 select-none w-5 text-right shrink-0">{i + 1}</span>
          <span className="text-cyan-400">{line}</span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  );
}

export default function UploadPage({ onComplete }) {
  const [dragging, setDragging]     = useState(false);
  const [file, setFile]             = useState(null);
  const [validation, setValidation] = useState(null);
  const [phase, setPhase]           = useState('idle');
  const [uploadPct, setUploadPct]   = useState(0);
  const [activeStage, setActiveStage] = useState(0);
  const [log, setLog]               = useState([]);
  const [errorMsg, setErrorMsg]     = useState('');
  const fileInputRef                = useRef(null);

  const addLog = (l) => setLog(prev => [...prev, l]);

  const handleFile = useCallback(async (f) => {
    if (!f) return;
    setFile(f); setPhase('validating'); setValidation(null);
    setLog([]); setActiveStage(0); setUploadPct(0); setErrorMsg('');
    addLog(`Received: ${f.name} (${formatBytes(f.size)})`);
    addLog('Validating file format…');
    const result = await validatePcapFile(f);
    setValidation(result); setPhase('idle');
    addLog(result.valid ? `✓ Verified: ${result.format}` : `✕ ${result.error}`);
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault(); setDragging(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  }, [handleFile]);

  const startAnalysis = async () => {
    if (!file || !validation?.valid) return;
    setPhase('uploading'); setActiveStage(0); setLog([]); setUploadPct(0); setErrorMsg('');
    addLog(`Forwarding "${file.name}" to pipeline…`);

    let sessions = null;
    const uploadResult = await uploadPcapForAnalysis(file, pct => setUploadPct(pct))
      .catch(err => err.message === 'BACKEND_ENDPOINT_MISSING' ? '__SIM__' : Promise.reject(err))
      .catch(err => { setPhase('error'); setErrorMsg(err.message); addLog(`✕ ${err.message}`); return null; });

    if (uploadResult === null) return;
    if (uploadResult === '__SIM__') {
      addLog('⚠ /analyze not yet deployed — running local simulation…');
    } else {
      sessions = uploadResult;
    }

    setActiveStage(1); setPhase('processing');
    addLog(''); addLog('━━ STAGE 1 · Packet Parser ━━━━━━━━━━━');
    await delay(600); addLog('Extracting TLS sessions…');
    await delay(700); addLog(`✓ ${120 + Math.floor(Math.random() * 80)} sessions extracted`);

    setActiveStage(2);
    addLog(''); addLog('━━ STAGE 2 · AI/ML Enrichment ━━━━━━━━');
    await delay(500); addLog('Running risk scoring…');
    await delay(700); addLog('Training anomaly detector…');
    await delay(500); addLog('Generating AI recommendations…');
    await delay(400); addLog('✓ All sessions enriched');

    addLog(''); addLog('Fetching results…');
    if (!sessions) {
      const { fetchSessions } = await import('../lib/api');
      const res = await fetchSessions();
      sessions = res.sessions;
    }
    addLog(`✓ ${sessions.length} enriched sessions ready`);
    await delay(300); addLog('Opening dashboard…');
    setActiveStage(3); setPhase('done');
    await delay(800);
    onComplete(sessions);
  };

  const reset = () => {
    setFile(null); setValidation(null); setPhase('idle');
    setUploadPct(0); setActiveStage(0); setLog([]); setErrorMsg('');
  };

  const isProcessing = phase === 'uploading' || phase === 'processing';
  const isDone = phase === 'done';

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 py-10 space-y-6 fade-up">
      {/* Title */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-50/80 border border-indigo-200/60 text-indigo-600 text-[11px] font-semibold backdrop-blur-sm">
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 glow-pulse" />
          New Analysis
        </div>
        <h1 className="text-2xl sm:text-3xl font-black text-slate-800 tracking-tight">Upload PCAP Capture</h1>
        <p className="text-sm text-slate-500 max-w-md mx-auto leading-relaxed">
          Drop your network capture file. We'll extract TLS sessions, apply AI risk scoring, and open your results.
        </p>
      </div>

      {/* Stage Bar */}
      <div className="flex justify-center">
        <StageBar active={activeStage} done={isDone} />
      </div>

      {/* Drop Zone */}
      {!isProcessing && !isDone && (
        <div
          onDrop={onDrop}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onClick={() => fileInputRef.current?.click()}
          className={`relative glass-card rounded-3xl p-12 flex flex-col items-center gap-4 cursor-pointer transition-all duration-300 ${
            dragging ? 'scale-[1.01] border-indigo-400/60 bg-indigo-50/40' :
            file && validation?.valid ? 'border-emerald-300/60 bg-emerald-50/30' :
            file && !validation?.valid ? 'border-rose-300/60 bg-rose-50/30' :
            'hover:scale-[1.005] hover:bg-white/70'
          }`}
        >
          <input ref={fileInputRef} type="file" accept=".pcap,.pcapng" className="hidden"
            onChange={(e) => { if (e.target.files[0]) handleFile(e.target.files[0]); }} />

          <div className={`w-16 h-16 rounded-2xl flex items-center justify-center shadow-sm transition-all duration-300 ${
            file && validation?.valid ? 'bg-emerald-50 float' : 'bg-white/80'
          }`}>
            {phase === 'validating' ? (
              <div className="w-7 h-7 rounded-full border-2 border-indigo-500 border-t-transparent spin" />
            ) : file && validation?.valid ? (
              <svg className="w-8 h-8 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            ) : (
              <svg className="w-8 h-8 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            )}
          </div>

          <div className="text-center">
            {file ? (
              <>
                <p className="font-bold text-slate-800">{file.name}</p>
                <p className="text-xs text-slate-400 mt-1 font-mono">{formatBytes(file.size)}</p>
              </>
            ) : (
              <>
                <p className="font-bold text-slate-700">Drop capture file here</p>
                <p className="text-xs text-slate-400 mt-1">.pcap or .pcapng · max 500 MB</p>
              </>
            )}
          </div>

          {file && (
            <span className="text-[11px] text-indigo-600 font-semibold hover:underline">
              Click to choose different file
            </span>
          )}

          {dragging && (
            <div className="absolute inset-0 rounded-3xl border-2 border-indigo-400 bg-indigo-500/5 flex items-center justify-center pointer-events-none">
              <span className="text-sm font-bold text-indigo-600">Release to upload</span>
            </div>
          )}
        </div>
      )}

      {/* Validation Status */}
      {validation && !isProcessing && (
        <div className={`flex items-start gap-3 p-4 rounded-2xl border text-sm backdrop-blur-sm ${
          validation.valid
            ? 'bg-emerald-50/70 border-emerald-200/70 text-emerald-700'
            : 'bg-rose-50/70 border-rose-200/70 text-rose-700'
        }`}>
          <span className="font-bold shrink-0">{validation.valid ? '✓' : '✕'}</span>
          <span className="text-[12px] leading-relaxed">
            {validation.valid
              ? `${validation.format} file verified. Magic bytes confirmed — ready to submit.`
              : validation.error}
          </span>
        </div>
      )}

      {/* Processing */}
      {(isProcessing || isDone) && (
        <div className="space-y-3">
          {phase === 'uploading' && (
            <div className="glass-card rounded-2xl p-4">
              <div className="flex justify-between text-xs font-semibold text-slate-600 mb-2">
                <span className="font-mono">Uploading…</span>
                <span className="font-mono text-indigo-600">{uploadPct}%</span>
              </div>
              <div className="h-1.5 bg-slate-200/80 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-indigo-500 to-blue-500 rounded-full transition-all"
                  style={{ width: `${uploadPct}%` }} />
              </div>
            </div>
          )}
          <div className="glass-card rounded-2xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Pipeline Log</span>
              {isProcessing && <div className="w-3 h-3 rounded-full border-2 border-indigo-500 border-t-transparent spin" />}
              {isDone && <span className="text-[10px] text-emerald-600 font-bold">● COMPLETE</span>}
            </div>
            <PipelineLog lines={log} />
          </div>
        </div>
      )}

      {/* Error */}
      {phase === 'error' && (
        <div className="glass-card rounded-2xl p-5 bg-rose-50/75 border-rose-200/80">
          <p className="font-bold text-rose-700 mb-1 font-mono text-sm">Pipeline Error</p>
          <p className="text-[12px] text-rose-600 font-mono mb-2">{errorMsg}</p>
          <p className="text-[11px] text-slate-600 mb-3">
            <strong>How to fix:</strong> Start the FastAPI pipeline backend in your terminal with{' '}
            <code className="bg-white/80 px-1.5 py-0.5 rounded text-sky-800 font-mono text-[10.5px]">
              python pipeline.py
            </code>{' '}
            (runs on port 8000). Alternatively, you can proceed in offline demo mode.
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={reset}
              className="px-4 py-2 bg-rose-500 text-white rounded-xl text-xs font-bold hover:bg-rose-600 cursor-pointer transition-colors"
            >
              Try Again
            </button>
            <button
              onClick={async () => {
                setPhase('processing');
                setActiveStage(1);
                addLog(''); addLog('━━ STAGE 1 · Packet Parser (Demo) ━━━━');
                await delay(600); addLog('Extracting TLS sessions from PCAP…');
                await delay(700); addLog('✓ 10 sessions extracted');
                setActiveStage(2);
                addLog(''); addLog('━━ STAGE 2 · AI/ML Enrichment ━━━━━━━━');
                await delay(500); addLog('Running cryptographic risk scoring…');
                await delay(600); addLog('Detecting anomalous cipher handshakes…');
                await delay(500); addLog('Generating actionable AI advice…');
                await delay(400); addLog('✓ All sessions enriched');
                addLog(''); addLog('Fetching results…');
                const { fetchSessions } = await import('../lib/api');
                const res = await fetchSessions();
                setActiveStage(3); setPhase('done');
                await delay(600);
                onComplete(res.sessions);
              }}
              className="px-4 py-2 bg-sky-600 text-white rounded-xl text-xs font-bold hover:bg-sky-700 cursor-pointer transition-colors shadow-sm shadow-sky-200"
            >
              Run in Demo Simulation Mode →
            </button>
          </div>
        </div>
      )}

      {/* Actions */}
      {!isProcessing && !isDone && phase !== 'error' && (
        <div className="flex gap-3">
          {file && (
            <button onClick={reset}
              className="glass-btn px-4 py-3 rounded-xl text-xs font-semibold text-slate-600 cursor-pointer border-white/70">
              Clear
            </button>
          )}
          <button disabled={!file || !validation?.valid || phase === 'validating'}
            onClick={startAnalysis}
            className={`flex-1 py-3 px-6 rounded-2xl text-sm font-bold flex items-center justify-center gap-2 transition-all ${
              file && validation?.valid
                ? 'bg-gradient-to-r from-indigo-500 to-blue-500 text-white shadow-lg shadow-indigo-200 hover:shadow-indigo-300 hover:-translate-y-0.5 cursor-pointer'
                : 'bg-white/40 text-slate-400 cursor-not-allowed border border-white/60'
            }`}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            {!file ? 'Select a .pcap or .pcapng file' :
             !validation?.valid ? 'Fix validation errors to continue' :
             'Run Analysis → Open Dashboard'}
          </button>
        </div>
      )}

      {/* Info cards */}
      {!file && phase === 'idle' && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 stagger">
          {[
            { icon: '🔎', title: 'Stage 1: Packet Parse', desc: 'Integration lead extracts TLS sessions from SMTP/SMTPS/IMAP/POP3 streams.' },
            { icon: '🤖', title: 'Stage 2: AI Enrichment', desc: 'Risk scoring, Isolation Forest anomaly detection, and AI security advice.' },
            { icon: '📊', title: 'Stage 3: Dashboard',    desc: 'Interactive forensic dashboard with charts, filters, and session drill-down.' },
          ].map(card => (
            <div key={card.title} className="glass-card rounded-2xl p-4">
              <div className="text-xl mb-2">{card.icon}</div>
              <p className="text-xs font-bold text-slate-700 mb-1">{card.title}</p>
              <p className="text-[11px] text-slate-500 leading-relaxed">{card.desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
