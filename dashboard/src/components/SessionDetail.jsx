import { useEffect } from 'react';
import SeverityBadge from './SeverityBadge';

function Row({ label, value, mono, accent }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5 border-b border-white/50 last:border-0">
      <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider shrink-0">{label}</span>
      <span className={`text-right text-xs font-medium text-slate-700 ${mono ? 'font-mono text-[11px]' : ''} ${accent || ''} break-all`}>
        {value}
      </span>
    </div>
  );
}

export default function SessionDetail({ session: s, onClose }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [onClose]);

  if (!s) return null;
  const certOk = !s.cert_expired && s.cert_chain_valid;
  const scoreColor = s.risk_score >= 75 ? 'text-rose-600' : s.risk_score >= 50 ? 'text-orange-500' : s.risk_score >= 25 ? 'text-amber-500' : 'text-emerald-600';
  const scoreGradient = s.risk_score >= 75 ? 'from-rose-400 to-rose-600' : s.risk_score >= 50 ? 'from-orange-400 to-orange-500' : s.risk_score >= 25 ? 'from-amber-400 to-amber-500' : 'from-emerald-400 to-emerald-500';

  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 z-40 bg-slate-900/30 backdrop-blur-sm" onClick={onClose} />
      {/* Drawer */}
      <aside className="fixed inset-y-0 right-0 z-50 w-full sm:w-[440px] flex flex-col glass-strong border-l border-white/80">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/60">
          <div>
            <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-0.5">Session Detail</p>
            <h2 className="text-sm font-bold font-mono text-slate-800">{s.session_id}</h2>
          </div>
          <div className="flex items-center gap-2">
            <SeverityBadge level={s.risk_level} />
            <button onClick={onClose}
              className="glass-btn w-8 h-8 rounded-xl flex items-center justify-center text-slate-400 hover:text-slate-700 cursor-pointer">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Risk Hero */}
          <div className="glass rounded-xl p-4">
            <div className="flex items-end justify-between mb-3">
              <div>
                <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Risk Score</p>
                <p className={`text-4xl font-black font-mono mt-1 ${scoreColor}`}>{s.risk_score}</p>
                <p className="text-[10px] text-slate-400 mt-0.5 font-mono">/ 100</p>
              </div>
              {s.anomaly_flag && (
                <div className="px-3 py-1.5 rounded-xl bg-indigo-50 border border-indigo-200 text-xs font-bold text-indigo-700">
                  ⚡ AI Anomaly
                </div>
              )}
            </div>
            <div className="h-2 bg-slate-200/80 rounded-full overflow-hidden">
              <div className={`h-full rounded-full bg-gradient-to-r ${scoreGradient}`}
                style={{ width: `${s.risk_score}%`, transition: 'width 0.8s cubic-bezier(0.16,1,0.3,1)' }} />
            </div>
          </div>

          {/* Properties */}
          <div className="glass rounded-xl p-4">
            <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-2">Session Properties</p>
            <Row label="Protocol"  value={`${s.protocol}${s.starttls_used ? ' (STARTTLS)' : ''}`} mono />
            <Row label="TLS"       value={s.tls_version} mono
              accent={s.tls_version === 'TLS 1.3' ? 'text-emerald-600' : s.tls_version === 'TLS 1.2' ? 'text-indigo-600' : 'text-orange-500'} />
            <Row label="Cipher"    value={s.cipher_suite} mono />
            <Row label="Key Exch"  value={s.key_exchange || '—'} mono />
            <Row label="PFS"       value={s.forward_secrecy ? '✓ Enabled' : '✕ Disabled'}
              accent={s.forward_secrecy ? 'text-emerald-600' : 'text-rose-600'} />
            <Row label="Handshake" value={`${s.handshake_duration_ms} ms`} mono />
          </div>

          {/* Certificate */}
          <div className="glass rounded-xl p-4">
            <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-2">Certificate</p>
            <Row label="Status"  value={certOk ? '✓ Valid Chain' : '✕ Issue Found'}
              accent={certOk ? 'text-emerald-600' : 'text-rose-600'} />
            <Row label="Expired" value={s.cert_expired ? '✕ Expired' : '✓ Valid'}
              accent={s.cert_expired ? 'text-rose-600' : 'text-emerald-600'} />
            <Row label="Key Len" value={`${s.cert_key_length} bits`} mono />
          </div>

          {/* Violations */}
          {s.rule_violations?.length > 0 && (
            <div className="rounded-xl p-4 bg-rose-50/80 border border-rose-200/60 backdrop-blur-sm">
              <p className="text-[10px] uppercase tracking-widest text-rose-500 font-bold mb-2">
                Violations ({s.rule_violations.length})
              </p>
              <ul className="space-y-1.5">
                {s.rule_violations.map((v, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-rose-700">
                    <span className="font-bold shrink-0 mt-px text-rose-500">✕</span>{v}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* AI Recs */}
          {s.recommendations?.length > 0 && (
            <div className="rounded-xl p-4 bg-indigo-50/80 border border-indigo-200/60 backdrop-blur-sm">
              <p className="text-[10px] uppercase tracking-widest text-indigo-500 font-bold mb-2">
                AI Recommendations
              </p>
              <ul className="space-y-2">
                {s.recommendations.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-indigo-800 leading-relaxed">
                    <span className="text-indigo-400 font-bold shrink-0 mt-px">→</span>{r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-white/60">
          <button onClick={onClose}
            className="w-full py-2 rounded-xl text-xs font-semibold text-slate-500 hover:text-slate-800 glass-btn border-white/60 cursor-pointer transition-all">
            Close · Esc
          </button>
        </div>
      </aside>
    </>
  );
}
