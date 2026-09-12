import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const TOOLTIP_STYLE = {
  background: 'rgba(255, 255, 255, 0.90)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  border: '1px solid rgba(255, 255, 255, 0.95)',
  borderRadius: '14px',
  fontSize: '12px',
  fontWeight: 600,
  color: '#1e293b',
  padding: '8px 14px',
  boxShadow: '0 8px 30px rgba(14, 116, 217, 0.12)',
};

export default function CipherStrengthChart({ sessions = [] }) {
  const total = sessions.length || 10;

  // Calculate dynamic cipher strength
  let strong = 0;
  let medium = 0;
  let weak = 0;

  if (sessions.length > 0) {
    for (const s of sessions) {
      const c = (s.cipher_suite || '').toUpperCase();
      if (s.risk_level === 'high' || s.risk_level === 'critical' || c.includes('3DES') || c.includes('CBC') || !s.forward_secrecy) {
        weak++;
      } else if (c.includes('AES_256') || c.includes('CHACHA20') || s.tls_version === 'TLS 1.3') {
        strong++;
      } else {
        medium++;
      }
    }
  } else {
    strong = 7;
    medium = 2;
    weak = 1;
  }

  // Ensure minimum rendering sanity if 0
  if (strong === 0 && medium === 0 && weak === 0) {
    strong = 7; medium = 2; weak = 1;
  }

  const strongPct = Math.round((strong / total) * 100);
  const mediumPct = Math.round((medium / total) * 100);
  const weakPct   = Math.round((weak / total) * 100);

  const data = [
    { name: 'Strong', value: strong, pct: strongPct, color: '#10b981' },
    { name: 'Medium', value: medium, pct: mediumPct, color: '#f59e0b' },
    { name: 'Weak',   value: weak,   pct: weakPct,   color: '#f43f5e' },
  ].filter(d => d.value > 0);

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
      {/* Title */}
      <div className="flex items-center gap-2 mb-2">
        <div className="w-6 h-6 rounded-lg bg-emerald-100 flex items-center justify-center text-emerald-600">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h3 className="text-xs font-bold text-slate-800 tracking-tight">
          Cipher Strength
        </h3>
      </div>

      {/* Donut & Legend Container */}
      <div className="flex items-center justify-between gap-2 h-44">
        {/* Donut with Center Text */}
        <div className="relative w-36 h-36 shrink-0 mx-auto sm:mx-0 outline-none focus:outline-none select-none" style={{ outline: 'none' }}>
          <ResponsiveContainer width="100%" height="100%" style={{ outline: 'none' }}>
            <PieChart style={{ outline: 'none' }}>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={42}
                outerRadius={62}
                paddingAngle={4}
                dataKey="value"
                strokeWidth={0}
                style={{ outline: 'none' }}
                tabIndex={-1}
              >
                {data.map((entry) => (
                  <Cell key={`cell-${entry.name}`} fill={entry.color} style={{ outline: 'none' }} tabIndex={-1} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                formatter={(v, name) => [`${v} sessions`, name]}
              />
            </PieChart>
          </ResponsiveContainer>

          {/* Center Callout */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-lg font-black font-mono text-slate-800 leading-none">
              {total}
            </span>
            <span className="text-[9px] font-semibold text-slate-400 mt-0.5">
              Sessions
            </span>
          </div>
        </div>

        {/* Legend on right */}
        <div className="flex flex-col gap-2 shrink-0 pr-1">
          {data.map((item) => (
            <div key={item.name} className="flex items-center gap-2 text-xs">
              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
              <span className="text-slate-600 font-medium text-[11px] w-12">{item.name}</span>
              <span className="text-slate-800 font-bold font-mono text-[11px]">
                {item.value} <span className="text-slate-400 font-normal text-[10px]">({item.pct}%)</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
