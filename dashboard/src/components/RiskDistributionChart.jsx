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

export default function RiskDistributionChart({ sessions = [] }) {
  const total = sessions.length || 10;
  const secure = sessions.filter(s => s.risk_level === 'low').length || (sessions.length ? 0 : 6);
  const medium = sessions.filter(s => s.risk_level === 'medium').length || (sessions.length ? 0 : 2);
  const high   = sessions.filter(s => s.risk_level === 'high' || s.risk_level === 'critical').length || (sessions.length ? 0 : 2);

  const securePct = Math.round((secure / total) * 100);
  const mediumPct = Math.round((medium / total) * 100);
  const highPct   = Math.round((high / total) * 100);

  const data = [
    { name: 'Secure', value: secure, pct: securePct, color: '#10b981' },
    { name: 'Medium', value: medium, pct: mediumPct, color: '#f59e0b' },
    { name: 'High',   value: high,   pct: highPct,   color: '#f43f5e' },
  ].filter(d => d.value > 0);

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
      {/* Title */}
      <div className="flex items-center gap-2 mb-2">
        <div className="w-6 h-6 rounded-lg bg-sky-100 flex items-center justify-center text-sky-600">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
          </svg>
        </div>
        <h3 className="text-xs font-bold text-slate-800 tracking-tight">
          Risk Distribution
        </h3>
      </div>

      {/* Donut & Legend Container */}
      <div className="flex items-center justify-between gap-2 h-44">
        {/* Donut */}
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

          {/* Center Text */}
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
        <div className="flex flex-col gap-2.5 shrink-0 pr-1">
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
