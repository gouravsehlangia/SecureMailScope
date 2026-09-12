import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer, LabelList } from 'recharts';

const TOOLTIP_STYLE = {
  background: 'rgba(255, 255, 255, 0.92)',
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

export default function TlsVersionChart({ sessions = [] }) {
  const count13 = sessions.filter(s => s.tls_version === 'TLS 1.3').length || (sessions.length ? 0 : 5);
  const count12 = sessions.filter(s => s.tls_version === 'TLS 1.2').length || (sessions.length ? 0 : 4);
  const count10 = sessions.filter(s => s.tls_version === 'TLS 1.0' || s.tls_version === 'TLS 1.1').length || (sessions.length ? 0 : 1);

  const data = [
    { version: 'TLS 1.3', count: count13, fill: '#60a5fa' },
    { version: 'TLS 1.2', count: count12, fill: '#93c5fd' },
    { version: 'TLS 1.0', count: count10, fill: '#bfdbfe' },
  ];

  const maxVal = Math.max(...data.map(d => d.count), 6);

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
      {/* Title */}
      <div className="flex items-center gap-2 mb-3">
        <div className="w-6 h-6 rounded-lg bg-sky-100 flex items-center justify-center text-sky-600">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h3 className="text-xs font-bold text-slate-800 tracking-tight">
          TLS Version Usage
        </h3>
      </div>

      {/* Chart */}
      <div className="h-44 w-full outline-none focus:outline-none" style={{ outline: 'none' }}>
        <ResponsiveContainer width="100%" height="100%" style={{ outline: 'none' }}>
          <BarChart data={data} margin={{ top: 20, right: 10, left: -24, bottom: 0 }} style={{ outline: 'none' }}>
            <XAxis
              dataKey="version"
              tick={{ fill: '#64748b', fontSize: 11, fontWeight: 600 }}
              axisLine={{ stroke: 'rgba(203, 213, 225, 0.4)' }}
              tickLine={false}
            />
            <YAxis
              domain={[0, Math.ceil(maxVal * 1.25)]}
              tick={{ fill: '#94a3b8', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              cursor={false}
              formatter={(v) => [`${v} sessions`, 'Count']}
            />
            <Bar dataKey="count" fill="#60a5fa" radius={[8, 8, 0, 0]} maxBarSize={38}>
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
              <LabelList
                dataKey="count"
                position="top"
                offset={6}
                style={{ fill: '#475569', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
