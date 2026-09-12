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

export default function ProtocolBreakdownChart({ sessions = [] }) {
  const smtpCount = sessions.filter(s => (s.protocol || '').toUpperCase().includes('SMTP')).length || (sessions.length ? 0 : 4);
  const imapCount = sessions.filter(s => (s.protocol || '').toUpperCase().includes('IMAP')).length || (sessions.length ? 0 : 3);
  const pop3Count = sessions.filter(s => (s.protocol || '').toUpperCase().includes('POP')).length || (sessions.length ? 0 : 3);

  const data = [
    { protocol: 'SMTP', count: smtpCount, fill: '#60a5fa' },
    { protocol: 'IMAP', count: imapCount, fill: '#c084fc' },
    { protocol: 'POP3', count: pop3Count, fill: '#2dd4bf' },
  ];

  const maxVal = Math.max(...data.map(d => d.count), 4);

  return (
    <div className="glass-card rounded-2xl p-5 flex flex-col justify-between">
      {/* Title */}
      <div className="flex items-center gap-2 mb-3">
        <div className="w-6 h-6 rounded-lg bg-indigo-100 flex items-center justify-center text-indigo-600">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
              d="M4 6h16M4 10h16M4 14h16M4 18h16" />
          </svg>
        </div>
        <h3 className="text-xs font-bold text-slate-800 tracking-tight">
          Protocol Breakdown
        </h3>
      </div>

      {/* Chart */}
      <div className="h-44 w-full outline-none focus:outline-none" style={{ outline: 'none' }}>
        <ResponsiveContainer width="100%" height="100%" style={{ outline: 'none' }}>
          <BarChart data={data} margin={{ top: 20, right: 10, left: -24, bottom: 0 }} style={{ outline: 'none' }}>
            <XAxis
              dataKey="protocol"
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
              formatter={(v) => [`${v} sessions`, 'Sessions']}
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
