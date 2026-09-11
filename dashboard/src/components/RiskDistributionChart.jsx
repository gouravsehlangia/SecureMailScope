import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer } from 'recharts';
import { SEVERITY, SEVERITY_ORDER } from '../lib/severity';

const RAW_COLOR = {
  critical: '#e5484d',
  high: '#f0883e',
  medium: '#e8b339',
  low: '#2fb88d',
};

export default function RiskDistributionChart({ sessions }) {
  const data = SEVERITY_ORDER.map((level) => ({
    level,
    label: SEVERITY[level].label,
    count: sessions.filter((s) => s.risk_level === level).length,
  }));

  return (
    <div className="border border-[var(--color-ink-border)] bg-[var(--color-ink-850)] p-4">
      <h3 className="text-xs uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-3">
        Risk Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
          <XAxis type="number" allowDecimals={false} stroke="#5c6480" tick={{ fill: '#8d96ad', fontSize: 11 }} />
          <YAxis
            type="category"
            dataKey="label"
            stroke="#5c6480"
            tick={{ fill: '#8d96ad', fontSize: 12, fontFamily: 'IBM Plex Mono' }}
            width={64}
          />
          <Tooltip
            contentStyle={{
              background: '#121828',
              border: '1px solid #232d45',
              fontFamily: 'IBM Plex Mono',
              fontSize: 12,
            }}
            cursor={{ fill: 'rgba(255,255,255,0.03)' }}
          />
          <Bar dataKey="count" barSize={18}>
            {data.map((d) => (
              <Cell key={d.level} fill={RAW_COLOR[d.level]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
