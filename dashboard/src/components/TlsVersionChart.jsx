import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer } from 'recharts';

const ORDER = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0'];
const DEPRECATED = new Set(['TLS 1.0', 'TLS 1.1']);

export default function TlsVersionChart({ sessions }) {
  const data = ORDER.map((version) => ({
    version,
    count: sessions.filter((s) => s.tls_version === version).length,
  })).filter((d) => d.count > 0 || ORDER.includes(d.version));

  return (
    <div className="border border-[var(--color-ink-border)] bg-[var(--color-ink-850)] p-4">
      <h3 className="text-xs uppercase tracking-wider text-[var(--color-text-dim)] font-mono mb-3">
        TLS Version Mix
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} margin={{ left: -16, right: 8, top: 4, bottom: 4 }}>
          <XAxis
            dataKey="version"
            stroke="#5c6480"
            tick={{ fill: '#8d96ad', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
          />
          <YAxis allowDecimals={false} stroke="#5c6480" tick={{ fill: '#8d96ad', fontSize: 11 }} />
          <Tooltip
            contentStyle={{
              background: '#121828',
              border: '1px solid #232d45',
              fontFamily: 'IBM Plex Mono',
              fontSize: 12,
            }}
            cursor={{ fill: 'rgba(255,255,255,0.03)' }}
          />
          <Bar dataKey="count" barSize={36}>
            {data.map((d) => (
              <Cell key={d.version} fill={DEPRECATED.has(d.version) ? '#e5484d' : '#4c9eeb'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
