import { useMemo, useState } from 'react';
import SeverityBadge from './SeverityBadge';

const COLUMNS = [
  { key: 'session_id', label: 'Session' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'tls_version', label: 'TLS' },
  { key: 'cipher_suite', label: 'Cipher Suite' },
  { key: 'forward_secrecy', label: 'PFS' },
  { key: 'cert_expired', label: 'Cert' },
  { key: 'risk_score', label: 'Score' },
  { key: 'risk_level', label: 'Severity' },
  { key: 'anomaly_flag', label: 'Anomaly' },
];

function OkBad({ ok, okLabel = 'OK', badLabel = 'FAIL' }) {
  return (
    <span
      className={`font-mono text-[11px] ${ok ? 'text-[var(--color-low)]' : 'text-[var(--color-crit)]'}`}
    >
      {ok ? okLabel : badLabel}
    </span>
  );
}

export default function SessionTable({ sessions, onSelect, selectedId }) {
  const [sortKey, setSortKey] = useState('risk_score');
  const [sortDir, setSortDir] = useState('desc');

  function toggleSort(key) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  }

  const sorted = useMemo(() => {
    const copy = [...sessions];
    copy.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (typeof av === 'boolean') { av = av ? 1 : 0; bv = bv ? 1 : 0; }
      if (typeof av === 'string') return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
      return sortDir === 'asc' ? av - bv : bv - av;
    });
    return copy;
  }, [sessions, sortKey, sortDir]);

  return (
    <div className="border border-[var(--color-ink-border)] bg-[var(--color-ink-850)] overflow-auto max-h-[560px]">
      <table className="w-full text-sm font-mono border-collapse">
        <thead className="sticky top-0 bg-[var(--color-ink-800)] z-10">
          <tr>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                onClick={() => toggleSort(col.key)}
                className="text-left px-3 py-2.5 text-[11px] uppercase tracking-wider text-[var(--color-text-dim)] font-mono font-medium cursor-pointer select-none hover:text-[var(--color-text-primary)] border-b border-[var(--color-ink-border)] whitespace-nowrap"
              >
                {col.label}
                {sortKey === col.key && (
                  <span className="ml-1 text-[var(--color-accent)]">{sortDir === 'asc' ? '↑' : '↓'}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((s) => (
            <tr
              key={s.session_id}
              onClick={() => onSelect(s)}
              className={`cursor-pointer border-b border-[var(--color-ink-border)]/60 hover:bg-[var(--color-ink-700)]/40 ${
                selectedId === s.session_id ? 'bg-[var(--color-accent)]/10' : ''
              }`}
            >
              <td className="px-3 py-2 text-[var(--color-text-primary)]">{s.session_id}</td>
              <td className="px-3 py-2 text-[var(--color-text-muted)]">{s.protocol}</td>
              <td className="px-3 py-2 text-[var(--color-text-muted)]">{s.tls_version}</td>
              <td className="px-3 py-2 text-[var(--color-text-muted)] truncate max-w-[220px]" title={s.cipher_suite}>
                {s.cipher_suite}
              </td>
              <td className="px-3 py-2"><OkBad ok={s.forward_secrecy} /></td>
              <td className="px-3 py-2">
                <OkBad ok={!s.cert_expired && s.cert_chain_valid} okLabel="VALID" badLabel="ISSUE" />
              </td>
              <td className="px-3 py-2 text-[var(--color-text-primary)]">{s.risk_score}</td>
              <td className="px-3 py-2"><SeverityBadge level={s.risk_level} size="sm" /></td>
              <td className="px-3 py-2">
                {s.anomaly_flag ? (
                  <span className="text-[var(--color-accent)]">●</span>
                ) : (
                  <span className="text-[var(--color-text-dim)]">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sorted.length === 0 && (
        <div className="p-8 text-center text-[var(--color-text-muted)] text-sm font-sans">
          No sessions match the current filters.
        </div>
      )}
    </div>
  );
}
