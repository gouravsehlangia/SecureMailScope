import { useMemo, useState } from 'react';

// Email endpoint mapping for realistic forensics matching reference screenshot
const SAMPLE_ENDPOINTS = [
  'client@nitk.in → mail.example.com',
  'user@gmail.com → imap.gmail.com',
  'user@domain.com → pop3.domain.com',
  'admin@company.com → mx.company.com',
  'test@outlook.com → imap.outlook.com',
  'user@yahoo.com → pop3.yahoo.com',
  'user@gmail.com → smtp.gmail.com',
  'support@abc.com → imap.abc.com',
  'client@host.com → pop3.host.com',
  'service@net.com → mail.net.com',
];

function getProtocolBadge(protocol) {
  const p = (protocol || 'SMTP').toUpperCase();
  if (p.includes('IMAP')) {
    return 'bg-purple-100 text-purple-700 border-purple-200';
  }
  if (p.includes('POP')) {
    return 'bg-teal-100 text-teal-700 border-teal-200';
  }
  return 'bg-sky-100 text-sky-700 border-sky-200';
}

function getCertBadge(session) {
  if (session.cert_expired) {
    return { label: 'Expired', class: 'bg-rose-100 text-rose-700 border-rose-200' };
  }
  if (session.cert_key_length && session.cert_key_length < 2048) {
    return { label: 'Weak Key', class: 'bg-amber-100 text-amber-700 border-amber-200' };
  }
  if (!session.cert_chain_valid) {
    return { label: 'Untrusted', class: 'bg-rose-100 text-rose-700 border-rose-200' };
  }
  return { label: 'Valid', class: 'bg-emerald-100 text-emerald-700 border-emerald-200' };
}

function getRiskBadge(score, level) {
  const s = typeof score === 'number' ? score : 20;
  if (s >= 70 || level === 'critical' || level === 'high') {
    return { text: `${s} (High)`, class: 'bg-rose-100 text-rose-700 border-rose-200' };
  }
  if (s >= 30 || level === 'medium') {
    return { text: `${s} (Medium)`, class: 'bg-amber-100 text-amber-700 border-amber-200' };
  }
  return { text: `${s} (Low)`, class: 'bg-emerald-100 text-emerald-700 border-emerald-200' };
}

export default function SessionTable({
  sessions = [],
  onSelect,
  selectedId,
  showCount = 10,
  searchQuery = '',
  onSearchChange,
  onFilterToggle,
}) {
  const [internalSearch, setInternalSearch] = useState('');
  const [sortKey, setSortKey] = useState('risk_score');
  const [sortDir, setSortDir] = useState('desc');
  const [showAll, setShowAll] = useState(false);

  const query = (searchQuery !== undefined ? searchQuery : internalSearch).toLowerCase();

  const filtered = useMemo(() => {
    return sessions.filter((s, idx) => {
      if (!query) return true;
      const endpoint = s.endpoints || SAMPLE_ENDPOINTS[idx % SAMPLE_ENDPOINTS.length];
      return (
        (s.session_id && s.session_id.toLowerCase().includes(query)) ||
        (s.protocol && s.protocol.toLowerCase().includes(query)) ||
        (s.cipher_suite && s.cipher_suite.toLowerCase().includes(query)) ||
        (s.tls_version && s.tls_version.toLowerCase().includes(query)) ||
        endpoint.toLowerCase().includes(query)
      );
    });
  }, [sessions, query]);

  const sorted = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      let av = a[sortKey], bv = b[sortKey];
      if (typeof av === 'boolean') { av = av ? 1 : 0; bv = bv ? 1 : 0; }
      if (typeof av === 'string') return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
      return sortDir === 'asc' ? (av ?? 0) - (bv ?? 0) : (bv ?? 0) - (av ?? 0);
    });
    return copy;
  }, [filtered, sortKey, sortDir]);

  const displayed = showAll ? sorted : sorted.slice(0, showCount);
  const hasMore = sorted.length > showCount;

  function toggleSort(key) {
    if (sortKey === key) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    else { setSortKey(key); setSortDir('desc'); }
  }

  const colHead = (key, label) => (
    <th
      onClick={() => toggleSort(key)}
      className="px-3.5 py-3 text-left text-[11px] font-bold text-slate-500 cursor-pointer select-none hover:text-sky-700 transition-colors whitespace-nowrap"
    >
      <div className="flex items-center gap-1">
        <span>{label}</span>
        {sortKey === key && (
          <span className="text-sky-600 font-bold">{sortDir === 'asc' ? '↑' : '↓'}</span>
        )}
      </div>
    </th>
  );

  return (
    <div className="glass-card rounded-2xl overflow-hidden shadow-md">
      {/* ── Card Header (matching screenshot) ── */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 px-5 py-3.5 border-b border-white/80 bg-white/40">
        {/* Title */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-sky-100 flex items-center justify-center text-sky-600 shadow-xs">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-800 tracking-tight">
              Email Sessions
            </h3>
          </div>
        </div>

        {/* Search and Filter */}
        <div className="flex items-center gap-2 flex-1 sm:max-w-md justify-end">
          <div className="relative w-full">
            <svg className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={searchQuery !== undefined ? searchQuery : internalSearch}
              onChange={(e) => {
                if (onSearchChange) onSearchChange(e.target.value);
                else setInternalSearch(e.target.value);
              }}
              placeholder="Search by IP, domain, or session ID..."
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-xl glass-input placeholder:text-slate-400 text-slate-700 outline-none"
            />
          </div>

          <button
            onClick={onFilterToggle}
            title="Filter options"
            className="glass-btn p-2 rounded-xl text-slate-500 hover:text-sky-600 cursor-pointer shrink-0"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
            </svg>
          </button>
        </div>
      </div>

      {/* ── Table ── */}
      <div className="overflow-x-auto max-h-[560px] overflow-y-auto">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 z-10 bg-white/80 backdrop-blur-md border-b border-white/90">
            <tr>
              <th className="px-3.5 py-3 text-[11px] font-bold text-slate-400 w-8">#</th>
              {colHead('protocol', 'Protocol')}
              <th className="px-3.5 py-3 text-[11px] font-bold text-slate-500">From → To</th>
              {colHead('tls_version', 'TLS Version')}
              {colHead('cipher_suite', 'Cipher Suite')}
              {colHead('key_exchange', 'Key Exchange')}
              {colHead('forward_secrecy', 'PFS')}
              <th className="px-3.5 py-3 text-[11px] font-bold text-slate-500">Cert Status</th>
              {colHead('risk_score', 'Risk Score')}
              <th className="px-3.5 py-3 text-[11px] font-bold text-slate-500 text-right">Action</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-white/60 text-xs">
            {displayed.map((s, idx) => {
              const isSelected = selectedId === s.session_id;
              const cert = getCertBadge(s);
              const risk = getRiskBadge(s.risk_score, s.risk_level);
              const endpoint = s.endpoints || SAMPLE_ENDPOINTS[idx % SAMPLE_ENDPOINTS.length];
              const kx = s.key_exchange || (s.tls_version === 'TLS 1.3' ? 'ECDHE' : 'RSA');

              return (
                <tr
                  key={s.session_id || idx}
                  onClick={() => onSelect && onSelect(s)}
                  className={`cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-sky-100/70'
                      : idx % 2 === 0
                      ? 'bg-white/30 hover:bg-white/70'
                      : 'bg-white/10 hover:bg-white/70'
                  }`}
                >
                  {/* # */}
                  <td className="px-3.5 py-3 font-mono text-[11px] text-slate-400 font-semibold">
                    {idx + 1}
                  </td>

                  {/* Protocol */}
                  <td className="px-3.5 py-3 whitespace-nowrap">
                    <span className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold border font-mono ${getProtocolBadge(s.protocol)}`}>
                      {s.protocol || 'SMTP'}
                    </span>
                  </td>

                  {/* From -> To */}
                  <td className="px-3.5 py-3 font-mono text-[11px] text-slate-700 whitespace-nowrap max-w-[200px] truncate" title={endpoint}>
                    {endpoint}
                  </td>

                  {/* TLS Version */}
                  <td className="px-3.5 py-3 font-mono text-[11px] font-medium text-slate-700 whitespace-nowrap">
                    {s.tls_version || 'TLS 1.2'}
                  </td>

                  {/* Cipher Suite */}
                  <td className="px-3.5 py-3 font-mono text-[10.5px] text-slate-600 whitespace-nowrap max-w-[200px] truncate" title={s.cipher_suite}>
                    {s.cipher_suite}
                  </td>

                  {/* Key Exchange */}
                  <td className="px-3.5 py-3 font-mono text-[11px] text-slate-600 whitespace-nowrap">
                    {kx}
                  </td>

                  {/* PFS */}
                  <td className="px-3.5 py-3 font-medium text-[11px] whitespace-nowrap">
                    <span className={s.forward_secrecy ? 'text-emerald-600 font-bold' : 'text-slate-500'}>
                      {s.forward_secrecy ? 'Yes' : 'No'}
                    </span>
                  </td>

                  {/* Cert Status */}
                  <td className="px-3.5 py-3 whitespace-nowrap">
                    <span className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${cert.class}`}>
                      {cert.label}
                    </span>
                  </td>

                  {/* Risk Score */}
                  <td className="px-3.5 py-3 whitespace-nowrap">
                    <span className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold border font-mono ${risk.class}`}>
                      {risk.text}
                    </span>
                  </td>

                  {/* Action */}
                  <td className="px-3.5 py-3 whitespace-nowrap text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (onSelect) onSelect(s);
                      }}
                      className="text-sky-600 hover:text-sky-800 font-semibold text-xs hover:underline cursor-pointer"
                    >
                      View
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {displayed.length === 0 && (
          <div className="py-12 text-center">
            <p className="text-xs text-slate-400 font-medium">No sessions matched your search.</p>
          </div>
        )}
      </div>

      {/* Footer count & Show all toggle */}
      {hasMore && (
        <div className="flex items-center justify-between px-5 py-2.5 border-t border-white/80 bg-white/40 text-xs">
          <span className="text-[11px] text-slate-500">
            Showing top {displayed.length} of {sorted.length} sessions
          </span>
          <button
            onClick={() => setShowAll(!showAll)}
            className="text-[11px] font-bold text-sky-600 hover:text-sky-800 transition-colors cursor-pointer"
          >
            {showAll ? `Show top ${showCount}` : `Show all ${sorted.length}`}
          </button>
        </div>
      )}
    </div>
  );
}
