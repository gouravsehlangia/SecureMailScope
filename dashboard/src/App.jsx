import { useEffect, useMemo, useState } from 'react';
import { fetchSessions } from './lib/api';
import TopBar from './components/TopBar';
import StatStrip from './components/StatStrip';
import RiskDistributionChart from './components/RiskDistributionChart';
import TlsVersionChart from './components/TlsVersionChart';
import TopViolations from './components/TopViolations';
import FilterBar from './components/FilterBar';
import SessionTable from './components/SessionTable';
import SessionDetail from './components/SessionDetail';

export default function App() {
  const [sessions, setSessions] = useState([]);
  const [source, setSource] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filters, setFilters] = useState({ severity: null, anomalyOnly: false, search: '' });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const { sessions, source } = await fetchSessions();
      setSessions(sessions);
      setSource(source);
    } catch (e) {
      setError('Could not load session data.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    return sessions.filter((s) => {
      if (filters.severity && s.risk_level !== filters.severity) return false;
      if (filters.anomalyOnly && !s.anomaly_flag) return false;
      if (filters.search) {
        const q = filters.search.toLowerCase();
        if (
          !s.session_id.toLowerCase().includes(q) &&
          !s.cipher_suite.toLowerCase().includes(q) &&
          !s.tls_version.toLowerCase().includes(q)
        ) return false;
      }
      return true;
    });
  }, [sessions, filters]);

  return (
    <div className="min-h-screen bg-[var(--color-ink-950)]">
      <TopBar source={source} onRefresh={load} sessions={filtered} />

      <main className="p-6 space-y-6 max-w-[1400px] mx-auto">
        {loading && (
          <p className="text-sm font-mono text-[var(--color-text-muted)]">Loading session data…</p>
        )}
        {error && (
          <p className="text-sm font-mono text-[var(--color-crit)]">{error}</p>
        )}

        {!loading && !error && (
          <>
            <StatStrip sessions={sessions} />

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <RiskDistributionChart sessions={sessions} />
              <TlsVersionChart sessions={sessions} />
              <TopViolations sessions={sessions} />
            </div>

            <FilterBar filters={filters} setFilters={setFilters} resultCount={filtered.length} />

            <SessionTable sessions={filtered} onSelect={setSelected} selectedId={selected?.session_id} />
          </>
        )}
      </main>

      {selected && <SessionDetail session={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
