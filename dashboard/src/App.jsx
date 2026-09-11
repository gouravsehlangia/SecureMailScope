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
import UploadPage from './pages/UploadPage';

// ─── App ─────────────────────────────────────────────────────────────────────
export default function App() {
  // "upload" = upload/analysis page  |  "dashboard" = forensic dashboard
  const [page, setPage] = useState('upload');

  const [sessions, setSessions]   = useState([]);
  const [source, setSource]       = useState(null);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState(null);
  const [selected, setSelected]   = useState(null);
  const [filters, setFilters]     = useState({ severity: null, anomalyOnly: false, search: '' });

  // Load from existing backend (used when navigating directly to dashboard)
  async function load() {
    setLoading(true);
    setError(null);
    try {
      const { sessions: data, source: src } = await fetchSessions();
      setSessions(data);
      setSource(src);
    } catch {
      setError('Could not load session data.');
    } finally {
      setLoading(false);
    }
  }

  // Called by UploadPage when pipeline is done
  // sessions = null  →  user clicked "View Dashboard" without uploading (load live/sample)
  // sessions = array →  came from PCAP pipeline; use directly
  function handleAnalysisComplete(enrichedSessions) {
    if (enrichedSessions) {
      setSessions(enrichedSessions);
      setSource('live');   // pipeline returned real data
    } else {
      // User skipped upload, load current enriched_sessions.json
      load();
    }
    setSelected(null);
    setFilters({ severity: null, anomalyOnly: false, search: '' });
    setPage('dashboard');
  }

  // If dashboard is opened directly (page reload), auto-fetch
  useEffect(() => {
    if (page === 'dashboard' && sessions.length === 0) load();
  }, [page]);

  const filtered = useMemo(() => {
    return sessions.filter((s) => {
      if (filters.severity && s.risk_level !== filters.severity) return false;
      if (filters.anomalyOnly && !s.anomaly_flag) return false;
      if (filters.search) {
        const q = filters.search.toLowerCase();
        if (
          !s.session_id.toLowerCase().includes(q) &&
          !s.cipher_suite.toLowerCase().includes(q) &&
          !s.tls_version.toLowerCase().includes(q) &&
          !s.protocol.toLowerCase().includes(q)
        ) return false;
      }
      return true;
    });
  }, [sessions, filters]);

  // ─── Upload Page ───────────────────────────────────────────────────────────
  if (page === 'upload') {
    return <UploadPage onComplete={handleAnalysisComplete} />;
  }

  // ─── Dashboard Page ────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col selection:bg-blue-500 selection:text-white">
      {/* Top Navigation Bar */}
      <TopBar
        source={source}
        onRefresh={load}
        sessions={filtered}
        onUploadNew={() => setPage('upload')}
      />

      {/* Main Content */}
      <main className="flex-1 p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1440px] w-full mx-auto">
        {/* Loading */}
        {loading && (
          <div className="py-24 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-[3px] border-blue-600 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm font-medium text-slate-500">
              Loading email cryptographic telemetry…
            </p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-800 text-sm flex items-center justify-between">
            <span>{error}</span>
            <button
              onClick={load}
              className="px-3 py-1 bg-rose-600 text-white rounded-lg text-xs font-semibold hover:bg-rose-700 cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {/* Dashboard Content */}
        {!loading && !error && (
          <>
            {/* Quick summary strip — shows source of data */}
            {source === 'live' && sessions.length > 0 && (
              <div className="flex items-center gap-3 p-3.5 bg-white rounded-xl border border-slate-200/80 shadow-xs text-xs text-slate-600">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0 animate-pulse" />
                <span>
                  Showing <strong className="text-slate-900">{sessions.length} sessions</strong> from{' '}
                  <span className="font-semibold text-emerald-700">live pipeline output</span>.
                  {' '}Use <strong>Analyse New Capture</strong> in the top bar to run a fresh PCAP.
                </span>
                <button
                  onClick={() => setPage('upload')}
                  className="ml-auto px-3 py-1 rounded-lg bg-blue-50 text-blue-700 font-semibold border border-blue-200 hover:bg-blue-100 cursor-pointer whitespace-nowrap"
                >
                  + New PCAP
                </button>
              </div>
            )}

            {/* Stat Cards */}
            <StatStrip sessions={sessions} />

            {/* Charts Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5">
              <RiskDistributionChart sessions={sessions} />
              <TlsVersionChart sessions={sessions} />
              <TopViolations sessions={sessions} />
            </div>

            {/* Filter Bar */}
            <FilterBar
              filters={filters}
              setFilters={setFilters}
              resultCount={filtered.length}
              totalCount={sessions.length}
            />

            {/* Session Table */}
            <SessionTable
              sessions={filtered}
              onSelect={setSelected}
              selectedId={selected?.session_id}
            />
          </>
        )}
      </main>

      {/* Session Detail Drawer */}
      {selected && (
        <SessionDetail
          session={selected}
          onClose={() => setSelected(null)}
        />
      )}

      {/* Footer */}
      <footer className="py-6 border-t border-slate-200 text-center text-xs text-slate-400">
        SecureMailScope • Automated TLS Security &amp; Forensic Anomaly Analysis
      </footer>
    </div>
  );
}
