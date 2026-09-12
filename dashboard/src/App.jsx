import { useEffect, useMemo, useState } from 'react';
import { fetchSessions } from './lib/api';
import NavBar from './components/NavBar';
import WelcomeBanner from './components/WelcomeBanner';
import StatStrip from './components/StatStrip';
import TlsVersionChart from './components/TlsVersionChart';
import CipherStrengthChart from './components/CipherStrengthChart';
import ProtocolBreakdownChart from './components/ProtocolBreakdownChart';
import RiskDistributionChart from './components/RiskDistributionChart';
import QuickStatsWidget from './components/QuickStatsWidget';
import RecentActivityWidget from './components/RecentActivityWidget';
import FilterBar from './components/FilterBar';
import SessionTable from './components/SessionTable';
import SessionDetail from './components/SessionDetail';
import UploadPage from './pages/UploadPage';
import ComparePage from './pages/ComparePage';

const STORAGE_SESSIONS_KEY = 'securemailscope_sessions_history';
const STORAGE_TIME_KEY = 'securemailscope_last_analysis_time';

export default function App() {
  const [page, setPage]             = useState('dashboard');
  const [sessions, setSessions]     = useState([]);
  const [source, setSource]         = useState(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState(null);
  const [selected, setSelected]     = useState(null);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters]       = useState({ severity: null, anomalyOnly: false, search: '' });
  const [lastAnalysisTime, setLastAnalysisTime] = useState(() => {
    return localStorage.getItem(STORAGE_TIME_KEY) || new Date().toISOString();
  });

  // Keep max 10 sessions. If new sessions come in, keep most recent 10 (drop oldest)
  function applySessionsWithLimit(newSessions, src = 'live', timestamp = null) {
    const list = Array.isArray(newSessions) ? newSessions : [];
    // Ensure only the latest 10 are kept
    const clamped = list.slice(0, 10);
    setSessions(clamped);
    setSource(src);
    try {
      localStorage.setItem(STORAGE_SESSIONS_KEY, JSON.stringify(clamped));
    } catch {}

    const nowIso = timestamp || new Date().toISOString();
    setLastAnalysisTime(nowIso);
    try {
      localStorage.setItem(STORAGE_TIME_KEY, nowIso);
    } catch {}
  }

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const { sessions: data, source: src } = await fetchSessions();
      applySessionsWithLimit(data, src);
    } catch {
      setError('Could not load session telemetry.');
    } finally {
      setLoading(false);
    }
  }

  function handleAnalysisComplete(enrichedSessions) {
    if (enrichedSessions && Array.isArray(enrichedSessions)) {
      // If adding new analysis sessions to existing list, merge with 10 max FIFO (newest first, drop oldest beyond 10)
      setSessions(prev => {
        const combined = [...enrichedSessions, ...prev];
        const limited = combined.slice(0, 10);
        try {
          localStorage.setItem(STORAGE_SESSIONS_KEY, JSON.stringify(limited));
        } catch {}
        return limited;
      });
      setSource('live');
      const nowIso = new Date().toISOString();
      setLastAnalysisTime(nowIso);
      try {
        localStorage.setItem(STORAGE_TIME_KEY, nowIso);
      } catch {}
    } else {
      load();
    }
    setSelected(null);
    setFilters({ severity: null, anomalyOnly: false, search: '' });
    setPage('dashboard');
  }

  useEffect(() => {
    const cached = localStorage.getItem(STORAGE_SESSIONS_KEY);
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setSessions(parsed.slice(0, 10));
          setSource('sample');
          return;
        }
      } catch {}
    }
    load();
  }, []);

  const filtered = useMemo(() =>
    sessions.filter((s) => {
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
    }), [sessions, filters]);

  return (
    <div className="min-h-dvh flex flex-col selection:bg-sky-500 selection:text-white">
      {/* ── PERSISTENT TOP NAV — matching existing structure ── */}
      <NavBar
        currentPage={page}
        source={source}
        onNavigate={(p) => {
          if (p === 'dashboard' && sessions.length === 0) load();
          setPage(p);
        }}
        onRefresh={load}
        sessions={filtered}
        lastAnalysisTime={lastAnalysisTime}
      />

      {/* ── MAIN CONTENT ── */}
      <main className="flex-1 overflow-x-hidden">
        {/* Upload Page */}
        {page === 'upload' && (
          <UploadPage onComplete={handleAnalysisComplete} />
        )}

        {/* Compare Page */}
        {page === 'compare' && (
          <ComparePage />
        )}

        {/* Dashboard */}
        {page === 'dashboard' && (
          <div className="max-w-[1680px] mx-auto px-4 sm:px-6 lg:px-8 py-5 space-y-4 fade-up">
            {/* Loading */}
            {loading && (
              <div className="py-24 flex flex-col items-center gap-4">
                <div className="w-12 h-12 rounded-full border-3 border-sky-300 border-t-sky-600 spin" />
                <p className="text-sm font-semibold text-slate-600">Loading session telemetry…</p>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="glass-card rounded-2xl p-4 border-rose-200 flex items-center justify-between gap-4">
                <span className="text-sm text-rose-600 font-semibold">{error}</span>
                <button
                  onClick={load}
                  className="px-4 py-1.5 bg-rose-500 text-white rounded-xl text-xs font-bold hover:bg-rose-600 transition-colors cursor-pointer"
                >
                  Retry
                </button>
              </div>
            )}

            {!loading && !error && (
              <>
                {/* 1. Welcome Greeting Banner */}
                <WelcomeBanner />

                {/* 2. Top 4 KPI Metric Cards */}
                <StatStrip sessions={sessions} />

                {/* 3. Two-Column Master Layout */}
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
                  {/* Left Column (Charts & Session Table) */}
                  <div className="xl:col-span-8 2xl:col-span-9 space-y-4">
                    {/* Middle 3 Charts Row */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <TlsVersionChart sessions={sessions} />
                      <CipherStrengthChart sessions={sessions} />
                      <ProtocolBreakdownChart sessions={sessions} />
                    </div>

                    {/* Collapsible Filter Bar if toggled */}
                    {showFilters && (
                      <div className="fade-up">
                        <FilterBar
                          filters={filters}
                          setFilters={setFilters}
                          resultCount={filtered.length}
                          totalCount={sessions.length}
                        />
                      </div>
                    )}

                    {/* Email Sessions Table */}
                    <SessionTable
                      sessions={filtered}
                      onSelect={setSelected}
                      selectedId={selected?.session_id}
                      showCount={10}
                      searchQuery={filters.search}
                      onSearchChange={(val) => setFilters(f => ({ ...f, search: val }))}
                      onFilterToggle={() => setShowFilters(prev => !prev)}
                    />
                  </div>

                  {/* Right Column (Sidebar Widgets) */}
                  <div className="xl:col-span-4 2xl:col-span-3 space-y-4">
                    <RiskDistributionChart sessions={sessions} />
                    <QuickStatsWidget sessions={sessions} />
                    <RecentActivityWidget sessions={sessions} lastAnalysisTime={lastAnalysisTime} />
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </main>

      {/* Session detail inspector drawer */}
      {selected && (
        <SessionDetail session={selected} onClose={() => setSelected(null)} />
      )}

      {/* Footer with SIH 2026 team credits */}
      <footer className="py-4 px-6 text-center text-xs text-slate-500 font-medium border-t border-white/60 bg-white/30 backdrop-blur-md flex flex-col sm:flex-row items-center justify-between gap-2 max-w-[1680px] mx-auto w-full">
        <div className="flex items-center gap-2 text-slate-600">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          <span>SecureMailScope · AI-Assisted Cryptographic Security Posture Assessment</span>
        </div>
        <div className="text-[11px] text-slate-500 font-mono">
          SIH 2026 | Team 6 | NIT Kurukshetra | SIH26159
        </div>
      </footer>
    </div>
  );
}
