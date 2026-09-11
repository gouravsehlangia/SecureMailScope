// API layer for SecureMailScope.
//
// Real backend: FastAPI service from pipeline.py (GET /api/sessions,
// GET /api/sessions/{id}). If it isn't running — e.g. during frontend-only
// development, or a demo laptop where the backend crashed mid-run — we fall
// back to the bundled real sample output (enriched_sessions.sample.json) so
// the dashboard is never blank.

import sampleSessions from '../data/enriched_sessions.sample.json';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

let backendReachable = null; // null = unknown, true/false once checked

async function tryFetch(path) {
  const res = await fetch(`${BASE_URL}${path}`, { signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw new Error(`API ${path} responded ${res.status}`);
  return res.json();
}

/**
 * Returns { sessions, source } where source is "live" or "sample".
 */
export async function fetchSessions({ riskLevel, anomalyOnly } = {}) {
  const params = new URLSearchParams();
  if (riskLevel) params.set('risk_level', riskLevel);
  if (anomalyOnly) params.set('anomaly_only', 'true');
  const qs = params.toString() ? `?${params.toString()}` : '';

  try {
    const data = await tryFetch(`/api/sessions${qs}`);
    backendReachable = true;
    return { sessions: data, source: 'live' };
  } catch (err) {
    backendReachable = false;
    let sessions = sampleSessions;
    if (riskLevel) sessions = sessions.filter((s) => s.risk_level === riskLevel);
    if (anomalyOnly) sessions = sessions.filter((s) => s.anomaly_flag);
    return { sessions, source: 'sample' };
  }
}

export async function fetchSessionById(sessionId) {
  try {
    const data = await tryFetch(`/api/sessions/${sessionId}`);
    return { session: data, source: 'live' };
  } catch (err) {
    const session = sampleSessions.find((s) => s.session_id === sessionId) || null;
    return { session, source: 'sample' };
  }
}

export function isBackendReachable() {
  return backendReachable;
}

/**
 * Triggers a fresh pcap-derived pipeline run on the backend, if it exposes
 * an /analyze endpoint. Safe no-op fallback for the current pipeline.py,
 * which serves a single pre-computed enriched_sessions.json — wire this up
 * once the Integration lead adds POST /analyze for live pcap uploads.
 */
export async function triggerAnalysis(file) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${BASE_URL}/analyze`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`Analyze request failed (${res.status})`);
  return res.json();
}
