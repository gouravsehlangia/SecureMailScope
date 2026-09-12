/**
 * api.js — API layer for SecureMailScope.
 *
 * Real backend: FastAPI service from pipeline.py (GET /api/sessions,
 * GET /api/sessions/{id}). Falls back to bundled sample data when backend
 * is unreachable so the dashboard is never blank.
 *
 * POST /analyze — stub for live PCAP pipeline, wired up once the
 * Integration lead adds the endpoint in pipeline.py.
 */

import sampleSessions from '../data/enriched_sessions.sample.json';
import showcaseSessions from '../data/sample_showcase_sessions.json';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

let backendReachable = null; // null = unknown, true/false once probed

async function tryFetch(path, opts = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    signal: AbortSignal.timeout(8000),
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${path} responded ${res.status}`);
  return res.json();
}

/** Returns { sessions, source } where source is "live" or "sample". */
export async function fetchSessions({ riskLevel, anomalyOnly } = {}) {
  const params = new URLSearchParams();
  if (riskLevel) params.set('risk_level', riskLevel);
  if (anomalyOnly) params.set('anomaly_only', 'true');
  const qs = params.toString() ? `?${params.toString()}` : '';

  try {
    const data = await tryFetch(`/api/sessions${qs}`);
    backendReachable = true;
    return { sessions: data, source: 'live' };
  } catch {
    backendReachable = false;
    let sessions = showcaseSessions;
    if (riskLevel) sessions = sessions.filter((s) => s.risk_level === riskLevel);
    if (anomalyOnly) sessions = sessions.filter((s) => s.anomaly_flag);
    return { sessions, source: 'sample' };
  }
}

export async function fetchSessionById(sessionId) {
  try {
    const data = await tryFetch(`/api/sessions/${sessionId}`);
    return { session: data, source: 'live' };
  } catch {
    const session = showcaseSessions.find((s) => s.session_id === sessionId) ||
                    sampleSessions.find((s) => s.session_id === sessionId) || null;
    return { session, source: 'sample' };
  }
}

export function isBackendReachable() {
  return backendReachable;
}

/**
 * Validate a file before processing. Supports:
 * 1. .json files (output directly from ML engineer)
 * 2. .pcap / .pcapng files (raw network captures)
 *
 * Returns { valid: boolean, type: 'json'|'pcap', data?: any, format?: string, count?: number, error?: string }.
 */
export async function validateDataFile(file) {
  const ext = file.name.split('.').pop().toLowerCase();

  if (file.size === 0) {
    return { valid: false, error: 'The file appears to be empty (0 bytes).' };
  }

  // Handle JSON file from ML Engineer directly
  if (ext === 'json') {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const items = Array.isArray(parsed) ? parsed : (parsed.sessions || [parsed]);

      if (!Array.isArray(items) || items.length === 0) {
        return { valid: false, error: 'JSON file is empty or does not contain a session array.' };
      }

      // Check basic session structure
      const sample = items[0];
      if (!sample || typeof sample !== 'object') {
        return { valid: false, error: 'JSON elements must be valid session objects.' };
      }

      return {
        valid: true,
        type: 'json',
        data: items,
        count: items.length,
        format: `JSON dataset (${items.length} sessions)`,
      };
    } catch (e) {
      return { valid: false, error: `Invalid JSON syntax: ${e.message}` };
    }
  }

  // Handle PCAP / PCAPNG
  if (['pcap', 'pcapng'].includes(ext)) {
    const MAX_MB = 500;
    if (file.size > MAX_MB * 1024 * 1024) {
      const sizeMB = (file.size / 1024 / 1024).toFixed(1);
      return {
        valid: false,
        error: `File is too large (${sizeMB} MB). Maximum allowed size is ${MAX_MB} MB.`,
      };
    }

    try {
      const header = await file.slice(0, 4).arrayBuffer();
      const bytes = new Uint8Array(header);
      const magic = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(' ');

      const PCAP_LE = 'd4 c3 b2 a1';
      const PCAP_BE = 'a1 b2 c3 d4';
      const PCAPNG  = '0a 0d 0d 0a';

      if (magic !== PCAP_LE && magic !== PCAP_BE && magic !== PCAPNG) {
        return {
          valid: false,
          error: `File header does not match PCAP/PCAPNG format (got 0x${magic.replace(/ /g, '')}).`,
        };
      }

      return {
        valid: true,
        type: 'pcap',
        format: magic === PCAPNG ? 'PCAPNG' : 'PCAP',
      };
    } catch (e) {
      return { valid: false, error: 'Could not read file header for validation.' };
    }
  }

  return {
    valid: false,
    error: `Unsupported file format ".${ext}". Please upload a .json file from the ML pipeline or a .pcap/.pcapng capture.`,
  };
}

export async function validatePcapFile(file) {
  return validateDataFile(file);
}

/**
 * Upload a PCAP file to the backend for pipeline analysis.
 * POSTs to POST /analyze and returns enriched sessions JSON.
 *
 * onProgress(pct) is called with 0–100 as the upload progresses.
 * If the backend /analyze endpoint is not yet implemented (404/405),
 * throws an error with a clear message so the UI can surface it.
 */
export async function uploadPcapForAnalysis(file, onProgress) {
  const form = new FormData();
  form.append('file', file);
  form.append('filename', file.name);

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    });

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch {
          reject(new Error('Backend returned invalid JSON.'));
        }
      } else if (xhr.status === 404 || xhr.status === 405) {
        reject(new Error('BACKEND_ENDPOINT_MISSING'));
      } else {
        reject(new Error(`Upload failed (HTTP ${xhr.status}): ${xhr.responseText}`));
      }
    });

    xhr.addEventListener('error', () =>
      reject(new Error('Network error — is the backend running on :8000?'))
    );
    xhr.addEventListener('abort', () => reject(new Error('Upload cancelled.')));

    xhr.open('POST', `${BASE_URL}/analyze`);
    xhr.send(form);
  });
}
