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
  } catch {
    const session = sampleSessions.find((s) => s.session_id === sessionId) || null;
    return { session, source: 'sample' };
  }
}

export function isBackendReachable() {
  return backendReachable;
}

/**
 * Validate a PCAP/PCAPNG file before upload.
 * Returns { valid: boolean, error?: string }.
 *
 * Checks:
 *  1. File extension must be .pcap or .pcapng
 *  2. File size must be > 0 and < 500 MB
 *  3. File magic bytes:
 *       PCAP:   d4 c3 b2 a1  (little-endian) or  a1 b2 c3 d4 (big-endian)
 *       PCAPNG: 0a 0d 0d 0a (Section Header Block magic)
 */
export async function validatePcapFile(file) {
  const ext = file.name.split('.').pop().toLowerCase();
  if (!['pcap', 'pcapng'].includes(ext)) {
    return {
      valid: false,
      error: `Invalid file type ".${ext}". Please upload a .pcap or .pcapng capture file.`,
    };
  }

  if (file.size === 0) {
    return { valid: false, error: 'The file appears to be empty (0 bytes).' };
  }

  const MAX_MB = 500;
  if (file.size > MAX_MB * 1024 * 1024) {
    const sizeMB = (file.size / 1024 / 1024).toFixed(1);
    return {
      valid: false,
      error: `File is too large (${sizeMB} MB). Maximum allowed size is ${MAX_MB} MB.`,
    };
  }

  // Read first 4 bytes to verify magic number
  try {
    const header = await file.slice(0, 4).arrayBuffer();
    const bytes = new Uint8Array(header);
    const magic = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(' ');

    // PCAP little-endian: d4 c3 b2 a1
    // PCAP big-endian:    a1 b2 c3 d4
    // PCAPNG SHB:         0a 0d 0d 0a
    const PCAP_LE = 'd4 c3 b2 a1';
    const PCAP_BE = 'a1 b2 c3 d4';
    const PCAPNG  = '0a 0d 0d 0a';

    if (magic !== PCAP_LE && magic !== PCAP_BE && magic !== PCAPNG) {
      return {
        valid: false,
        error: `File header does not match PCAP/PCAPNG format (got 0x${magic.replace(/ /g, '')}). Is this really a capture file?`,
      };
    }

    return { valid: true, format: magic === PCAPNG ? 'PCAPNG' : 'PCAP' };
  } catch (e) {
    return { valid: false, error: 'Could not read file header for validation.' };
  }
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
