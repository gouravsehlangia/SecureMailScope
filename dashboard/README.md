# SecureMailScope — Dashboard

React + Tailwind (v4) + Recharts frontend for the SecureMailScope pipeline.
Reads the enriched-session JSON produced by `pipeline.py` and renders a
severity-ranked forensic dashboard.

## Run it

```bash
npm install
npm run dev
```

Opens on http://localhost:5173.

## Backend connection

The app calls the FastAPI service from `pipeline.py`:

- `GET /api/sessions` — all enriched sessions
- `GET /api/sessions/{session_id}` — single session

Point it at your backend with an env var (defaults to `http://localhost:8000`):

```bash
cp .env.example .env
# edit VITE_API_BASE_URL if the backend runs elsewhere
```

Start the backend from the main repo:

```bash
python pipeline.py
```

**If the backend isn't running, the dashboard falls back to a bundled real
sample (`src/data/enriched_sessions.sample.json` — a real 200-session pipeline
output) automatically**, so the UI is never blank during dev or demo. The top
bar shows "Live backend" or "Sample data (backend offline)" so it's always
clear which one you're looking at during the judging demo — flip the backend
on and hit Refresh to switch.

## What's here

- `src/lib/api.js` — fetch layer + offline fallback
- `src/lib/severity.js` — single source of truth for risk-level colors/labels
  (mirrors `risk_scoring.py`'s thresholds: ≥75 critical, ≥50 high, ≥25 medium)
- `src/lib/report.js` — client-side JSON / HTML / PDF(via print) report export
- `src/components/` — StatStrip, RiskDistributionChart, TlsVersionChart,
  TopViolations, FilterBar, SessionTable, SessionDetail (drill-down),
  TopBar, ExportMenu

## Wiring up live PCAP upload

`pipeline.py` currently serves one pre-computed `enriched_sessions.json`.
`src/lib/api.js` already has a `triggerAnalysis(file)` stub that POSTs to
`/analyze` for when the Integration lead adds a live-upload endpoint —
hook it up to a file input in `TopBar` once that route exists.
