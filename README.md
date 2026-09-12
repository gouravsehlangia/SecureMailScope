# SecureMailScope

SecureMailScope is an email TLS cryptographic security posture analysis platform. It combines a Python/FastAPI pipeline for automated risk scoring, Isolation Forest anomaly detection, and AI recommendations with an interactive React + Tailwind + Recharts dashboard.

---

## Architecture & Directory Structure

```text
SecureMailScope/
├── pipeline.py                 # FastAPI backend, pipeline orchestration & API endpoints
├── risk_scoring.py             # Rule-based TLS risk scoring engine
├── anomaly_detection.py        # Scikit-learn Isolation Forest anomaly detector
├── ai_recommendations.py       # Context-aware security remediation advisor
├── generate_mock_sessions.py   # Synthetic TLS session generator
├── test_pipeline.py            # Unit & real network integration tests
├── mock_sessions.json          # Input TLS session records
├── enriched_sessions.json      # Output enriched security data served by API
├── requirements.txt            # Python dependencies
├── dashboard/                  # React + Tailwind + Recharts frontend dashboard
│   ├── src/                    # UI components, charts, and API client
│   ├── public/                 # Static assets
│   ├── package.json            # Node.js dependencies
│   ├── vite.config.js          # Vite configuration
│   └── README.md               # Frontend-specific documentation
└── README.md                   # Project documentation
```

---

## How to Run Both Halves Together

### 1. Backend (FastAPI on Port 8000)

1. Create and activate a Python virtual environment:
   ```bash
   # Windows PowerShell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install backend dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the backend service:
   ```bash
   python pipeline.py
   ```
   The backend pipeline will run, generate/update `enriched_sessions.json`, and start the FastAPI uvicorn server on **`http://localhost:8000`**.
   - API Docs: `http://localhost:8000/docs`
   - Sessions endpoint: `http://localhost:8000/api/sessions`

### 2. Frontend (Vite + React on Port 5173)

Open a new terminal window:

1. Navigate to the `dashboard` directory:
   ```bash
   cd dashboard
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Launch the development server:
   ```bash
   npm run dev
   ```
   The dashboard will be available at **`http://localhost:5173`**.

---

## Backend Connection & Offline Fallback

- The dashboard automatically communicates with `http://localhost:8000` by default (or the URL set in `VITE_API_BASE_URL`).
- **Live Indicator**: When `pipeline.py` is running, the top bar displays a green badge marked **"Live backend"**.
- **Offline Fallback**: If the backend is stopped or unreachable, the dashboard automatically falls back to bundled sample data (`src/data/enriched_sessions.sample.json`) and indicates **"Sample data (backend offline)"**, ensuring the dashboard remains usable during offline reviews and demonstrations.

---

## Generating Mock Data & Retesting

To generate a fresh batch of mock TLS sessions and re-enrich them:
```bash
python generate_mock_sessions.py
python pipeline.py
```

To run the backend unit and network integration tests:
```bash
python test_pipeline.py
```