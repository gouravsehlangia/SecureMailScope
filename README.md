# SecureMailScope

SecureMailScope is an email TLS cryptographic security posture analysis platform for Smart India Hackathon 2026. It combines a full 5-stage Python pipeline for automated PCAP parsing, TLS handshake reconstruction, X.509 certificate analysis, risk scoring, Isolation Forest anomaly detection, and AI-powered recommendations — with an interactive React + Recharts dashboard.

---

## Architecture & Directory Structure

```text
SecureMailScope/
├── pipeline.py                     # FastAPI backend, unified 5-stage pipeline orchestration
├── risk_scoring.py                 # Rule-based TLS risk scoring engine
├── anomaly_detection.py            # Scikit-learn Isolation Forest anomaly detector
├── ai_recommendations.py           # Context-aware security remediation advisor (Cerebras LLM + fallback)
├── test_pipeline.py                # Full pipeline integration tests
├── requirements.txt                # Python dependencies
├── history/                        # Last 10 analysis run results (auto-managed)
│
├── Protocol ID (SMTP⁄IMAP⁄POP3) + TCP stream reassembly/
│   ├── pcap_reader.py              # Dual-engine PCAP/PCAPNG parser (pure Python + Scapy)
│   ├── reassembler.py              # TCP stream reassembly with gap/reorder handling
│   ├── protocol_detector.py        # DPI-based protocol identification (SMTP/IMAP/POP3)
│   ├── starttls_detector.py        # STARTTLS negotiation & downgrade attack detection
│   ├── extractor.py                # Master extraction pipeline
│   └── models.py                   # Data models & contracts
│
├── backend/
│   └── tls_analysis/               # TLS handshake reconstruction & crypto evaluation
│       ├── handshake_parser.py     # TLS record layer & handshake message parser
│       ├── crypto_analyzer.py      # Cipher suite, PFS, key exchange evaluation
│       ├── cipher_suites.py        # Cipher suite database & classification
│       ├── keylog_manager.py       # SSLKEYLOGFILE TLS 1.3 decryption
│       └── models.py              # TLS analysis data models
│
├── cert_analysis/                  # X.509 certificate analysis
│   ├── parser.py                   # Certificate DER/PEM parser
│   ├── rules.py                    # Weak-crypto rule engine
│   ├── chain_validator.py          # Certificate chain validation
│   └── analyzer.py                 # Unified analysis entry point
│
├── test_data/                      # Test PCAP files & stubs
│   ├── mock_email_traffic.pcap     # Test PCAP with 5 email security scenarios
│   └── mock_session.keylog         # TLS 1.3 keylog for test PCAP
│
├── dashboard/                      # React + Vite + Recharts frontend dashboard
│   ├── src/
│   │   ├── App.jsx                 # Main app with routing
│   │   ├── pages/
│   │   │   ├── UploadPage.jsx      # PCAP/JSON upload & pipeline execution
│   │   │   ├── HistoryPage.jsx     # Last 10 analysis runs history
│   │   │   └── ComparePage.jsx     # Multi-capture comparison
│   │   ├── components/             # Dashboard UI components
│   │   ├── lib/api.js              # Backend API client
│   │   └── data/                   # Sample/demo data for offline fallback
│   ├── package.json
│   ├── vite.config.js
│   └── README.md
└── README.md
```

---

## Pipeline Architecture

```
PCAP File (.pcap / .pcapng)
    ↓
Stage 1: Protocol ID + TCP Reassembly + STARTTLS Detection
    ↓
Stage 2: TLS Handshake Reconstruction + Crypto Evaluation + PFS
    ↓
Stage 3: X.509 Certificate Analysis + Chain Validation
    ↓
Stage 4: Risk Scoring + Isolation Forest Anomaly Detection + AI Recommendations
    ↓
Enriched Sessions JSON → Dashboard + History
```

---

## How to Run

### 1. Backend (FastAPI on Port 8000)

1. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install backend dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the backend API server:
   ```bash
   python pipeline.py
   ```
   The FastAPI server starts on **`http://localhost:8000`**.
   - API Docs: `http://localhost:8000/docs`
   - Sessions: `http://localhost:8000/api/sessions`
   - History: `http://localhost:8000/api/history`

4. (Optional) Run pipeline on a PCAP file at startup:
   ```bash
   python pipeline.py --pcap test_data/mock_email_traffic.pcap --keylog test_data/mock_session.keylog
   ```

### 2. Frontend (Vite + React on Port 5173)

Open a new terminal:

```bash
cd dashboard
npm install
npm run dev
```

The dashboard will be available at **`http://localhost:5173`**.

---

## Using the Dashboard

1. **Upload Page**: Upload a `.pcap`, `.pcapng`, or `.json` file. The full pipeline runs automatically.
2. **Dashboard**: View enriched session results with risk charts, anomaly detection, and AI recommendations.
3. **History**: View last 10 analysis runs. Click any past run to reload its results.
4. **Compare**: Upload multiple PCAP files to compare security posture side by side.

---

## Backend API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Service info & available endpoints |
| GET | `/api/sessions` | Latest enriched session data |
| GET | `/api/sessions/{id}` | Single session by ID |
| POST | `/analyze` | Upload PCAP/JSON for full pipeline analysis |
| GET | `/api/history` | List last 10 analysis runs |
| GET | `/api/history/{run_id}` | Load a specific past analysis |
| DELETE | `/api/history/{run_id}` | Delete a past analysis run |

---

## Offline Fallback

- When the backend is unreachable, the dashboard falls back to bundled sample data (`src/data/enriched_sessions.sample.json`).
- The "Live backend" / "Sample data" indicator is shown in the top bar.

---

## Running Tests

```bash
python test_pipeline.py
```

This runs the full pipeline integration test including:
- PCAP parsing through all 5 stages
- Schema validation
- History management
- FastAPI endpoint tests
- Real network test (spawns Uvicorn subprocess)

---

## Team Structure (SIH 2026)

| # | Role | Module |
|---|------|--------|
| 1 | PCAP Parsing Lead | Protocol ID, TCP reassembly, STARTTLS detection |
| 2 | TLS/Crypto Engineer | TLS handshake parsing, cipher/version/key exchange |
| 3 | Certificate Engineer | X.509 validation, weak-crypto rule engine |
| 4 | AI/ML Engineer | Risk scoring, anomaly detection, AI recommendations |
| 5 | Frontend/Dashboard Lead | React UI, visualizations |
| 6 | Integration & Reports Lead | API glue, pipeline orchestration, testing |

**Team**: NIT Kurukshetra | SIH26159