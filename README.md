# Hybrid Explainable AI-Based Intrusion Detection System

A real-time intrusion detection system that combines **network traffic analysis** with **system-log anomaly detection**, powered by Explainable AI (SHAP & LIME) to provide transparent, interpretable security alerts.

## Architecture

```
Data Sources          Detection Modules        Explainability        Dashboard
┌─────────────┐      ┌──────────────────┐     ┌──────────────┐     ┌──────────────┐
│ CICIDS2017  │─────▶│ MLP Classifier   │────▶│     SHAP     │────▶│              │
│ (Network)   │      │ (52 features)    │     └──────────────┘     │   Real-Time  │
└─────────────┘      └──────────────────┘                          │   Dashboard  │
                                                                   │              │
┌─────────────┐      ┌──────────────────┐     ┌──────────────┐     │  - Alerts    │
│ BGL Logs    │─────▶│ CNN-LSTM Model   │────▶│     LIME     │────▶│  - SHAP/LIME │
│ (System)    │      │ (Text Sequence)  │     └──────────────┘     │  - History   │
└─────────────┘      └──────────────────┘                          └──────────────┘
```

## Features

- **Network Intrusion Detection** — Classifies network flows into 7 attack categories (DoS, DDoS, Brute Force, Port Scan, Botnet, Web Attack, Infiltration) using an MLP model trained on CICIDS2017
- **System-Log Anomaly Detection** — Detects anomalous system log entries using a CNN-LSTM model trained on BGL logs
- **Explainable AI** — SHAP values for network predictions and LIME explanations for log anomalies
- **Real-Time Dashboard** — Live event feed with severity badges, confidence scores, and feature importance charts
- **Dual Mode** — Switch between CSV data simulation and live system monitoring
- **Live Network Monitoring** — Captures real packets via Scapy, aggregates into flows, extracts 52 CICIDS2017 features, and classifies with MLP
- **Live Log Monitoring** — Tails system logs (auth.log, syslog, journalctl) with rolling 100-line windows for CNN-LSTM classification
- **Hybrid Correlation Engine** — Correlates network alerts and log alerts within 60s time windows based on host/IP and attack type compatibility
- **Historical Incident Storage** — SQLite database with KNN cosine similarity search for similar past incidents
- **Async Explanations** — SHAP/LIME computed in background threads without blocking real-time monitoring
- **Controlled Test Scenarios** — Pre-built scripts for brute force, port scan, and high-rate traffic testing

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Frontend | React.js, Tailwind CSS, Recharts, Socket.IO |
| Backend | FastAPI, Python-Socket.IO, TensorFlow |
| Network Detection | MLP (Multi-Layer Perceptron) — scikit-learn/TensorFlow |
| Log Detection | CNN-LSTM — TensorFlow/Keras |
| Explainability | SHAP, LIME |
| Live Capture | Scapy (packets), psutil (logs) |
| Communication | WebSockets (Socket.IO) |
| Datasets | CICIDS2017 (network), BGL (system logs) |

## Project Structure

```
hybrid-ids-dashboard/
├── backend/
│   ├── main.py                 # FastAPI + Socket.IO server (full integration)
│   ├── inference.py            # Model loading & prediction wrappers
│   ├── feature_extractor.py    # Packet → 52 CICIDS2017 features
│   ├── live_network_monitor.py # Scapy capture → flow → features → MLP
│   ├── live_log_monitor.py     # Log tailing → rolling window → CNN-LSTM
│   ├── correlation.py          # Hybrid correlation engine (time+host+type)
│   ├── explainer.py            # Async SHAP/LIME background worker
│   ├── incident_store.py       # SQLite storage + KNN similarity search
│   ├── test_scenarios/         # Controlled attack test scripts
│   ├── requirements.txt        # Python dependencies
│   └── models/                 # Trained model files (.pkl, .h5)
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main dashboard layout
│   │   ├── components/
│   │   │   ├── Dashboard.jsx   # Dashboard container
│   │   │   ├── MetricsPanel.jsx# Stats cards & charts
│   │   │   ├── LiveFeed.jsx    # Real-time event feed
│   │   │   └── AlertDetail.jsx # Alert detail with XAI
│   │   └── index.css           # Global styles
│   ├── package.json
│   └── vite.config.js
├── training/
│   ├── train_mlp_network.py    # Train MLP on CICIDS2017
│   ├── train_cnnlstm_logs.py   # Train CNN-LSTM on BGL
│   ├── requirements.txt        # Training dependencies
│   └── data/                   # Dataset files (not in git)
└── README.md
```

## Setup Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/anwarunnisa13/Real-Time-Intrusion-Detection-System.git
cd Real-Time-Intrusion-Detection-System
```

### 2. Backend Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install tensorflow scapy psutil
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

### 4. Train Models (Optional)
Download datasets and place them in `training/data/`:
- **CICIDS2017**: [Kaggle Link](https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed) — save as `training/data/CICIDS2017.csv`
- **BGL Logs**: [Kaggle Link](https://www.kaggle.com/datasets/boltzmannbrain/bgl-logs) — save as `training/data/BGL.csv`

Then train:
```bash
cd training
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 train_mlp_network.py      # Train network detection model
python3 train_cnnlstm_logs.py     # Train log detection model
```

### 5. Run the System

**Terminal 1 — Backend:**
```bash
cd backend
source venv/bin/activate
python3 main.py
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

**Open** `http://localhost:5173` in your browser.

### 6. Live Monitoring (Optional)
For real-time packet capture, run with sudo:
```bash
cd backend
sudo ./venv/bin/python3 main.py
```
Then click **"Live Monitor"** button in the dashboard header.

## Dashboard Modes

| Mode | Description |
|------|-------------|
| **CSV Data** | Streams events from CICIDS2017 and BGL datasets through the trained models. Good for demonstration. |
| **Live Monitor** | Captures real network packets (Scapy) and tails system logs in real-time. Requires root/sudo access. |

## Real-Time Pipeline

```
LIVE EVENT (packet or log line)
    ↓
CAPTURE (Scapy sniffer / log tailer)
    ↓
PROCESS (flow aggregation / rolling window)
    ↓
FEATURES (52 CICIDS2017 features / 100-token sequence)
    ↓
PREPROCESSING (StandardScaler / Tokenizer + pad_sequences)
    ↓
TRAINED MODEL (MLP / CNN-LSTM)
    ↓
DETECTION (attack type / anomaly score)
    ↓
CORRELATION (time window + host + attack type matching)
    ↓
EXPLANATION (SHAP / LIME in background thread)
    ↓
INCIDENT STORED (SQLite + similar incidents retrieved)
    ↓
DASHBOARD ALERT (WebSocket → React auto-update)
```

## Test Scenarios

```bash
# Brute force login simulation
bash backend/test_scenarios/brute_force.sh

# Port scanning simulation
bash backend/test_scenarios/port_scan.sh

# High-rate network activity
bash backend/test_scenarios/high_rate.sh
```

## Model Performance

### Network Intrusion Detection (MLP on CICIDS2017)
| Metric | Score |
|--------|-------|
| Accuracy | 98.7% |
| Weighted F1 | 0.98 |
| Classes | 7 (Normal, DoS, DDoS, Brute Force, Port Scan, Botnet, Web Attack) |

### System-Log Anomaly Detection (CNN-LSTM on BGL)
| Metric | Score |
|--------|-------|
| Accuracy | 93.5% |
| Classes | 2 (Normal, Anomaly) |

## Explainability

Each alert includes:

- **SHAP (Network)** — Shows which network features (flow duration, packet counts, byte rates) contributed most to the classification
- **LIME (Logs)** — Provides a human-readable explanation of why the log entry was flagged as anomalous

## Datasets

| Dataset | Source | Records | Purpose |
|---------|--------|---------|---------|
| CICIDS2017 | Canadian Institute for Cybersecurity | ~2M network flows | Network intrusion detection |
| BGL | Blue Gene/L Supercomputer | System logs | System-log anomaly detection |

## License

This project is for academic/research purposes.
