# AI IoT Security Platform

An end-to-end real-time anomaly detection and threat analysis platform for IoT devices, powered by an ensemble of machine learning models, explainable AI, and network graph analysis.

---

## Overview

The AI IoT Security Platform continuously monitors IoT device telemetry, detects threats and anomalies in real time, and explains the reasoning behind each detection. It combines three ML models (Isolation Forest, Random Forest, One-Class SVM) in a voting ensemble, uses SHAP for explainability, and analyzes device communication patterns to detect botnets, lateral movement, and coordinated attacks.

### Key Features

- **Real-time anomaly detection** via a 3-model ensemble with majority voting
- **Explainable AI (SHAP)** — understand which features triggered each alert
- **Network graph analysis** — detect botnets, lateral movement, and coordinated attacks
- **Live dashboard** — WebSocket-driven telemetry feed and network topology visualization
- **Voice SOC agent** — text-to-speech alerts via ElevenLabs
- **IoT device simulator** — generate synthetic traffic for testing
- **MQTT integration** — subscribe to real device telemetry streams
- **PostgreSQL persistence** — store and query all detections

### Threat Types Detected

| Threat | Detection Signal |
|--------|-----------------|
| DDoS Attack | High CPU + high packet rate |
| Credential Stuffing / Code Injection | High failed authentication attempts |
| Data Exfiltration | Outbound traffic >> inbound traffic |
| Location Spoofing / Identity Theft | High geo-location variation |
| Botnet Recruitment | High CPU + elevated packet rate |
| Unknown Anomaly | ML ensemble flags with no rule match |

---

## Architecture

```
┌─────────────────┐     MQTT      ┌──────────────────┐
│  IoT Simulator  │ ─────────────▶│  Backend API     │
│  (Python)       │               │  (Express/Node)  │
└─────────────────┘               │  Port 5000       │
                                  └────────┬─────────┘
                                           │ HTTP
                                           ▼
                                  ┌──────────────────┐
                                  │  ML Engine       │
                                  │  (FastAPI/Python)│
                                  │  Port 8000       │
                                  └────────┬─────────┘
                                           │
                          ┌────────────────┼─────────────────┐
                          ▼                ▼                  ▼
                   Ensemble Models    SHAP Explainer    Network Graph
                   (IF + RF + SVM)                     Analyzer

┌─────────────────┐   WebSocket   ┌──────────────────┐
│  Frontend       │◀─────────────▶│  Backend API     │
│  (Next.js)      │               │                  │
│  Port 3000      │               └────────┬─────────┘
└─────────────────┘                        │
                                  ┌────────▼─────────┐
                                  │  PostgreSQL DB   │
                                  └──────────────────┘
```

---

## Prerequisites

Before you begin, make sure the following are installed:

- **Node.js** 18+
- **Python** 3.8+
- **PostgreSQL** 12+
- **MQTT Broker** (e.g., [Mosquitto](https://mosquitto.org/download/))

---

## Project Structure

```
ai-iot-security/
├── backend/          # Express.js API server (TypeScript)
├── frontend/         # Next.js dashboard
├── ml-engine/        # FastAPI ML service
├── iot-simulator/    # IoT device telemetry simulator
└── docs/             # Documentation
```

---

## Setup & Installation

### 1. Database

Create the PostgreSQL database:

```sql
CREATE DATABASE ai_iot_security;
```

### 2. Backend

```bash
cd backend
npm install
```

Create a `.env` file:

```env
PORT=5000
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/ai_iot_security?schema=public
ML_BASE_URL=http://localhost:8000
MQTT_URL=mqtt://localhost:1883
MQTT_TOPIC=devices/+/telemetry
```

Run database migrations and start the server:

```bash
npx prisma migrate deploy
npm run dev        # Development (with hot reload)
# OR
npm run build && npm start   # Production
```

The backend runs on **http://localhost:5000**.

### 3. ML Engine

```bash
cd ml-engine
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt
```

Create a `.env` file:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
LLM_PROVIDER=gemini
```

Train the models (required before first run):

```bash
python train_ensemble_fixed.py
```

Start the ML engine:

```bash
python app.py
```

The ML engine runs on **http://localhost:8000**.

### 4. Frontend

```bash
cd frontend
npm install
```

Create a `.env.local` file:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:5000
NEXT_PUBLIC_BACKEND_WS_URL=http://localhost:5000
NEXT_PUBLIC_ML_ENGINE_HTTP_URL=http://localhost:8000
ELEVENLABS_API_KEY=your_elevenlabs_api_key
ELEVENLABS_VOICE_ID=your_voice_id
```

Start the frontend:

```bash
npm run dev        # Development on port 3000
# OR
npm run build && npm start   # Production
```

### 5. IoT Simulator (Optional)

Use this to generate simulated device telemetry for testing.

```bash
cd iot-simulator
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file:

```env
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_TOPIC_PREFIX=devices
SIM_BATCH_SIZE=5
SIM_SLEEP=1.5
SIM_NORMAL_PROB=0.90
```

Run the simulator:

```bash
python simulator.py
```

This spawns 20 virtual IoT devices (5 cameras, 8 sensors, 4 thermostats, 3 smart lights) publishing telemetry over MQTT with configurable attack injection.

---

## Running the Full Stack

Start each service in a separate terminal, in this order:

```
1. MQTT Broker (Mosquitto)
2. PostgreSQL
3. ML Engine        →  cd ml-engine && python app.py
4. Backend          →  cd backend && npm run dev
5. Frontend         →  cd frontend && npm run dev
6. Simulator        →  cd iot-simulator && python simulator.py  (optional)
```

Then open **http://localhost:3000** to access the dashboard.

---

## API Reference

### Backend API (Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | System health check |
| `POST` | `/api/telemetry` | Submit telemetry for anomaly detection |
| `POST` | `/api/telemetry/explained` | Detection with SHAP explanations |
| `GET` | `/api/detections` | Query detections (filters: deviceId, severity, isAnomaly, dateRange) |
| `GET` | `/api/detections/:id` | Get a single detection |
| `GET` | `/api/anomalies/recent` | Latest anomalies (default: 10) |
| `GET` | `/api/stats/summary` | Detection counts and incident summary |
| `GET` | `/api/stats/threats` | Threat type distribution |
| `GET` | `/api/stats/timeline` | Hourly detection timeline |
| `POST` | `/api/network/analyze` | Analyze network behavior for botnet/lateral movement |
| `GET` | `/api/network/status` | Current network health from recent detections |

### ML Engine API (Port 8000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Model status check |
| `POST` | `/api/ml/detect` | Run ensemble detection |
| `POST` | `/api/ml/detect/explained` | Detection + SHAP top contributing factors |
| `POST` | `/api/ml/network/analyze` | Graph-based network threat analysis |
| `POST` | `/api/ml/batch-detect` | Batch telemetry processing |

#### Example Detection Request

```json
POST /api/telemetry
{
  "device_id": "camera_01",
  "device_type": "camera",
  "cpu_usage": 88.5,
  "memory_usage": 72.0,
  "network_in_kb": 120.0,
  "network_out_kb": 950.0,
  "packet_rate": 1200,
  "avg_response_time_ms": 340,
  "service_access_count": 45,
  "failed_auth_attempts": 2,
  "is_encrypted": 1,
  "geo_location_variation": 3.2
}
```

#### Example Detection Response

```json
{
  "device_id": "camera_01",
  "is_anomaly": true,
  "confidence_score": 0.667,
  "risk_score": 85,
  "threat_type": "DDoS Attack",
  "threat_severity": "CRITICAL",
  "explanation": "High packet rate and CPU usage detected.",
  "model_votes": {
    "isolation_forest": "Anomaly",
    "random_forest": "Anomaly",
    "one_class_svm": "Normal"
  },
  "recommended_actions": [
    "Isolate device from network",
    "Review firewall rules"
  ]
}
```

---

## ML Model Details

### Ensemble Architecture

Three models vote on each prediction. An anomaly is flagged when **at least 2 out of 3 models agree**.

| Model | Type | Training Data |
|-------|------|--------------|
| Isolation Forest | Unsupervised | Normal samples only |
| Random Forest | Supervised | Labeled normal + attack |
| One-Class SVM | Unsupervised | Normal samples only |

### Feature Engineering

The engine uses 10 raw telemetry metrics plus 3 derived features:

- `network_total` = `network_in_kb` + `network_out_kb`
- `network_ratio` = `network_out_kb` / (`network_in_kb` + 1)
- `cpu_memory_product` = `cpu_usage` × `memory_usage`

### Severity Levels

| Score | Severity |
|-------|----------|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| < 20 | INFO |

---

## Tech Stack

| Component | Technologies |
|-----------|-------------|
| **Backend** | Node.js, Express, TypeScript, Prisma ORM, Socket.IO, MQTT |
| **Database** | PostgreSQL |
| **ML Engine** | Python, FastAPI, scikit-learn, SHAP, NetworkX, Pandas |
| **Frontend** | Next.js 16, React 19, TypeScript, Tailwind CSS, Socket.IO Client, D3 |
| **LLM / TTS** | Google Gemini API, ElevenLabs |
| **Simulator** | Python, paho-mqtt, Faker |

---

## License

MIT
