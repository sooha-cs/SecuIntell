# 🛡️ SecuIntell — SIEM Intelligence Platform

> A full-stack AI-powered SIEM platform for security monitoring, threat detection, and compliance-aware evaluation of SIEM tools in the Indian market.

---

## 🌐 Live Demo

| Layer | URL |
|---|---|
| Frontend | https:// |
| Backend API | https:// |

---

## 📌 Overview

**SecuIntell** helps CISOs, SOC practitioners, MSSPs, and security researchers make informed, compliance-aware decisions when evaluating SIEM solutions for the Indian market.

India's cybersecurity landscape is uniquely complex; containing multi-layered regulations, sector-specific mandates, and a rapidly growing threat surface. Yet most SIEM evaluations use generic global frameworks that ignore India-specific requirements.

SecuIntell solves this by providing:
- **Real-time threat detection** with a rule-based engine (15 rules), Isolation Forest anomaly detection, and sliding-window correlation
- **AI-powered alert explanations** using Gemini/Groq API — risk assessment, MITRE ATT&CK mapping, attack stage classification, and suggested playbooks
- **An interactive dashboard** to monitor alerts, incidents, and live log feeds

---

## 🧩 Problem Statement

The Indian SIEM market is growing at **13% CAGR**, yet procurement decisions are often made without:
    - Alignment to Indian regulatory frameworks (CERT-In Directive 2022, DPDP Act, RBI CSF)
    - Practical SOC usability benchmarks relevant to Indian team sizes and skill sets

SecuIntell aims to bridge this gap.

---

## ✅ Key Features

| Feature | Description |
|---|---|
| 🚨 Alert Dashboard | Real-time alerts with severity, MITRE tactic tagging, risk scoring, and anomaly flags |
| 🔗 Incident Correlation | Sliding-window correlation engine linking alerts into attack chains |
| 🤖 AI Explain | Groq-powered natural language explanation for any alert — what happened, why it matters, suggested actions |
| 📡 Live Feed | Real-time log ingestion stream with source IP, event type, and host tracking |
| 🧠 Detection Engine | Rule-based (15 rules) + Isolation Forest anomaly detection + 6 attack chain correlators |

---

## 🗂️ Project Structure

```
SecuIntell/
├── backend/                    # Python backend (FastAPI)
│   ├── main.py                 # App entry point + CORS + lifespan
│   ├── start.py                # Server startup script
│   ├── requirements.txt        # Python dependencies
│   ├── .python-version         # Pins Python 3.11 for Render
│   ├── core/
│   │   ├── database.py         # MongoDB Atlas connection & indexes
│   │   └── .env.example        # Environment variable template
│   ├── detection/
│   │   ├── engine.py           # Core detection pipeline
│   │   ├── rules.py            # 15 detection rule definitions
│   │   ├── anomaly.py          # Isolation Forest anomaly detection
│   │   ├── correlator.py       # Sliding-window event correlation
│   │   ├── detection.py        # Detection orchestration
│   │   └── tests.py            # Unit tests
│   ├── models/
│   │   ├── log_model.py        # Log data model
│   │   └── detection_model.py  # Alert & incident data model
│   ├── routes/
│   │   ├── logs.py             # Log ingestion endpoints
│   │   └── detection.py        # Detection + AI explain endpoints
│   └── schemas/
│       ├── log_schema.py       # Request/response schemas
│       └── detection_schema.py
│
├── frontend/                   # React + Vite dashboard
│   ├── index.html
│   ├── vite.config.js
│   ├── vercel.json             # Vercel SPA routing config
│   └── src/
│       ├── App.jsx             # Root component + routing
│       ├── main.jsx            # React entry point
│       └── index.css
│
├── simulator/
│   └── simulator.py            # Log data simulator for testing
│
├── .gitignore
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Tailwind CSS |
| Backend | FastAPI, Python 3.11 |
| Database | MongoDB Atlas |
| AI Engine | Gemini & Groq API |
| Detection | scikit-learn (Isolation Forest), custom rule engine |
| Deployment — Frontend | Vercel |
| Deployment — Backend | Render |

---

## 🚀 Getting Started (Local)

### Prerequisites
- Node.js v18+
- Python 3.11+
- MongoDB Atlas account
- Groq API Key → https://console.groq.com/
- Gemini API Key

### 1. Clone the repository
```bash
git clone https://github.com/sooha-cs/SecuIntell.git
cd SecuIntell
```

### 2. Backend setup
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file inside `backend/`:
```
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxx
GEMINI_API_KEY=xxxxxxxxxxxxxxxx
MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/?retryWrites=true&w=majority
DB_NAME=secuintell
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:5173
```

Start the backend:
```bash
python start.py
```
Backend runs at `http://localhost:8000` — API docs at `http://localhost:8000/docs`

### 3. Frontend setup
```bash
cd frontend
npm install
```

Create a `.env` file inside `frontend/`:
```
VITE_API_URL=http://localhost:8000
```

Start the frontend:
```bash
npm run dev
```
Frontend runs at `http://localhost:5173`

### 4. Run the Log Simulator (optional — for testing)
```bash
cd simulator
python simulator.py
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Health check |
| POST | `/logs` | Ingest a new log entry |
| POST | `/logs/bulk` | Bulk log ingestion |
| GET | `/logs` | Retrieve stored logs with filters |
| GET | `/logs/{id}` | Get a specific log by ID |
| GET | `/alerts` | Get all detection alerts |
| GET | `/alerts/{id}` | Get a specific alert |
| PATCH | `/alerts/{id}/status` | Update alert status |
| GET | `/incidents` | Get all correlated incidents |
| GET | `/incidents/{id}` | Get a specific incident |
| POST | `/detection/analyze` | Trigger detection on recent logs |
| POST | `/detection/explain` | AI explanation for an alert (Groq) |
| GET | `/detection/stats` | Detection engine statistics |

Full interactive docs: `https://secuintell.onrender.com/docs`

---

## 👥 Target Audience

- **CISOs** evaluating SIEM procurement for Indian enterprises
- **SOC Analysts & Architects** benchmarking detection and response capabilities
- **MSSPs** building India-compliant managed security offerings
- **Security Researchers** studying the Indian SIEM landscape

---

## 🏆 Hackathon Submission

This project was built as part of **solution-challenge-2026**.

**Track:** Cybersecurity / AI for Security  
**Team:** KeepSwimming  
**Demo:** https://  
**Backend:** https://

---

## 📄 License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## 🙏 Acknowledgements

- [DNIF](https://dnif.it/) for India-native SIEM reference architecture
- [Groq](https://groq.com/) for powering intelligent alert analysis

---

## ⚠️ Note

- This project was mainly built to examine and try out AI developer tools and familiarizing with "Google for Developers" features, we premarily used GEMINI API and Google Cloud for storage but had to switch with other models due to free tier limits temporarily.

 ## Future developments
 - Future progress in this project includes:
    - 1.Compliance Mapping Layer — Every SIEM evaluation is scored against CERT-In, RBI CSF, SEBI, IRDAI, and DPDP Act requirements.
    - 2. Sector-Specific Matrices — Separate weighted scorecards for BFSI and SME/mid-market segments.
    - 3. Gmail Alert notification — Sends an email via GMAIL API when a critical level incident is created.


*Built with ❤️ for India's cybersecurity community.*
