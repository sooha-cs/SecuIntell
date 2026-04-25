# 🛡️ SecuIntell — India-Focused SIEM Intelligence Platform

> A structured research and evaluation platform for Security Information & Event Management (SIEM) tools tailored to the Indian regulatory and threat landscape.

---

## 📌 Overview

**SecuIntell** helps CISOs, SOC practitioners, MSSPs, and security researchers make informed, compliance-aware decisions when evaluating SIEM solutions for the Indian market.

India's cybersecurity landscape is uniquely complex — multi-layered regulations, sector-specific mandates, and a rapidly growing threat surface. Yet most SIEM evaluations use generic global frameworks that ignore India-specific requirements.

SecuIntell solves this by providing:
- **Structured tool evaluations** using a consistent rubric across all major SIEM vendors
- **Indian compliance mapping** across CERT-In, RBI, SEBI, IRDAI, and the DPDP Act
- **Sector-specific scoring matrices** for BFSI and SME/mid-market segments
- **An interactive frontend** to explore, compare, and filter tools

---

## 🧩 Problem Statement

The Indian SIEM market is growing at **13% CAGR**, yet procurement decisions are often made without:
- Alignment to Indian regulatory frameworks (CERT-In Directive 2022, DPDP Act, RBI CSF)
- Sector-specific weighting (a bank's needs ≠ a mid-market SaaS company's needs)
- Practical SOC usability benchmarks relevant to Indian team sizes and skill sets

SecuIntell bridges this gap.

---

## ✅ Key Features

| Feature | Description |
|---|---|
| 🔍 Tool Profiles | In-depth evaluations of DNIF HYPERCLOUD, Microsoft Sentinel, ManageEngine Log360, IBM QRadar, Elastic SIEM |
| 📋 Compliance Mapping | Scored comparison tables across CERT-In, RBI, SEBI, IRDAI, DPDP Act |
| 🏦 BFSI Matrix | Weighted scoring tailored for banking and financial services |
| 🏢 SME Matrix | Mid-market focused procurement recommendations |
| 🤖 AI-Powered Analysis | Intelligent backend for querying and comparing SIEM tools |
| 🖥️ Interactive Frontend | Clean UI for exploring research, scores, and sector filters |

---

## 🗂️ Project Structure

```
SecuIntell/
├── backend/                    # Python backend (FastAPI)
│   ├── main.py                 # App entry point
│   ├── start.py                # Server startup script
│   ├── core/
│   │   ├── database.py         # Database connection & config
│   │   └── .env.example        # Environment variable template
│   ├── detection/
│   │   ├── engine.py           # Core detection engine
│   │   ├── rules.py            # Detection rule definitions
│   │   ├── anomaly.py          # Anomaly detection logic
│   │   ├── correlator.py       # Event correlation
│   │   ├── detection.py        # Detection orchestration
│   │   └── tests.py            # Unit tests
│   ├── models/
│   │   ├── log_model.py        # Log data model
│   │   └── detection_model.py  # Detection data model
│   ├── routes/
│   │   ├── logs.py             # Log ingestion endpoints
│   │   └── detection.py        # Detection result endpoints
│   └── schemas/
│       ├── log_schema.py       # Request/response schemas
│       └── detection_schema.py
│
├── frontend/                   # React + Vite dashboard
│   ├── index.html
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx             # Root component
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
| Frontend | React, Vite, Tailwind CSS |
| Backend | Node.js / Express |
| AI Engine | Grok API |
| Research Docs | Markdown |
| Data | Structured JSON / MD compliance tables |

---

## 🚀 Getting Started

### Prerequisites
- Node.js v18+
- npm or yarn
- Grok API Key

### 1. Clone the repository
```bash
git clone https://github.com/sooha-cs/SecuIntell.git
cd SecuIntell
```

### 2. Set up environment variables
```bash
cp .env.example .env
```
Open `.env` and fill in your values:
```
GROQ_API_KEY=your_api_key_here
DATABASE_URL=your_database_url_here
```

### 3. Install dependencies & run

**Backend:**
```bash
cd backend
pip install -r requirements.txt
python start.py
```
Backend runs at http://localhost:8000 by default.

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` by default.

**Run the Log Simulator (optional — for testing)**
```bash
    cd simulator
    python simulator.py
```
---

## 🔌 API Endpoints
 
| Method | Endpoint | Description |
|---|---|---|
| POST | `/logs` | Ingest a new log entry |
| GET | `/logs` | Retrieve stored logs |
| GET | `/detection` | Get detection results |
| POST | `/detection/analyze` | Trigger analysis on logs |
 
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
**Demo:** [Link if deployed]

---

## 📄 License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## 🙏 Acknowledgements

- [CERT-In](https://www.cert-in.org.in/) for regulatory documentation
- [DNIF](https://dnif.it/) for India-native SIEM reference architecture
-  Grok API for powering intelligent analysis

---

*Built with ❤️ for India's cybersecurity community.*
