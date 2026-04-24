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
├── frontend/               # React-based UI
│   ├── src/
│   └── package.json
├── backend/                # API server & AI integration
│   ├── src/
│   └── package.json
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Tailwind CSS |
| Backend | Node.js / Express |
| AI Engine | Google Gemini API |
| Research Docs | Markdown |
| Data | Structured JSON / MD compliance tables |

---

## 🚀 Getting Started

### Prerequisites
- Node.js v18+
- npm or yarn
- Gemini API Key

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
GEMINI_API_KEY=your_api_key_here
VITE_API_URL=http://localhost:3000
```

### 3. Install dependencies & run

**Backend:**
```bash
cd backend
npm install
npm run dev
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` by default.

---

## 🇮🇳 Indian Regulatory Coverage

| Framework | Coverage |
|---|---|
| CERT-In Directive 2022 | ✅ Log retention, incident reporting, 6-hour breach notification |
| RBI Cyber Security Framework | ✅ BFSI-specific controls, SOC requirements |
| SEBI Guidelines | ✅ Capital markets cybersecurity mandates |
| IRDAI Cyber Guidelines | ✅ Insurance sector requirements |
| DPDP Act 2023 | ✅ Data principal rights, processing obligations |

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
-  Google Gemini API for powering intelligent analysis

---

*Built with ❤️ for India's cybersecurity community.*
