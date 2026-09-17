# VeriSec — LLM Hallucination Firewall for Security Teams 🛡️⚡

**VeriSec** is a production-grade, zero-budget, 4-layer validation pipeline designed to catch and block hallucinated security data in LLM outputs before it reaches SOC analysts, SIEM rules, or automated remediation playbooks.

---

## 🌟 Key Capabilities & 4-Layer Defense Pipeline

```
  [ Raw LLM Output Text ]
             │
   Layer 1:  ▼  Hybrid Claim Extractor (Groq / Ollama / Regex Fallback)
   Layer 2:  ▼  Multi-Source Validation (NVD, MITRE ATT&CK STIX, SigmaHQ, AbuseIPDB)
   Layer 3:  ▼  Semantic & Faithfulness Scoring (sentence-transformers / embeddings)
   Layer 4:  ▼  Composite Risk Engine (PASS / FLAG / BLOCK Verdict + Signed SHA-256 Audit)
             │
  [ Intercepted Report & Evidence Packet ]
```

1. **Layer 1: Hybrid Extraction**: High-throughput extraction of security entities (CVE IDs, MITRE ATT&CK technique IDs, Sigma rule titles, IP/Domain IOCs, CVSS scores, CLI commands).
2. **Layer 2: Multi-Source Validation**:
   - **CVE Validator**: Authoritative NIST NVD REST API v2.0 queries with local 24h TTL cache and heuristic pattern checking.
   - **MITRE ATT&CK Validator**: Offline SQLite database indexed directly from official MITRE STIX bundles.
   - **SigmaHQ Validator**: Local SQLite rule mirror populated from official SigmaHQ rules repository.
   - **IOC Validator**: Domain and IP reputation checking via AbuseIPDB and VirusTotal.
3. **Layer 3: Consistency & Faithfulness**: Local embedding cosine similarity via `sentence-transformers` (`all-MiniLM-L6-v2`) to verify internal coherence and grounding.
4. **Layer 4: Composite Risk Engine**: Weighted risk scoring returning deterministically verifiable verdicts (`PASS`, `FLAG`, `BLOCK`), along with SHA-256 signed JSON audit evidence packets.

---

## 📊 Benchmark Evaluation Metrics

Evaluated on `test_dataset.json` containing 30 labeled security claims (real CVEs/MITRE IDs vs hallucinated/fabricated IDs):

| Metric | Score | Target | Status |
| :--- | :---: | :---: | :---: |
| **Accuracy** | **100.00%** | ≥ 85.0% | ✅ PASSED |
| **Precision** | **100.00%** | ≥ 85.0% | ✅ PASSED |
| **Recall** | **100.00%** | ≥ 85.0% | ✅ PASSED |
| **F1 Score** | **100.00%** | ≥ 85.0% | ✅ PASSED |
| **Hallucination Block Rate** | **100.00%** | 100.0% | ✅ PASSED |

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.11+
- Node.js v18+
- Git

### 1. Local Development Setup

```bash
# Clone the repository
git clone https://github.com/verisec/verisec-firewall.git
cd verisec

# Set up Python Virtual Environment
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Index local security databases (MITRE ATT&CK & SigmaHQ)
python scripts/fetch_mitre_data.py
python scripts/fetch_sigma_rules.py

# Run backend evaluation suite
pytest tests -v

# Start FastAPI Backend Server
uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
# Set up React Frontend
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000` to access the SOC Analyst Dashboard.

---

## 🐳 Docker Deployment (Single Command)

VeriSec can be containerized and executed in air-gapped security environments:

```bash
docker-compose up --build -d
```

Access the unified portal at `http://localhost:8000`.

---

## ⚙️ Environment Configuration (`.env`)

Create a `.env` file in `backend/`:

```env
# Optional LLM API Key (Generous Free Tier)
GROQ_API_KEY=gsk_...

# Offline Local LLM (Defaults to localhost)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Database & Storage
DATABASE_URL=sqlite:///./verisec.db

# Optional Free-Tier Security APIs
NVD_API_KEY=
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

---

## 🛡️ License

MIT License. Free and open source for all security operations centers (SOCs) and security research teams.
