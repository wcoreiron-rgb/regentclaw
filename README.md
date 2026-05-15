<p align="center">
  <img src="frontend/public/logo.png" alt="RegentClaw" width="120" />
</p>

<h1 align="center">RegentClaw — Zero Trust Security Ecosystem</h1>

<p align="center">Modular, governed security ecosystem with Zero Trust enforcement across every module, agent, and workflow.</p>

<p align="center">
  <a href="https://wcoreiron-rgb.github.io/regentclaw/">📄 Documentation</a> &nbsp;·&nbsp;
  <a href="https://wcoreiron-rgb.github.io/regentclaw/docs.html">🛠 Technical Docs</a> &nbsp;·&nbsp;
  <a href="http://localhost:3000">🖥 Dashboard (local)</a>
</p>

## Architecture

```
RegentClaw/
├── backend/           FastAPI — CoreOS, Trust Fabric, ArcClaw, IdentityClaw
├── frontend/          Next.js — Platform UI dashboard
├── docker-compose.yml Full local stack
```

## Quick Start

### Prerequisites
- Docker + Docker Compose installed
- 4GB RAM available

### Run locally

```bash
cd RegentClaw
docker-compose up --build
```

Then open:
- **Frontend UI**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Health check**: http://localhost:8000/health

### First steps after launch

1. Open http://localhost:3000/dashboard
2. Go to **Policies** → add preset policies (Block Shell Execution, etc.)
3. Go to **ArcClaw** → submit a test prompt (try including an API key to test detection)
4. Watch the **Events** and **Audit** log populate
5. Go to **IdentityClaw** → check identity inventory

## API Reference

Full interactive docs at: http://localhost:8000/docs

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/dashboard | Platform stats |
| POST | /api/v1/arcclaw/events | Submit AI event for inspection |
| GET | /api/v1/arcclaw/stats | ArcClaw risk summary |
| GET | /api/v1/identityclaw/identities | Identity inventory |
| GET | /api/v1/identityclaw/orphaned | Orphaned identities |
| GET | /api/v1/policies | List policies |
| POST | /api/v1/policies | Create policy |
| GET | /api/v1/events | All events |
| GET | /api/v1/events/anomalies | Anomalies only |
| GET | /api/v1/audit | Audit log |

## Security Design Principles

1. **Every component has identity** — No anonymous modules or connectors
2. **Every action is authorized** — Policy evaluated before execution
3. **Every runtime is monitored** — Behavior tracked, not just access
4. **Every workflow is attributable** — Maps to a human owner
5. **Every risk is containable** — Isolation, revocation, kill switch
6. **Every module is governed** — Plug-and-play = plug-and-governed

## Claw Modules (24 total)

| Module | Description |
|--------|-------------|
| 🤖 ArcClaw | AI & LLM Security — prompt injection detection, AGT integration |
| 🪪 IdentityClaw | Identity Governance — human & non-human identity risk scoring |
| ☁️ CloudClaw | Cloud Security Posture — AWS, Azure, GCP |
| 🌐 ExposureClaw | External Attack Surface Management |
| 🛡️ EndpointClaw | EDR — CrowdStrike, Defender, SentinelOne |
| 🔍 ThreatClaw | Threat Intelligence & Detection |
| 📋 LogClaw | Log Management & SIEM coverage |
| 🌐 NetClaw | Network Security & segmentation |
| 🔑 AccessClaw | Access Control & IAM governance |
| 🗂️ DataClaw | Data Loss Prevention |
| 📱 AppClaw | Application Security — SAST, SCA |
| ☁️ SaasClaw | SaaS Security Posture Management |
| ⚙️ ConfigClaw | Configuration Compliance |
| ✅ ComplianceClaw | SOC2, PCI DSS, ISO 27001, HIPAA, GDPR, CIS |
| 🔒 PrivacyClaw | Privacy & GDPR enforcement |
| 🏢 VendorClaw | Third-Party & Supply Chain Risk |
| 👤 UserClaw | User Behavior Analytics |
| 🔎 InsiderClaw | Insider Threat Detection |
| ⚡ AutomationClaw | Automation & CI/CD Security |
| 🗺️ AttackPathClaw | Attack Path Analysis |
| 💻 DevClaw | DevSecOps & Secret Scanning |
| 🧠 IntelClaw | Threat Intelligence Feeds |
| 🔄 RecoveryClaw | Incident Recovery & Runbooks |
| 🔌 CustomClaw | User-defined REST API integrations |

## Tech Stack

- **Backend**: FastAPI + SQLAlchemy (async) + PostgreSQL + Redis
- **Frontend**: Next.js 14 + TypeScript + Tailwind CSS
- **Infra**: Docker Compose

## Development

### Backend only
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend only
```bash
cd frontend
npm install
npm run dev
```
