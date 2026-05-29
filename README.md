<p align="center">
  <img src="frontend/public/logo.png" alt="RegentClaw" width="120" />
</p>

<h1 align="center">RegentClaw — Zero Trust Security Ecosystem</h1>

<p align="center">Modular, governed security ecosystem with Zero Trust enforcement across every module, agent, and workflow.</p>

<p align="center">
  <a href="https://wcoreiron-rgb.github.io/regentclaw/">
    <img src="https://img.shields.io/badge/Documentation-1f2937?style=for-the-badge&logo=gitbook&logoColor=white" alt="Documentation" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/regentclaw/docs.html">
    <img src="https://img.shields.io/badge/Technical%20Docs-2563eb?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Technical Docs" />
  </a>
  <a href="http://localhost:3000">
    <img src="https://img.shields.io/badge/Dashboard%20(local)-0f766e?style=for-the-badge&logo=vercel&logoColor=white" alt="Dashboard (local)" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/regentclaw/projects">
    <img src="https://img.shields.io/badge/Roadmap%202026-7c3aed?style=for-the-badge&logo=githubprojects&logoColor=white" alt="Roadmap 2026" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/regentclaw/issues/new?labels=bug&title=%5BBug%5D+">
    <img src="https://img.shields.io/badge/Report%20Bug-dc2626?style=for-the-badge&logo=github&logoColor=white" alt="Report Bug" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/regentclaw/issues/new?labels=enhancement&title=%5BFeature%5D+">
    <img src="https://img.shields.io/badge/Request%20Feature-2563eb?style=for-the-badge&logo=github&logoColor=white" alt="Request Feature" />
  </a>
  <a href="https://github.com/wcoreiron-rgb/regentclaw/discussions">
    <img src="https://img.shields.io/badge/GitHub%20Discussions-0f766e?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Discussions" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/wcoreiron-rgb/regentclaw/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/wcoreiron-rgb/regentclaw/ci.yml?branch=main&label=Build%20and%20Test%20(Unit%20%2B%20E2E)" alt="Build and Test (Unit + E2E)" />
  </a>
  <a href="https://codecov.io/gh/wcoreiron-rgb/regentclaw">
    <img src="https://img.shields.io/codecov/c/github/wcoreiron-rgb/regentclaw?label=codecov" alt="codecov" />
  </a>
</p>

<p align="center"><strong>Full Documentation</strong></p>
<p align="center">
  <a href="https://wcoreiron-rgb.github.io/regentclaw/">
    <img src="https://img.shields.io/badge/Quick%20Start-f59e0b?style=for-the-badge&logo=rocket&logoColor=white" alt="Quick Start" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/regentclaw/docs.html#architecture">
    <img src="https://img.shields.io/badge/Specifications-0891b2?style=for-the-badge&logo=bookstack&logoColor=white" alt="Specifications" />
  </a>
  <a href="https://wcoreiron-rgb.github.io/regentclaw/changelog.html">
    <img src="https://img.shields.io/badge/Changelog-4f46e5?style=for-the-badge&logo=readme&logoColor=white" alt="Changelog" />
  </a>
</p>

<p align="center"><strong>Languages</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-62.8%25-3776AB?logo=python&logoColor=white" alt="Python 62.8%" />
  <img src="https://img.shields.io/badge/TypeScript-36.5%25-3178C6?logo=typescript&logoColor=white" alt="TypeScript 36.5%" />
  <img src="https://img.shields.io/badge/Shell-0.4%25-121011?logo=gnubash&logoColor=white" alt="Shell 0.4%" />
  <img src="https://img.shields.io/badge/CSS-0.3%25-1572B6?logo=css3&logoColor=white" alt="CSS 0.3%" />
  <img src="https://img.shields.io/badge/JavaScript-0.0%25-F7DF1E?logo=javascript&logoColor=black" alt="JavaScript 0.0%" />
  <img src="https://img.shields.io/badge/Mako-0.0%25-8B5CF6" alt="Mako 0.0%" />
</p>

## Architecture

```
RegentClaw/
├── backend/           FastAPI — CoreOS, Trust Fabric, ArcClaw, IdentityClaw
├── frontend/          Next.js — Platform UI dashboard
├── docker-compose.yml Full local stack
```

## Security Compliance

RegentClaw maintains an honest, evidence-backed self-assessment against the **OWASP Top 10 for LLM/Agentic AI Applications (2025)**.

| Document | Format |
|---|---|
| [OWASP Agentic Top 10 Evidence Matrix](https://wcoreiron-rgb.github.io/regentclaw/owasp-agentic.html) | Interactive HTML |
| [docs/owasp-agentic-mapping.md](docs/owasp-agentic-mapping.md) | Markdown |

**Current posture (2026-05-29):**

| Category | Status |
|---|---|
| LLM01 Prompt Injection | Shipped — 12-vector AGT audit on every AI event |
| LLM02 Insecure Output Handling | Partially Shipped — input scanning only; output re-scan not yet applied |
| LLM03 Training Data Poisoning | N/A — uses provider APIs, no training pipeline |
| LLM04 Model Denial of Service | In Progress — auth rate limiting exists; AI endpoint limits planned |
| LLM05 Supply-Chain Vulnerabilities | In Progress — encrypted credentials, pinned deps; no SBOM yet |
| LLM06 Sensitive Information Disclosure | Shipped — Fernet encryption, DLP scanner, masked credential hints |
| LLM07 Insecure Plugin Design | Partially Shipped — ring policy + SSRF protection shipped; OS sandbox not yet |
| LLM08 Excessive Agency | Shipped — 4-ring privilege isolation, dual-approval gates, self-approval blocked |
| LLM09 Overreliance | Partially Shipped — risk scores visible; no override audit trail yet |
| LLM10 Model Theft | N/A — no hosted weights; API keys encrypted at rest |

> This is a vendor self-assessment. Independent audit recommended before compliance reliance.

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
2. Go to **Connectors** → click any connector → enter your own API credentials
   - Credentials are encrypted at rest (Fernet AES-128) and never stored in plaintext
   - Each deployment auto-generates its own encryption key in `backend/.secrets/` (gitignored)
3. Go to **Policies** → add preset policies (Block Shell Execution, etc.)
4. Go to **ArcClaw** → submit a test prompt (try including an API key to test detection)
5. Watch the **Events** and **Audit** log populate
6. Go to **IdentityClaw** → check identity inventory

> **Security note:** Never commit `backend/.secrets/` — it contains your encryption key and stored credentials. This directory is gitignored by default. Each deployer gets their own isolated key.

### Connecting your own tools

Every Claw module supports real integrations. Go to **Connectors** and add credentials for the tools you use:

| Category | Supported integrations |
|---|---|
| Cloud | AWS (Security Hub), Azure (Defender), GCP (Security Command Center) |
| Endpoint | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne |
| Identity | Okta, Microsoft Entra ID, AWS IAM |
| AI/LLM | Anthropic, OpenAI, Azure OpenAI, Ollama (local) |
| Code | GitHub (secret scanning, code review) |
| Log/SIEM | Splunk |
| Custom | Any REST API via CustomClaw |

Without credentials, all modules run on realistic simulated findings so the platform is fully usable for demos and evaluation.

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

## AGT + Multi-Agent Governance (New)

RegentClaw now exposes AGT rollout through a provider boundary instead of direct Claw coupling:

- Adapter boundary: `backend/app/fabric/providers/agt/`
- Feature flags (opt-in): `AGT_ENABLE_MCP_GATEWAY`, `AGT_ENABLE_E2E_MESSAGING`, `AGT_ENABLE_AGENT_MESH`, `AGT_ENABLE_SHADOW_DISCOVERY`
- Trust Fabric APIs:
  - `GET /api/v1/trust-fabric/multi-agent/status`
  - `POST /api/v1/trust-fabric/mcp/scan`

Detailed rollout plan: `docs/agt-3.2-regentclaw-plan.md`

## Latest Updates (May 28, 2026)

- Trust Fabric:
  - Added live MCP scan controls in UI (`/trust-fabric`) wired to `POST /api/v1/trust-fabric/mcp/scan`.
  - Added regression coverage for:
    - `GET /api/v1/trust-fabric/multi-agent/status`
    - `POST /api/v1/trust-fabric/mcp/scan`
- Swarm:
  - Added secure-channel visibility per task in `/swarm/[id]` (E2E messaging status).
  - Improved `/swarm` list with participants and runtime columns for faster validation.
  - Added test coverage for `AGT_ENABLE_E2E_MESSAGING` enabled/disabled paths.
- Platform reliability:
  - Fixed route shadowing on `GET /api/v1/policy-packs/stats`.
  - Fixed schedule delete FK issue by clearing linked `agent_runs.schedule_id`.
  - Fixed autonomy emergency payload shape to accept object JSON from UI.
  - Added run replay alias endpoint: `GET /api/v1/orchestrations/run-replay/{run_id}`.
  - Added compatibility endpoints for claw contract consistency:
    - `/api/v1/arcclaw/findings`, `/api/v1/arcclaw/providers`
    - `/api/v1/identityclaw/findings`, `/api/v1/identityclaw/providers`

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
