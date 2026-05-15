"""
RegentClaw — Example Orchestration Seeder
==========================================
Seeds two fully wired, multi-Claw security pipelines that demonstrate how
specialized agents from different Claws chain together in an orchestration.

Pipeline 1: Cloud Vulnerability Intelligence
  CloudClaw → ExposureClaw → ConfigClaw → NetClaw → ThreatClaw → ArcClaw

Pipeline 2: Compliance Environment Sweep
  ComplianceClaw → PrivacyClaw → IdentityClaw → DataClaw → VendorClaw → LogClaw → ArcClaw

Usage:
  docker compose exec backend python seed_example_orchestrations.py
  docker compose exec backend python seed_example_orchestrations.py --reset
"""
import sys
import os
import json
import asyncio
from sqlalchemy import delete, select

sys.path.insert(0, os.path.dirname(__file__))

from app.core.database import AsyncSessionLocal
from app.models.agent import Agent, ExecutionMode, AgentStatus, RiskLevel
from app.models.workflow import Workflow


# ─────────────────────────────────────────────────────────────────────────────
#  Specialist Agents — one expert per Claw per pipeline
# ─────────────────────────────────────────────────────────────────────────────

SPECIALIST_AGENTS = [

    # ── Pipeline 1: Cloud Vulnerability Intelligence ──────────────────────────

    {
        "name":        "Cloud Asset Discovery",
        "description": (
            "Enumerates all cloud resources across AWS/Azure/GCP: compute, storage, databases, "
            "serverless functions, container registries, and IAM roles. Builds the asset inventory "
            "that downstream vulnerability and exposure agents work against."
        ),
        "claw":        "cloudclaw",
        "category":    "Cloud Vulnerability Intelligence",
        "icon":        "☁️",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["list_resources", "read_tags", "read_network_config"]),
        "allowed_connectors": json.dumps(["aws_security_hub", "azure_security_center", "google_chronicle"]),
        "scope_notes": "Read-only. Discovers resources in all configured cloud accounts.",
        "owner_name":  "Cloud Security Team",
    },
    {
        "name":        "CVE Vulnerability Scanner",
        "description": (
            "Takes the asset inventory from CloudClaw and maps each asset against the NVD/CVE "
            "database. Scores findings with CVSS v3.1, groups by severity, and identifies "
            "exploitable vulnerabilities that have known public exploits (EPSS scoring)."
        ),
        "claw":        "exposureclaw",
        "category":    "Cloud Vulnerability Intelligence",
        "icon":        "🔍",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   900,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_cve_db", "score_cvss", "read_epss", "read_asset_inventory"]),
        "allowed_connectors": json.dumps(["tenable_io", "qualys"]),
        "scope_notes": "Read-only CVE correlation. Requires asset list from Cloud Asset Discovery.",
        "owner_name":  "Vulnerability Management",
    },
    {
        "name":        "CIS Benchmark Auditor",
        "description": (
            "Validates cloud and endpoint configurations against CIS Benchmarks (CIS AWS, CIS Azure, "
            "CIS GCP, CIS Kubernetes). Flags deviations from Level 1 and Level 2 controls. "
            "Produces a scored hardening report per resource type."
        ),
        "claw":        "configclaw",
        "category":    "Cloud Vulnerability Intelligence",
        "icon":        "📋",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_config", "compare_cis_benchmark", "read_security_groups"]),
        "allowed_connectors": json.dumps(["aws_security_hub", "azure_security_center"]),
        "scope_notes": "Read-only configuration assessment against CIS controls.",
        "owner_name":  "Cloud Security Team",
    },
    {
        "name":        "Network Exposure Analyzer",
        "description": (
            "Identifies publicly reachable assets: open ports, permissive security groups, "
            "unprotected load balancers, and internet-facing databases. Cross-references findings "
            "with the vulnerability list to surface the highest-risk exposed attack surface."
        ),
        "claw":        "netclaw",
        "category":    "Cloud Vulnerability Intelligence",
        "icon":        "🌐",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["scan_open_ports", "read_firewall_rules", "read_load_balancer_config"]),
        "allowed_connectors": json.dumps(["crowdstrike_falcon", "aws_security_hub"]),
        "scope_notes": "Passive network exposure analysis. No active scanning or packet injection.",
        "owner_name":  "Network Security Team",
    },
    {
        "name":        "Threat Intelligence Correlator",
        "description": (
            "Takes the CVE and exposure list and correlates it against active threat intel feeds: "
            "MITRE ATT&CK, known threat actor TTPs, and current exploitation campaigns. "
            "Flags vulnerabilities being actively exploited in the wild and maps them to likely "
            "attack paths in your environment."
        ),
        "claw":        "threatclaw",
        "category":    "Cloud Vulnerability Intelligence",
        "icon":        "🎯",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_threat_feeds", "correlate_ttp", "read_mitre_attack"]),
        "allowed_connectors": json.dumps(["crowdstrike_falcon", "microsoft_sentinel"]),
        "scope_notes": "Read-only threat intel correlation. No blocking or response actions.",
        "owner_name":  "Threat Intelligence Team",
    },
    {
        "name":        "Vulnerability Summary Generator",
        "description": (
            "AI-powered final step in the cloud vulnerability pipeline. Reads all upstream findings "
            "(cloud misconfigs, CVEs, CIS gaps, network exposure, active threats) and produces: "
            "(1) an executive summary, (2) a prioritized remediation list sorted by risk × exploitability, "
            "(3) quick-win fixes vs. long-term improvements, and (4) estimated remediation effort per item."
        ),
        "claw":        "arcclaw",
        "category":    "Cloud Vulnerability Intelligence",
        "icon":        "⚡",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   300,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_findings", "generate_summary", "call_llm"]),
        "allowed_connectors": json.dumps(["openai", "anthropic"]),
        "scope_notes": "Read-only. Synthesizes upstream agent findings into an actionable report.",
        "owner_name":  "Security Engineering",
    },

    # ── Pipeline 2: Compliance Environment Sweep ──────────────────────────────

    {
        "name":        "Compliance Control Mapper",
        "description": (
            "Maps your environment's current security controls against a chosen framework "
            "(SOC2, ISO27001, HIPAA, PCI-DSS, NIST CSF). For each control, determines: "
            "IMPLEMENTED / PARTIAL / MISSING. Produces a compliance coverage matrix and "
            "calculates an overall compliance score per domain."
        ),
        "claw":        "complianceclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "✅",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   900,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_controls", "map_framework", "score_compliance"]),
        "allowed_connectors": json.dumps(["microsoft_sentinel", "azure_security_center"]),
        "scope_notes": "Read-only compliance posture assessment.",
        "owner_name":  "Compliance Team",
    },
    {
        "name":        "PII Data Inventory Agent",
        "description": (
            "Scans all connected data stores (databases, file shares, cloud storage, SaaS apps) "
            "to discover and classify sensitive data: PII, PHI, financial records, credentials. "
            "Tags each data store with classification level, identifies unprotected PII, and "
            "maps data flows to third parties."
        ),
        "claw":        "privacyclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "🔐",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   900,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["scan_data_stores", "classify_data", "map_data_flows"]),
        "allowed_connectors": json.dumps(["microsoft_purview", "box"]),
        "scope_notes": "Read-only data discovery. No modification of data or access controls.",
        "owner_name":  "Privacy Team",
    },
    {
        "name":        "IAM Posture Auditor",
        "description": (
            "Reviews the full identity and access management posture: privileged account inventory, "
            "role assignments, stale permissions, service account usage, MFA coverage, and "
            "separation of duties violations. Surfaces accounts with excessive privilege "
            "and identifies orphaned access."
        ),
        "claw":        "identityclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "👤",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_users", "read_roles", "read_mfa_status", "read_service_accounts"]),
        "allowed_connectors": json.dumps(["entra_id", "okta", "active_directory"]),
        "scope_notes": "Read-only IAM audit. No changes to accounts or permissions.",
        "owner_name":  "Identity Team",
    },
    {
        "name":        "Data Protection Posture Agent",
        "description": (
            "Assesses data protection controls: encryption at rest and in transit, DLP policy "
            "coverage, backup integrity, data retention compliance, and key management hygiene. "
            "Identifies unencrypted data stores, expired keys, and gaps in DLP rule coverage."
        ),
        "claw":        "dataclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "🛡️",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["check_encryption", "read_dlp_policies", "check_backup_status", "read_key_vault"]),
        "allowed_connectors": json.dumps(["microsoft_purview", "aws_security_hub", "azure_security_center"]),
        "scope_notes": "Read-only data protection assessment.",
        "owner_name":  "Data Security Team",
    },
    {
        "name":        "Third-Party Risk Assessor",
        "description": (
            "Reviews all active vendor and third-party connections: connector security posture, "
            "data sharing agreements, BAA/DPA status, vendor security ratings, and access scope. "
            "Flags vendors with high risk scores, missing agreements, or overly broad permissions."
        ),
        "claw":        "vendorclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "🤝",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_vendor_list", "check_baa_status", "read_connector_permissions"]),
        "allowed_connectors": json.dumps(["servicenow"]),
        "scope_notes": "Read-only third-party risk review.",
        "owner_name":  "Vendor Risk Team",
    },
    {
        "name":        "Audit Log Completeness Checker",
        "description": (
            "Validates that audit logging is enabled and complete across all critical systems: "
            "identity events, data access, configuration changes, network flows, and admin actions. "
            "Identifies systems with missing, incomplete, or tampered logs. Checks log retention "
            "policies against regulatory requirements."
        ),
        "claw":        "logclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "📖",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   600,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_log_sources", "check_retention", "detect_gaps", "check_tampering"]),
        "allowed_connectors": json.dumps(["microsoft_sentinel", "splunk", "elastic_siem"]),
        "scope_notes": "Read-only log infrastructure audit.",
        "owner_name":  "SOC Team",
    },
    {
        "name":        "Compliance Remediation Planner",
        "description": (
            "AI-powered final step in the compliance sweep. Reads all upstream findings and produces: "
            "(1) overall compliance score per framework, (2) control gap analysis, "
            "(3) quick wins — gaps fixable in < 1 week, (4) medium-term items — 1-4 weeks, "
            "(5) strategic items — 1-3 months, and (6) an executive summary with risk narrative "
            "and board-ready language. Automatically prioritizes by regulatory impact."
        ),
        "claw":        "arcclaw",
        "category":    "Compliance Environment Sweep",
        "icon":        "⚡",
        "execution_mode":    ExecutionMode.MONITOR,
        "risk_level":        RiskLevel.LOW,
        "max_runtime_sec":   300,
        "requires_approval": False,
        "allowed_actions":   json.dumps(["read_findings", "generate_summary", "prioritize_remediation", "call_llm"]),
        "allowed_connectors": json.dumps(["openai", "anthropic"]),
        "scope_notes": "Read-only. Synthesizes upstream compliance findings into prioritized remediation plan.",
        "owner_name":  "Compliance Team",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestration Workflows
#  (agent_ids filled in dynamically after agents are seeded)
# ─────────────────────────────────────────────────────────────────────────────

def _build_workflows(agent_map: dict) -> list:
    """Build workflow step defs using agent IDs looked up by name."""

    def agent_step(step_id, step_name, agent_name, on_failure="continue"):
        agent_id = agent_map.get(agent_name)
        return {
            "id": step_id,
            "name": step_name,
            "type": "agent_run",
            "config": {
                "agent_id": str(agent_id) if agent_id else None,
                "label": agent_name,
            },
            "on_failure": on_failure,
        }

    def policy_step(step_id, step_name, field, op, value, label, on_failure="stop"):
        return {
            "id": step_id,
            "name": step_name,
            "type": "policy_check",
            "config": {"field": field, "op": op, "value": value, "label": label},
            "on_failure": on_failure,
        }

    def notify_step(step_id, step_name, message, severity="medium"):
        return {
            "id": step_id,
            "name": step_name,
            "type": "notify",
            "config": {"message": message, "severity": severity},
            "on_failure": "continue",
        }

    # ── Workflow 1: Cloud Vulnerability Intelligence ───────────────────────────
    vuln_steps = [
        policy_step(
            "s1", "Zero Trust Gate — Cloud Module Active",
            "module", "eq", "cloudclaw", "Cloud module must be active",
            on_failure="stop",
        ),
        agent_step("s2", "☁️ Discover All Cloud Assets",
                   "Cloud Asset Discovery", on_failure="stop"),
        agent_step("s3", "🔍 Scan for CVEs & Score with CVSS/EPSS",
                   "CVE Vulnerability Scanner", on_failure="continue"),
        agent_step("s4", "📋 Audit CIS Benchmark Compliance",
                   "CIS Benchmark Auditor", on_failure="continue"),
        agent_step("s5", "🌐 Identify Network Exposure & Open Ports",
                   "Network Exposure Analyzer", on_failure="continue"),
        agent_step("s6", "🎯 Correlate with Active Threat Intel",
                   "Threat Intelligence Correlator", on_failure="continue"),
        {
            "id": "s7",
            "name": "Condition — Critical Findings Detected?",
            "type": "condition",
            "config": {"expression": "critical_cves > 0 OR actively_exploited = true"},
            "on_failure": "continue",
        },
        agent_step("s8", "⚡ Generate AI Vulnerability Report",
                   "Vulnerability Summary Generator", on_failure="continue"),
        notify_step(
            "s9",
            "📬 Deliver Vulnerability Intelligence Report",
            "Cloud Vulnerability Intelligence complete. "
            "CVE findings, CIS gaps, network exposure, and active threat correlations are ready. "
            "Prioritized remediation list available in ArcClaw.",
            severity="high",
        ),
    ]

    # ── Workflow 2: Compliance Environment Sweep ──────────────────────────────
    compliance_steps = [
        policy_step(
            "s1", "Compliance Gate — Audit Logging Must Be Active",
            "audit_logging", "eq", "enabled", "Audit logging active",
            on_failure="stop",
        ),
        agent_step("s2", "✅ Map Controls to Compliance Framework",
                   "Compliance Control Mapper", on_failure="continue"),
        agent_step("s3", "🔐 Inventory & Classify All PII / PHI Data",
                   "PII Data Inventory Agent", on_failure="continue"),
        agent_step("s4", "👤 Audit IAM Posture & Privilege Assignments",
                   "IAM Posture Auditor", on_failure="continue"),
        agent_step("s5", "🛡️ Check Encryption, DLP & Data Protection",
                   "Data Protection Posture Agent", on_failure="continue"),
        agent_step("s6", "🤝 Assess Vendor & Third-Party Risk",
                   "Third-Party Risk Assessor", on_failure="continue"),
        agent_step("s7", "📖 Verify Audit Log Completeness & Retention",
                   "Audit Log Completeness Checker", on_failure="continue"),
        {
            "id": "s8",
            "name": "Condition — Critical Compliance Gaps?",
            "type": "condition",
            "config": {"expression": "compliance_score < 70 OR critical_gaps > 0"},
            "on_failure": "continue",
        },
        agent_step("s9", "⚡ Generate AI Remediation Plan",
                   "Compliance Remediation Planner", on_failure="continue"),
        notify_step(
            "s10",
            "📬 Deliver Compliance Report & Remediation Roadmap",
            "Compliance Environment Sweep complete. "
            "Control gaps identified across ComplianceClaw, PrivacyClaw, IdentityClaw, DataClaw, "
            "VendorClaw, and LogClaw. Prioritized remediation roadmap available — "
            "quick wins, medium-term fixes, and strategic items listed by regulatory impact.",
            severity="medium",
        ),
    ]

    return [
        {
            "name": "Cloud Vulnerability Intelligence Pipeline",
            "description": (
                "End-to-end cloud vulnerability pipeline. Six specialist agents work in sequence: "
                "CloudClaw discovers assets → ExposureClaw maps CVEs → ConfigClaw audits CIS benchmarks "
                "→ NetClaw finds network exposure → ThreatClaw correlates active threats → "
                "ArcClaw generates a prioritized AI remediation report. "
                "Run weekly or on-demand after cloud changes."
            ),
            "trigger_type": "schedule",
            "category": "Cloud Vulnerability Intelligence",
            "tags": "cloud,vulnerability,cve,cis,network,threat-intel,arcclaw",
            "owner_name": "Security Engineering",
            "steps": vuln_steps,
        },
        {
            "name": "Compliance Environment Sweep",
            "description": (
                "Full-stack compliance sweep powered by 7 specialist agents. "
                "ComplianceClaw maps controls → PrivacyClaw inventories PII/PHI → "
                "IdentityClaw audits IAM → DataClaw checks encryption/DLP → "
                "VendorClaw assesses third-party risk → LogClaw verifies audit coverage → "
                "ArcClaw produces a board-ready remediation roadmap with quick wins and "
                "estimated effort per item. Maps to SOC2, ISO27001, HIPAA, PCI-DSS."
            ),
            "trigger_type": "schedule",
            "category": "Compliance Environment Sweep",
            "tags": "compliance,soc2,iso27001,hipaa,pci-dss,privacy,iam,data,vendor,logs",
            "owner_name": "Compliance Team",
            "steps": compliance_steps,
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  Seed logic
# ─────────────────────────────────────────────────────────────────────────────

async def seed(reset: bool = False):
    async with AsyncSessionLocal() as db:

        if reset:
            # Remove only agents and workflows in these categories
            for cat in ["Cloud Vulnerability Intelligence", "Compliance Environment Sweep"]:
                result = await db.execute(select(Agent).where(Agent.category == cat))
                for a in result.scalars().all():
                    await db.delete(a)
                result = await db.execute(select(Workflow).where(Workflow.category == cat))
                for w in result.scalars().all():
                    await db.delete(w)
            await db.commit()
            print("🗑  Cleared example orchestration agents and workflows")

        # ── Seed agents ──────────────────────────────────────────────────────
        print("\n  Seeding specialist agents…")
        agent_map = {}  # name → id

        for spec in SPECIALIST_AGENTS:
            result = await db.execute(select(Agent).where(Agent.name == spec["name"]))
            existing = result.scalar_one_or_none()

            if existing:
                for k, v in spec.items():
                    if hasattr(existing, k):
                        setattr(existing, k, v)
                existing.status = AgentStatus.ACTIVE
                existing.is_builtin = True
                agent_map[spec["name"]] = existing.id
                print(f"    ↻  Updated agent: {spec['icon']} {spec['name']} ({spec['claw']})")
            else:
                agent = Agent(
                    **spec,
                    status=AgentStatus.ACTIVE,
                    is_builtin=True,
                )
                db.add(agent)
                await db.flush()
                agent_map[spec["name"]] = agent.id
                print(f"    ✅ Created agent: {spec['icon']} {spec['name']} ({spec['claw']})")

        await db.commit()

        # ── Seed workflows ────────────────────────────────────────────────────
        print("\n  Seeding orchestration workflows…")
        workflows = _build_workflows(agent_map)

        for wf_def in workflows:
            steps = wf_def.pop("steps")
            steps_json = json.dumps(steps)
            step_count = len(steps)

            result = await db.execute(select(Workflow).where(Workflow.name == wf_def["name"]))
            existing = result.scalar_one_or_none()

            if existing:
                existing.description = wf_def["description"]
                existing.trigger_type = wf_def["trigger_type"]
                existing.category = wf_def["category"]
                existing.tags = wf_def["tags"]
                existing.owner_name = wf_def["owner_name"]
                existing.steps_json = steps_json
                existing.step_count = step_count
                existing.is_active = True
                print(f"    ↻  Updated workflow: {wf_def['name']} ({step_count} steps)")
            else:
                db.add(Workflow(
                    **wf_def,
                    steps_json=steps_json,
                    step_count=step_count,
                    is_active=True,
                ))
                print(f"    ✅ Created workflow: {wf_def['name']} ({step_count} steps)")

        await db.commit()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"""
✅ Example orchestrations seeded!

PIPELINE 1 — Cloud Vulnerability Intelligence ({len([a for a in SPECIALIST_AGENTS if a['category'] == 'Cloud Vulnerability Intelligence'])} agents, 9 steps)
  ☁️  CloudClaw   → Cloud Asset Discovery
  🔍  ExposureClaw → CVE Vulnerability Scanner (CVSS + EPSS)
  📋  ConfigClaw  → CIS Benchmark Auditor
  🌐  NetClaw     → Network Exposure Analyzer
  🎯  ThreatClaw  → Threat Intelligence Correlator
  ⚡  ArcClaw     → AI Vulnerability Summary Generator

PIPELINE 2 — Compliance Environment Sweep ({len([a for a in SPECIALIST_AGENTS if a['category'] == 'Compliance Environment Sweep'])} agents, 10 steps)
  ✅  ComplianceClaw → Control Mapper (SOC2/ISO27001/HIPAA/PCI)
  🔐  PrivacyClaw   → PII/PHI Data Inventory
  👤  IdentityClaw  → IAM Posture Auditor
  🛡️  DataClaw      → Encryption & DLP Posture
  🤝  VendorClaw    → Third-Party Risk Assessor
  📖  LogClaw       → Audit Log Completeness
  ⚡  ArcClaw       → AI Remediation Planner

Run from the Orchestrations page or via:
  POST /api/v1/orchestrations/<id>/run
""")


if __name__ == "__main__":
    reset = "--reset" in sys.argv
    asyncio.run(seed(reset))
