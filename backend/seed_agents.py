"""
RegentClaw — Seed Prebuilt Security Agents + Default Schedules
Usage:
  python seed_agents.py             # insert if not present
  python seed_agents.py --reset     # delete all agents/schedules/runs then re-seed
"""
import sys
import os
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Seed scripts use the sync URL (asyncpg not needed here)
_engine = create_engine(settings.DATABASE_URL_SYNC)
SessionLocal = sessionmaker(bind=_engine)

from app.core.database import Base
from app.models.agent import (
    Agent, Schedule, AgentRun,
    ExecutionMode, AgentStatus, ScheduleFrequency, ScheduleStatus, RiskLevel,
)

# Ensure agent tables exist (safe to run even if already created)
Base.metadata.create_all(_engine)

# ─────────────────────────────────────────────────────────────────────────────
# Prebuilt Agent Definitions
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_AGENTS = [
    {
        "name":        "Identity Hygiene Monitor",
        "description": "Scans Entra ID / Active Directory for stale accounts, missing MFA, and orphaned service principals. Reports findings without making changes.",
        "claw":        "identityclaw",
        "category":    "Core Security",
        "icon":        "👤",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 300,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_users", "read_groups", "read_mfa_status"]),
        "allowed_connectors": json.dumps(["entra_id", "active_directory"]),
        "scope_notes": "Read-only scan of identity directory. No write operations.",
        "owner_name":  "SOC Team",
        "default_schedule": ScheduleFrequency.DAILY,
    },
    {
        "name":        "Stale Account Remediation",
        "description": "Identifies and disables accounts inactive for 90+ days in Entra ID. Requires human approval before disabling any account.",
        "claw":        "identityclaw",
        "category":    "Core Security",
        "icon":        "🔒",
        "execution_mode": ExecutionMode.ASSIST,
        "risk_level":  RiskLevel.MEDIUM,
        "max_runtime_sec": 600,
        "requires_approval": True,
        "allowed_actions": json.dumps(["read_users", "disable_account", "send_notification"]),
        "allowed_connectors": json.dumps(["entra_id"]),
        "scope_notes": "Scoped to accounts inactive 90+ days. Each disable requires analyst approval.",
        "owner_name":  "Identity Team",
        "default_schedule": ScheduleFrequency.WEEKLY,
    },
    {
        "name":        "Cloud Posture Scanner",
        "description": "Checks Azure / AWS for public-facing storage, misconfigured IAM roles, and missing encryption. Monitor-only — findings fed to dashboard.",
        "claw":        "cloudclaw",
        "category":    "Core Security",
        "icon":        "☁️",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 600,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_storage_config", "read_iam_roles", "read_encryption_status"]),
        "allowed_connectors": json.dumps(["azure_security_center", "aws_security_hub"]),
        "scope_notes": "Read-only cloud posture assessment.",
        "owner_name":  "Cloud Team",
        "default_schedule": ScheduleFrequency.DAILY,
    },
    {
        "name":        "Cloud Auto-Remediation",
        "description": "Automatically remediates low-risk cloud misconfigurations (e.g., enables storage encryption, removes public ACLs). High-risk changes held for approval.",
        "claw":        "cloudclaw",
        "category":    "Core Security",
        "icon":        "⚡",
        "execution_mode": ExecutionMode.AUTONOMOUS,
        "risk_level":  RiskLevel.MEDIUM,
        "max_runtime_sec": 900,
        "requires_approval": False,
        "allowed_actions": json.dumps(["enable_encryption", "remove_public_acl", "disable_iam_role"]),
        "allowed_connectors": json.dumps(["azure_security_center", "aws_security_hub"]),
        "scope_notes": "Auto-executes low/medium-risk fixes. High-risk queued for analyst.",
        "owner_name":  "Cloud Team",
        "default_schedule": ScheduleFrequency.EVERY_6_HOURS,
    },
    {
        "name":        "PAM Credential Auditor",
        "description": "Audits privileged accounts, shared credentials, and service account usage via AccessClaw. Flags accounts not rotated within policy window.",
        "claw":        "accessclaw",
        "category":    "Core Security",
        "icon":        "🗝️",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 300,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_privileged_accounts", "read_session_logs", "read_credential_age"]),
        "allowed_connectors": json.dumps(["cyberark", "hashicorp_vault", "active_directory"]),
        "scope_notes": "Read-only privileged account audit.",
        "owner_name":  "IAM Team",
        "default_schedule": ScheduleFrequency.DAILY,
    },
    {
        "name":        "Endpoint Compliance Checker",
        "description": "Scans all managed endpoints for missing EDR agents, unpatched CVEs, and non-compliant device configurations via EndpointClaw.",
        "claw":        "endpointclaw",
        "category":    "Core Security",
        "icon":        "💻",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 600,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_endpoint_inventory", "read_patch_status", "read_edr_status"]),
        "allowed_connectors": json.dumps(["microsoft_defender", "crowdstrike", "intune"]),
        "scope_notes": "Read-only endpoint inventory and compliance scan.",
        "owner_name":  "Endpoint Team",
        "default_schedule": ScheduleFrequency.DAILY,
    },
    {
        "name":        "AI/LLM Traffic Sentinel",
        "description": "Monitors all LLM API traffic through ArcClaw for prompt injection, data exfiltration, and policy violations. Blocks flagged sessions automatically.",
        "claw":        "arcclaw",
        "category":    "Core Security",
        "icon":        "🤖",
        "execution_mode": ExecutionMode.AUTONOMOUS,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 60,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_llm_traffic", "block_session", "flag_output", "log_violation"]),
        "allowed_connectors": json.dumps(["openai", "azure_openai", "anthropic"]),
        "scope_notes": "Auto-blocks confirmed violations. Flags ambiguous sessions for review.",
        "owner_name":  "AI Security Team",
        "default_schedule": ScheduleFrequency.EVERY_15_MIN,
    },
    {
        "name":        "Threat Detection & Response",
        "description": "Correlates Sentinel alerts, Defender incidents, and network anomalies via ThreatClaw. Creates incidents and isolates confirmed compromised hosts.",
        "claw":        "threatclaw",
        "category":    "Detection",
        "icon":        "🎯",
        "execution_mode": ExecutionMode.ASSIST,
        "risk_level":  RiskLevel.HIGH,
        "max_runtime_sec": 300,
        "requires_approval": True,
        "allowed_actions": json.dumps(["read_alerts", "correlate_incidents", "isolate_host", "create_incident"]),
        "allowed_connectors": json.dumps(["microsoft_sentinel", "microsoft_defender", "crowdstrike"]),
        "scope_notes": "Isolations require SOC analyst approval. Alert correlation is automatic.",
        "owner_name":  "SOC Team",
        "default_schedule": ScheduleFrequency.EVERY_15_MIN,
    },
    {
        "name":        "Compliance Gap Analyzer",
        "description": "Evaluates control coverage against SOC 2, ISO 27001, and NIST CSF frameworks via ComplianceClaw. Produces gap report and remediation tasks.",
        "claw":        "complianceclaw",
        "category":    "Governance",
        "icon":        "📋",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 900,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_controls", "read_evidence", "read_policy_mappings"]),
        "allowed_connectors": json.dumps(["vanta", "drata"]),
        "scope_notes": "Read-only compliance framework assessment.",
        "owner_name":  "GRC Team",
        "default_schedule": ScheduleFrequency.WEEKLY,
    },
    {
        "name":        "Network Anomaly Watcher",
        "description": "Monitors east-west and north-south network traffic for anomalous patterns, unauthorized lateral movement, and Zero Trust policy violations via NetClaw.",
        "claw":        "netclaw",
        "category":    "Core Security",
        "icon":        "🌐",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 300,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_flow_logs", "read_firewall_logs", "read_dns_logs"]),
        "allowed_connectors": json.dumps(["microsoft_sentinel", "palo_alto", "zscaler"]),
        "scope_notes": "Read-only traffic analysis. No network changes.",
        "owner_name":  "Network Security Team",
        "default_schedule": ScheduleFrequency.HOURLY,
    },
    {
        "name":        "Data Loss Prevention Agent",
        "description": "Scans email, file shares, and SaaS apps for data policy violations, PII exposure, and unauthorized exfiltration via DataClaw.",
        "claw":        "dataclaw",
        "category":    "Core Security",
        "icon":        "🛡️",
        "execution_mode": ExecutionMode.ASSIST,
        "risk_level":  RiskLevel.MEDIUM,
        "max_runtime_sec": 600,
        "requires_approval": True,
        "allowed_actions": json.dumps(["read_email_headers", "scan_file_content", "quarantine_file", "block_share"]),
        "allowed_connectors": json.dumps(["microsoft_purview", "google_workspace"]),
        "scope_notes": "Quarantine actions require analyst sign-off.",
        "owner_name":  "Data Security Team",
        "default_schedule": ScheduleFrequency.EVERY_6_HOURS,
    },
    {
        "name":        "Vendor Risk Assessor",
        "description": "Aggregates third-party risk signals from vendor security questionnaires, breach databases, and BitSight scores via VendorClaw.",
        "claw":        "vendorclaw",
        "category":    "Governance",
        "icon":        "🤝",
        "execution_mode": ExecutionMode.MONITOR,
        "risk_level":  RiskLevel.LOW,
        "max_runtime_sec": 600,
        "requires_approval": False,
        "allowed_actions": json.dumps(["read_vendor_profiles", "read_breach_data", "read_security_ratings"]),
        "allowed_connectors": json.dumps(["bitsight", "securityscorecard"]),
        "scope_notes": "Read-only vendor risk aggregation.",
        "owner_name":  "Vendor Risk Team",
        "default_schedule": ScheduleFrequency.WEEKLY,
    },
]


# ─────────────────────────────────────────────────────────────────────────────

def seed(reset: bool = False) -> None:
    db = SessionLocal()
    try:
        if reset:
            print("🗑  Resetting agent tables…")
            db.query(AgentRun).delete()
            db.query(Schedule).delete()
            db.query(Agent).delete()
            db.commit()
            print("   Done.\n")

        existing_names = {a.name for a in db.query(Agent.name).all()}
        added_agents   = 0
        added_schedules = 0

        for spec in BUILTIN_AGENTS:
            if spec["name"] in existing_names:
                print(f"  ↩  Skip (exists): {spec['name']}")
                continue

            freq = spec.pop("default_schedule", ScheduleFrequency.DAILY)

            agent = Agent(
                is_builtin=True,
                status=AgentStatus.ACTIVE,
                **spec,
            )
            db.add(agent)
            db.flush()  # get agent.id

            # Default schedule
            now = datetime.now(timezone.utc)
            delta_map = {
                ScheduleFrequency.EVERY_15_MIN:  timedelta(minutes=15),
                ScheduleFrequency.HOURLY:        timedelta(hours=1),
                ScheduleFrequency.EVERY_6_HOURS: timedelta(hours=6),
                ScheduleFrequency.DAILY:         timedelta(days=1),
                ScheduleFrequency.WEEKLY:        timedelta(weeks=1),
                ScheduleFrequency.MONTHLY:       timedelta(days=30),
            }
            next_run = now + delta_map.get(freq, timedelta(days=1))

            sched = Schedule(
                name=f"{agent.name} — Default",
                agent_id=agent.id,
                frequency=freq,
                status=ScheduleStatus.ACTIVE,
                approval_required=agent.requires_approval,
                owner_name=agent.owner_name,
                next_run_at=next_run,
            )
            db.add(sched)
            added_agents   += 1
            added_schedules += 1
            print(f"  ✓  {agent.icon} {agent.name}  [{agent.execution_mode} / {agent.risk_level}]  sched={freq}")

        db.commit()
        print(f"\n✅  Seeded {added_agents} agents + {added_schedules} schedules.")

    finally:
        db.close()


if __name__ == "__main__":
    reset_flag = "--reset" in sys.argv
    seed(reset=reset_flag)
