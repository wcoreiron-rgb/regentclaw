"""
RegentClaw — Seed Skill Packs
Installs a curated set of built-in skill packs covering the major security domains.
Run: python seed_skill_packs.py
"""
import asyncio
import json
import hashlib
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal, engine, Base
from app.models.skill_pack import SkillPack


SKILL_PACKS = [
    {
        "name": "Endpoint Rapid Response",
        "slug": "endpoint-rapid-response",
        "version": "1.3.0",
        "description": "Isolation, forensic collection, and triage for compromised endpoints. Integrates CrowdStrike, Defender, and SentinelOne.",
        "icon": "🖥️",
        "category": "Incident Response",
        "publisher": "RegentClaw Core",
        "tags": "endpoint,edr,isolation,forensics",
        "risk_level": "high",
        "requires_approval": True,
        "license": "MIT",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "ep-isolate", "name": "Isolate Endpoint", "description": "Quarantine a device from the network", "claw": "endpointclaw", "action": "isolate_endpoint"},
                {"id": "ep-collect", "name": "Collect Forensic Data", "description": "Pull memory dump, process list, network connections", "claw": "endpointclaw", "action": "collect_forensics"},
                {"id": "ep-scan",    "name": "Run Malware Scan",     "description": "Deep scan with AV + behavioural analysis", "claw": "endpointclaw", "action": "run_scan"},
                {"id": "ep-kill",    "name": "Kill Process",         "description": "Terminate a malicious process by PID/name", "claw": "endpointclaw", "action": "kill_process"},
                {"id": "ep-remediate","name": "Auto-Remediate",      "description": "Remove malware and restore system state", "claw": "endpointclaw", "action": "remediate"},
            ],
            "required_connectors": ["crowdstrike", "defender", "sentinelone"],
            "required_claws": ["endpointclaw"],
            "scope_permissions": ["read:findings", "write:findings", "execute:containment"],
            "policy_mappings": [
                {"skill_id": "ep-isolate",  "policy_name": "High-Risk Action Approval Gate"},
                {"skill_id": "ep-kill",     "policy_name": "High-Risk Action Approval Gate"},
            ],
            "min_platform_version": "0.2.0",
        },
    },
    {
        "name": "Identity Threat Response",
        "slug": "identity-threat-response",
        "version": "2.0.1",
        "description": "Account takeover detection and response. Covers Okta, Entra ID, and CyberArk PAM.",
        "icon": "🔑",
        "category": "Incident Response",
        "publisher": "RegentClaw Core",
        "tags": "identity,okta,entra,ato,mfa",
        "risk_level": "high",
        "requires_approval": True,
        "license": "MIT",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "id-disable",  "name": "Disable User Account",    "claw": "identityclaw", "action": "disable_user"},
                {"id": "id-reset",    "name": "Force Password Reset",    "claw": "identityclaw", "action": "reset_password"},
                {"id": "id-revoke",   "name": "Revoke All Sessions",     "claw": "identityclaw", "action": "revoke_sessions"},
                {"id": "id-mfa",      "name": "Enroll MFA",              "claw": "identityclaw", "action": "enroll_mfa"},
                {"id": "id-review",   "name": "Review Privilege Access", "claw": "accessclaw",   "action": "review_access"},
            ],
            "required_connectors": ["okta", "entra", "cyberark"],
            "required_claws": ["identityclaw", "accessclaw"],
            "scope_permissions": ["read:identities", "write:identities", "read:access"],
            "policy_mappings": [
                {"skill_id": "id-disable", "policy_name": "High-Risk Action Approval Gate"},
                {"skill_id": "id-reset",   "policy_name": "High-Risk Action Approval Gate"},
            ],
            "min_platform_version": "0.2.0",
        },
    },
    {
        "name": "Cloud Security Posture",
        "slug": "cloud-security-posture",
        "version": "1.1.0",
        "description": "Automated CSPM checks for AWS, Azure, and GCP. Detects misconfigurations, public buckets, and over-permissive IAM.",
        "icon": "☁️",
        "category": "Hardening",
        "publisher": "RegentClaw Core",
        "tags": "cloud,cspm,aws,azure,gcp,iam",
        "risk_level": "medium",
        "requires_approval": False,
        "license": "Apache-2.0",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "csp-scan",   "name": "Scan Cloud Posture",    "claw": "cloudclaw", "action": "posture_scan"},
                {"id": "csp-iam",    "name": "Audit IAM Permissions", "claw": "cloudclaw", "action": "audit_iam"},
                {"id": "csp-bucket", "name": "Check Public Buckets",  "claw": "cloudclaw", "action": "check_public_storage"},
                {"id": "csp-sg",     "name": "Audit Security Groups", "claw": "cloudclaw", "action": "audit_security_groups"},
                {"id": "csp-fix",    "name": "Auto-Remediate CSPM",   "claw": "cloudclaw", "action": "remediate_posture"},
            ],
            "required_connectors": ["aws", "azure", "gcp"],
            "required_claws": ["cloudclaw"],
            "scope_permissions": ["read:findings", "write:findings"],
            "policy_mappings": [],
            "min_platform_version": "0.2.0",
        },
    },
    {
        "name": "Threat Intelligence Enrichment",
        "slug": "threat-intel-enrichment",
        "version": "1.0.2",
        "description": "Automated IOC lookups, MITRE ATT&CK mapping, and reputation scoring via IntelClaw.",
        "icon": "🧠",
        "category": "Threat Hunting",
        "publisher": "RegentClaw Core",
        "tags": "intel,ioc,mitre,enrichment,cti",
        "risk_level": "low",
        "requires_approval": False,
        "license": "MIT",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "ti-lookup",  "name": "IOC Lookup",           "claw": "intelclaw", "action": "lookup_ioc"},
                {"id": "ti-mitre",   "name": "Map to MITRE ATT&CK",  "claw": "intelclaw", "action": "map_mitre"},
                {"id": "ti-score",   "name": "Reputation Score",     "claw": "intelclaw", "action": "score_reputation"},
                {"id": "ti-pivot",   "name": "Pivot on Indicators",  "claw": "intelclaw", "action": "pivot_intel"},
            ],
            "required_connectors": ["crowdstrike_intel", "virustotal"],
            "required_claws": ["intelclaw"],
            "scope_permissions": ["read:findings"],
            "policy_mappings": [],
            "min_platform_version": "0.1.0",
        },
    },
    {
        "name": "Vulnerability Remediation Workflow",
        "slug": "vuln-remediation-workflow",
        "version": "1.2.0",
        "description": "Prioritised patch management: scan → score → assign → track → verify. Integrates Tenable and Qualys.",
        "icon": "🛡️",
        "category": "Vulnerability Management",
        "publisher": "RegentClaw Core",
        "tags": "vuln,cve,patch,remediation,tenable,qualys",
        "risk_level": "medium",
        "requires_approval": False,
        "license": "MIT",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "vr-scan",    "name": "Vulnerability Scan",   "claw": "exposureclaw", "action": "scan_vulnerabilities"},
                {"id": "vr-score",   "name": "CVSS Prioritisation",  "claw": "exposureclaw", "action": "prioritize_cvss"},
                {"id": "vr-assign",  "name": "Assign Patch Ticket",  "claw": "exposureclaw", "action": "create_patch_ticket"},
                {"id": "vr-verify",  "name": "Verify Remediation",   "claw": "exposureclaw", "action": "verify_patched"},
                {"id": "vr-report",  "name": "Remediation Report",   "claw": "exposureclaw", "action": "generate_report"},
            ],
            "required_connectors": ["tenable", "qualys", "rapid7"],
            "required_claws": ["exposureclaw"],
            "scope_permissions": ["read:findings", "write:findings"],
            "policy_mappings": [],
            "min_platform_version": "0.2.0",
        },
    },
    {
        "name": "Compliance Evidence Collection",
        "slug": "compliance-evidence-collection",
        "version": "1.0.0",
        "description": "Automated evidence gathering for SOC 2, ISO 27001, PCI-DSS, and HIPAA. Produces audit-ready reports.",
        "icon": "📋",
        "category": "Compliance",
        "publisher": "RegentClaw Core",
        "tags": "compliance,soc2,iso27001,pci,hipaa,evidence",
        "risk_level": "low",
        "requires_approval": False,
        "license": "Apache-2.0",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "ce-collect",  "name": "Collect Control Evidence", "claw": "complianceclaw", "action": "collect_evidence"},
                {"id": "ce-gap",      "name": "Gap Analysis",             "claw": "complianceclaw", "action": "gap_analysis"},
                {"id": "ce-report",   "name": "Generate Audit Report",    "claw": "complianceclaw", "action": "audit_report"},
                {"id": "ce-track",    "name": "Track Remediation Tasks",  "claw": "complianceclaw", "action": "track_remediation"},
            ],
            "required_connectors": [],
            "required_claws": ["complianceclaw"],
            "scope_permissions": ["read:findings", "read:policies"],
            "policy_mappings": [],
            "min_platform_version": "0.1.0",
        },
    },
    {
        "name": "SIEM Log Investigation",
        "slug": "siem-log-investigation",
        "version": "1.1.0",
        "description": "Automated query generation, anomaly correlation, and log triage across Splunk, Sentinel, and Elastic.",
        "icon": "📊",
        "category": "Threat Hunting",
        "publisher": "RegentClaw Core",
        "tags": "siem,splunk,sentinel,elastic,log,hunting",
        "risk_level": "low",
        "requires_approval": False,
        "license": "MIT",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "si-query",   "name": "Build Detection Query",   "claw": "logclaw", "action": "build_query"},
                {"id": "si-correlate","name": "Correlate Events",       "claw": "logclaw", "action": "correlate_events"},
                {"id": "si-anomaly", "name": "Detect Anomalies",        "claw": "logclaw", "action": "detect_anomalies"},
                {"id": "si-extract", "name": "Extract IOCs from Logs",  "claw": "logclaw", "action": "extract_iocs"},
            ],
            "required_connectors": ["splunk", "sentinel", "elastic"],
            "required_claws": ["logclaw"],
            "scope_permissions": ["read:events"],
            "policy_mappings": [],
            "min_platform_version": "0.1.0",
        },
    },
    {
        "name": "DevSecOps Pipeline Guard",
        "slug": "devsecops-pipeline-guard",
        "version": "1.0.0",
        "description": "Secret scanning, SAST/DAST integration, and dependency vulnerability checks for CI/CD pipelines.",
        "icon": "🔧",
        "category": "DevSecOps",
        "publisher": "RegentClaw Core",
        "tags": "devsecops,sast,dast,secrets,cicd,github",
        "risk_level": "low",
        "requires_approval": False,
        "license": "Apache-2.0",
        "is_builtin": True,
        "manifest": {
            "skills": [
                {"id": "ds-secrets",  "name": "Scan for Secret Leaks",   "claw": "devclaw", "action": "scan_secrets"},
                {"id": "ds-sast",     "name": "Static Code Analysis",    "claw": "devclaw", "action": "run_sast"},
                {"id": "ds-deps",     "name": "Dependency Audit",        "claw": "devclaw", "action": "audit_dependencies"},
                {"id": "ds-iac",      "name": "IaC Security Scan",       "claw": "devclaw", "action": "scan_iac"},
            ],
            "required_connectors": ["github"],
            "required_claws": ["devclaw"],
            "scope_permissions": ["read:findings", "write:findings"],
            "policy_mappings": [],
            "min_platform_version": "0.2.0",
        },
    },
]


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        for pack_data in SKILL_PACKS:
            manifest = pack_data.pop("manifest")
            manifest_json = json.dumps(manifest, indent=2)
            sig = hashlib.sha256(manifest_json.encode()).hexdigest()[:32]
            skill_count = len(manifest.get("skills", []))

            existing = await db.execute(
                select(SkillPack).where(SkillPack.slug == pack_data["slug"])
            )
            if existing.scalar_one_or_none():
                print(f"  ↩  skip  {pack_data['slug']} (already exists)")
                continue

            pack = SkillPack(
                **pack_data,
                manifest_json=manifest_json,
                skill_count=skill_count,
                signature=sig,
                is_installed=pack_data.get("is_builtin", False),
                is_active=False,
            )
            db.add(pack)
            print(f"  ✓  added {pack_data['slug']} ({skill_count} skills)")

        await db.commit()
        print("\nDone — skill packs seeded.")


if __name__ == "__main__":
    asyncio.run(seed())
